use std::backtrace::Backtrace;
use std::collections::VecDeque;
use std::fmt::{Display, Formatter};
use std::iter::FromIterator;
use std::panic::Location;

use error_stack::{AttachmentKind, Context, Frame, FrameKind, Report};
use serde::{Deserialize, Serialize};
use valuable::Valuable;

#[derive(Debug, Serialize, Deserialize)]
pub struct Error(String);

impl Error {
    pub fn new(msg: String) -> Error {
        Error(msg)
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0.as_str())
    }
}

impl Context for Error {}

#[derive(Valuable, PartialEq, Debug, Clone)]
pub struct LoggableError {
    pub msg: String,
    pub attachments: Vec<String>,
    pub location: String,
    pub cause: Option<Box<LoggableError>>,
    pub backtrace: Option<LoggableBacktrace>,
}

#[derive(Valuable, PartialEq, Eq, Debug, Clone)]
pub struct LoggableBacktrace(Vec<String>);

impl<T> From<&Report<T>> for LoggableError {
    fn from(report: &Report<T>) -> Self {
        let mut errors: Vec<LoggableError> = Vec::new();

        let mut frames = VecDeque::from_iter(report.frames());
        while !frames.is_empty() {
            let mut error = LoggableError {
                msg: String::new(),
                attachments: Vec::new(),
                location: String::new(),
                cause: None,
                backtrace: None,
            };
            let mut attachments = Vec::new();

            while let Some(f) = frames.pop_front() {
                // errors are represented by frames in this order:
                //
                // attachment n   of error i
                // attachment n-1 of error i
                // ...
                // attachment 1   of error i
                // context        of error i
                //
                // attachment m   of error i-1
                // ...
                // attachment 1   of error i-1
                // context        of error i-1
                // ...
                //
                // so a context frame denotes the end of one error and we can break to create the next
                match FrameType::from(f) {
                    FrameType::Context(c) => {
                        error.msg = c.to_string();
                        break;
                    }
                    FrameType::Location(loc) => error.location = loc.to_string(),
                    FrameType::Printable(p) => attachments.push(p),
                    FrameType::Opaque => attachments.push("opaque attachment".to_string()),
                    FrameType::Backtrace(b) => error.backtrace = Some(LoggableBacktrace::from(b)),
                }
            }

            // because of the stack order of attachments we need to reverse them to get the historical order
            attachments.reverse();
            error.attachments = attachments;
            errors.push(error)
        }

        chain_causes(errors).expect("a report must have at least one error")
    }
}

impl From<&Backtrace> for LoggableBacktrace {
    fn from(backtrace: &Backtrace) -> Self {
        LoggableBacktrace(
            backtrace
                .to_string()
                .split('\n')
                .map(|s| s.to_string())
                .collect(),
        )
    }
}

fn chain_causes(errors: Vec<LoggableError>) -> Option<LoggableError> {
    errors
        .into_iter()
        .rev()
        .fold(None, |acc: Option<LoggableError>, mut e: LoggableError| {
            e.cause = acc.map(Box::new);
            Some(e)
        })
}

enum FrameType<'a> {
    Context(&'a dyn Context),
    Location(&'a Location<'a>),
    Backtrace(&'a Backtrace),
    Printable(String),
    Opaque,
}

impl<'a> From<&'a Frame> for FrameType<'a> {
    fn from(f: &'a Frame) -> Self {
        use AttachmentKind::{Opaque, Printable};
        use FrameKind::{Attachment, Context};

        match f.kind() {
            Context(c) => FrameType::Context(c),
            Attachment(Opaque(_)) => {
                if let Some(loc) = f.downcast_ref::<Location>() {
                    return FrameType::Location(loc);
                }

                if let Some(b) = f.downcast_ref::<Backtrace>() {
                    return FrameType::Backtrace(b);
                }

                FrameType::Opaque
            }
            Attachment(Printable(p)) => FrameType::Printable(p.to_string()),
            Attachment(_) => unreachable!(),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::report::{Error, LoggableError};
    use error_stack::Report;

    #[test]
    fn correct_error_log() {
        let report = Report::new(Error::new("error1".to_string()))
            .attach_printable("foo1")
            .change_context(Error::new("error2".to_string()))
            .attach_printable("test1")
            .attach_printable("test2")
            .change_context(Error::new("error3".to_string()))
            .attach(5);

        let mut err = LoggableError::from(&report);

        let root_err = err.cause.as_mut().unwrap().cause.as_mut().unwrap();

        assert!(root_err.backtrace.is_some());
        assert!(!root_err.backtrace.as_ref().unwrap().0.is_empty());

        root_err.backtrace = None;

        let expected_err = LoggableError {
            msg: "error3".to_string(),
            attachments: vec!["opaque attachment".to_string()],
            location: "src/report.rs:159:14".to_string(),
            cause: Some(Box::new(LoggableError {
                msg: "error2".to_string(),
                attachments: vec!["test1".to_string(), "test2".to_string()],
                location: "src/report.rs:156:14".to_string(),
                cause: Some(Box::new(LoggableError {
                    msg: "error1".to_string(),
                    attachments: vec!["foo1".to_string()],
                    location: "src/report.rs:154:22".to_string(),
                    cause: None,
                    backtrace: None,
                })),
                backtrace: None,
            })),
            backtrace: None,
        };

        // assert_eq!(err.msg, "error3");
        // assert!(err.backtrace.is_none());
        // assert_eq!(err.location, "src/report.rs:159:14");
        // assert_eq!(err.attachments.len(), 1);
        assert_eq!(err, expected_err);
    }
}
