use std::backtrace::Backtrace;
use std::collections::VecDeque;
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::iter::FromIterator;
use std::panic::Location;

use error_stack::{AttachmentKind, Context, Frame, FrameKind, Report};
use itertools::Itertools;
use valuable::Valuable;

#[derive(Valuable, PartialEq, Debug, Default)]
pub struct LoggableError {
    pub msg: String,
    pub attachments: Vec<String>,
    pub location: String,
    pub cause: Option<Box<LoggableError>>,
    pub backtrace: Option<LoggableBacktrace>,
}

impl Display for LoggableError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let msg = if self.attachments.is_empty() {
            self.msg.clone()
        } else {
            let string = self
                .attachments
                .iter()
                .map(|a| format!("{:?}", a))
                .join(", ");
            format!("{} ({})", self.msg, string)
        };

        let output = match &self.cause {
            None => msg,
            Some(cause) => format!("{}: {}", msg, cause),
        };
        write!(f, "{}", output)
    }
}

impl Error for LoggableError {}

#[derive(Valuable, PartialEq, Eq, Debug)]
pub struct LoggableBacktrace {
    pub lines: Vec<String>,
}

impl<T> From<&Report<T>> for LoggableError {
    fn from(report: &Report<T>) -> Self {
        let mut errors: Vec<LoggableError> = Vec::new();

        let mut frames = VecDeque::from_iter(report.frames());
        while !frames.is_empty() {
            let mut error = LoggableError::default();
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
        LoggableBacktrace {
            lines: backtrace
                .to_string()
                .split('\n')
                .map(|s| s.to_string())
                .collect(),
        }
    }
}

fn chain_causes(errors: Vec<LoggableError>) -> Option<LoggableError> {
    errors
        .into_iter()
        // the outermost error appears first in the vector, so the iterator for the causal dependency needs to be reversed
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
    use crate::LoggableError;
    use error_stack::Report;
    use std::env;
    use thiserror::Error;

    #[derive(Error, Debug)]
    enum Error {
        #[error("{0}")]
        FromString(String),
    }

    #[test]
    fn correct_error_log() {
        env::set_var("RUST_BACKTRACE", "1");
        let line_offset = line!();
        let report = Report::new(Error::FromString("error1".to_string()))
            .attach_printable("foo1")
            .change_context(Error::FromString("error2".to_string()))
            .attach_printable("test1")
            .attach_printable("test2")
            .change_context(Error::FromString("error3".to_string()))
            .attach(5);

        let mut err = LoggableError::from(&report);

        let root_err = err.cause.as_mut().unwrap().cause.as_mut().unwrap();

        assert!(root_err.backtrace.is_some());
        assert!(!root_err.backtrace.as_ref().unwrap().lines.is_empty());

        root_err.backtrace = None;

        let expected_err = LoggableError {
            msg: "error3".to_string(),
            attachments: vec!["opaque attachment".to_string()],
            location: format!("packages/report/src/loggable.rs:{}:14", line_offset + 6),
            cause: Some(Box::new(LoggableError {
                msg: "error2".to_string(),
                attachments: vec!["test1".to_string(), "test2".to_string()],
                location: format!("packages/report/src/loggable.rs:{}:14", line_offset + 3),
                cause: Some(Box::new(LoggableError {
                    msg: "error1".to_string(),
                    attachments: vec!["foo1".to_string()],
                    location: format!("packages/report/src/loggable.rs:{}:22", line_offset + 1),
                    cause: None,
                    backtrace: None,
                })),
                backtrace: None,
            })),
            backtrace: None,
        };

        assert_eq!(err, expected_err);
    }

    #[test]
    fn display_should_not_panic() {
        let vec_attachment = format!("{:?}", vec![1, 2, 3, 4, 5]);
        let report = Report::new(Error::FromString("internal error".to_string()))
            .attach_printable("inner attachment")
            .change_context(Error::FromString("middle error".to_string()))
            .attach_printable("test1")
            .attach_printable(format!("{{ value = {:?} }}", 5))
            .change_context(Error::FromString("outer error".to_string()))
            .attach(5)
            .attach_printable(vec_attachment.clone());

        let error = LoggableError::from(&report);
        println!("{}", error);
        let error_msg = format!("{}", error);

        assert!(error_msg.contains("internal error"));
        assert!(error_msg.contains("middle error"));
        assert!(error_msg.contains("outer error"));
        assert!(error_msg.contains("test1"));
        assert!(error_msg.contains("value"));
        assert!(error_msg.contains("inner attachment"));
        assert!(error_msg.contains(vec_attachment.as_str()));
    }
}
