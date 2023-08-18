use std::collections::VecDeque;
use std::iter::FromIterator;
use std::panic::Location;
use std::{backtrace::Backtrace, fmt::Display};

use error_stack::{AttachmentKind, Context, Frame, FrameKind, Report};
use thiserror::Error;
use valuable::Valuable;

#[derive(Error, Debug)]
pub enum Error {
    #[error("event sub failed")]
    EventSub,
    #[error("event processor failed")]
    EventProcessor,
    #[error("broadcaster failed")]
    Broadcaster,
    #[error("state updater failed")]
    StateUpdater,
    #[error("{0}")]
    Error(String),
}

impl Error {
    pub fn new<T>(msg: T) -> Error
    where
        T: Display,
    {
        Error::Error(msg.to_string())
    }
}

#[derive(Valuable, PartialEq, Debug, Default)]
pub struct LoggableError {
    pub msg: String,
    pub attachments: Vec<String>,
    pub location: String,
    pub cause: Option<Box<LoggableError>>,
    pub backtrace: Option<LoggableBacktrace>,
}

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
            lines: backtrace.to_string().split('\n').map(|s| s.to_string()).collect(),
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
