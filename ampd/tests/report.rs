use error_stack::Report;
use thiserror::Error;

use ampd::report::LoggableError;
use std::env;

#[derive(Error, Debug)]
enum Error {
    #[error("{0}")]
    FromString(String),
}

// Do not move this test or the location field checks break
#[test]
fn correct_error_log() {
    env::set_var("RUST_BACKTRACE", "1");
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
        location: "ampd/tests/report.rs:22:10".to_string(),
        cause: Some(Box::new(LoggableError {
            msg: "error2".to_string(),
            attachments: vec!["test1".to_string(), "test2".to_string()],
            location: "ampd/tests/report.rs:19:10".to_string(),
            cause: Some(Box::new(LoggableError {
                msg: "error1".to_string(),
                attachments: vec!["foo1".to_string()],
                location: "ampd/tests/report.rs:17:18".to_string(),
                cause: None,
                backtrace: None,
            })),
            backtrace: None,
        })),
        backtrace: None,
    };

    assert_eq!(err, expected_err);
}
