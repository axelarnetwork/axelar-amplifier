use std::fmt::Display;

use cosmrs::Any;
use error_stack::{report, Context, Report};
use itertools::Itertools;
use report::LoggableError;
use serde_json;
use tracing::error;
use valuable::Valuable;

use super::event_handler::{Error, HandlerTaskAction};

/// Default callback for event subscription errors.
/// Logs the error and continues processing.
pub fn default_event_subscription_error_cb(err: Report<Error>) -> HandlerTaskAction {
    error!(
        err = LoggableError::from(&err).as_value(),
        "failed to subscribe to events"
    );

    HandlerTaskAction::Continue
}

/// Default callback for event handler errors.
/// Logs the error along with the event information and continues processing.
pub fn default_handler_error_cb<E, Err>(event: &E, err: Err) -> HandlerTaskAction
where
    E: Display,
    Err: Context,
{
    error!(
        err = LoggableError::from(&report!(err)).as_value(),
        event = format!("{event}").as_value(),
        "failed to handle events"
    );

    HandlerTaskAction::Continue
}

/// Default callback for message broadcast errors.
/// Logs the error along with the serialized messages and continues processing.
pub fn default_broadcast_error_cb<Err>(msgs: &[Any], err: Err) -> HandlerTaskAction
where
    Err: Context,
{
    let msgs: Vec<String> = msgs
        .iter()
        .map(serde_json::to_string)
        .try_collect()
        .unwrap_or_default();

    error!(
        err = LoggableError::from(&report!(err)).as_value(),
        msgs = msgs.as_value(),
        "failed to broadcast messages"
    );

    HandlerTaskAction::Continue
}
