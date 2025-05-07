use std::fmt::Display;

use error_stack::{Context, Report};
use report::LoggableError;
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
pub fn default_handler_error_cb<E, Err>(event: &E, err: Report<Err>) -> HandlerTaskAction
where
    E: Display,
    Err: Context,
{
    error!(
        err = LoggableError::from(&err).as_value(),
        event = format!("{event}").as_value(),
        "failed to handle events"
    );

    HandlerTaskAction::Continue
}

#[cfg(test)]
mod tests {
    use error_stack::report;
    use events::Event;

    use super::*;

    #[tokio::test]
    async fn test_default_event_subscription_error_cb() {
        let error = report!(Error::EventStream);
        let action = default_event_subscription_error_cb(error);

        assert!(matches!(action, HandlerTaskAction::Continue));
    }

    #[tokio::test]
    async fn test_default_handler_error_cb() {
        let event = Event::BlockBegin(1u32.into());
        let error = report!(Error::HandlerFailed);
        let action = default_handler_error_cb(&event, error);

        assert!(matches!(action, HandlerTaskAction::Continue));
    }
}
