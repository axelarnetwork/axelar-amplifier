use async_trait::async_trait;
use cosmrs::Any;
use error_stack::{Context, Result};
use events::Event;

use crate::event_sub::event_filter::EventFilters;

#[async_trait]
pub trait EventHandler {
    type Err: Context;

    async fn handle(&self, event: &Event) -> Result<Vec<Any>, Self::Err>;

    fn event_filters(&self) -> EventFilters;
}
