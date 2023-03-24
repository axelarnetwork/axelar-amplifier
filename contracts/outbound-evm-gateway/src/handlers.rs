use cosmwasm_std::{Event, Uint64};

pub fn expired_signing_handler(signing_session_id: Uint64) -> Event {
    // TODO: penalize non-voters
    build_event("SigningExpired", signing_session_id)
}

pub fn completed_signing_handler(signing_session_id: Uint64) -> Event {
    // TODO: rewards
    build_event("SigningCompleted", signing_session_id)
}

fn build_event(event_type: &str, signing_session_id: Uint64) -> Event {
    Event::new(event_type).add_attribute("sig_id", signing_session_id)
}
