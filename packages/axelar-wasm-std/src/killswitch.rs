use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Event, Response, StdError, StdResult, Storage};
use cw_storage_plus::Item;

/// This is a generic module to be used as a "killswitch" for any contract.
/// The killswitch can be set to "engaged" or "disengaged". The contract
/// can then call `is_contract_active`, which will return true if the killswitch
/// is disengaged. `init` should be called at contract instantiation to set
/// the initial state of the killswitch.

#[cw_serde]
pub enum State {
    Engaged,
    Disengaged,
}

/// Sets the initial state of the killswitch. Should be called during contract instantiation
pub fn init(storage: &mut dyn Storage, initial_state: State) -> StdResult<()> {
    STATE.save(storage, &initial_state)
}

/// Sets the killswitch state to `Engaged`. If the state was previously `Disengaged`,
/// adds the on_state_changed event to the response. Returns an error if the killswitch
/// was not initialized via `init`
pub fn engage(storage: &mut dyn Storage, on_state_change: impl Into<Event>) -> StdResult<Response> {
    let state = STATE.update(storage, |state| match state {
        State::Disengaged => Ok(State::Engaged),
        State::Engaged => Err(KillSwitchUpdateError::SameState),
    });

    killswitch_update_response(state, on_state_change)
}

/// Sets the killswitch state to `Disengaged`. If the state was previously `Engaged`,
/// adds the on_state_changed event to the response. Returns an error if the killswitch
/// was not initialized via `init`
pub fn disengage(
    storage: &mut dyn Storage,
    on_state_change: impl Into<Event>,
) -> StdResult<Response> {
    let state = STATE.update(storage, |state| match state {
        State::Engaged => Ok(State::Disengaged),
        State::Disengaged => Err(KillSwitchUpdateError::SameState),
    });

    killswitch_update_response(state, on_state_change)
}

/// Returns true if the killswitch state is `Disengaged`. Otherwise returns false.
/// Returns false if the killswitch was not initialized
pub fn is_contract_active(storage: &dyn Storage) -> bool {
    STATE.load(storage).unwrap_or(State::Engaged) == State::Disengaged
}

#[derive(thiserror::Error, Debug)]
enum KillSwitchUpdateError {
    #[error("killswitch is already in the same state")]
    SameState,
    #[error(transparent)]
    Std(#[from] StdError),
}

fn killswitch_update_response(
    state: Result<State, KillSwitchUpdateError>,
    on_state_change: impl Into<Event>,
) -> StdResult<Response> {
    match state {
        Ok(_) => Ok(Response::new().add_event(on_state_change.into())),
        Err(KillSwitchUpdateError::SameState) => Ok(Response::new()),
        Err(KillSwitchUpdateError::Std(err)) => Err(err),
    }
}

const STATE: Item<State> = Item::new("state");

#[cfg(test)]
mod tests {
    use cosmwasm_std::testing::mock_dependencies;
    use cosmwasm_std::Event;

    use crate::killswitch::{disengage, engage, init, is_contract_active, State, STATE};

    enum Events {
        Engaged,
        Disengaged,
    }

    impl From<Events> for Event {
        fn from(val: Events) -> Event {
            match val {
                Events::Engaged => Event::new("engaged"),
                Events::Disengaged => Event::new("disengaged"),
            }
        }
    }

    #[test]
    fn init_should_be_able_to_set_state_to_engaged() {
        let mut deps = mock_dependencies();
        assert!(STATE.may_load(&deps.storage).unwrap().is_none());

        init(deps.as_mut().storage, State::Engaged).unwrap();

        assert_eq!(STATE.load(&deps.storage).unwrap(), State::Engaged);
        assert!(!is_contract_active(&deps.storage));
    }

    #[test]
    fn init_should_be_able_to_set_state_to_disengaged() {
        let mut deps = mock_dependencies();
        assert!(STATE.may_load(&deps.storage).unwrap().is_none());

        init(deps.as_mut().storage, State::Disengaged).unwrap();

        assert_eq!(STATE.load(&deps.storage).unwrap(), State::Disengaged);
        assert!(is_contract_active(&deps.storage));
    }

    #[test]
    fn is_contract_active_should_return_true_when_disengaged() {
        let mut deps = mock_dependencies();

        assert!(!is_contract_active(&deps.storage));

        STATE.save(deps.as_mut().storage, &State::Engaged).unwrap();

        assert!(!is_contract_active(&deps.storage));

        STATE
            .save(deps.as_mut().storage, &State::Disengaged)
            .unwrap();

        assert!(is_contract_active(&deps.storage));
    }

    #[test]
    fn engage_should_error_when_unset() {
        let mut deps = mock_dependencies();

        assert!(engage(deps.as_mut().storage, Events::Engaged).is_err());
    }

    #[test]
    fn engage_should_correctly_set_state_when_disengaged() {
        let mut deps = mock_dependencies();

        STATE
            .save(deps.as_mut().storage, &State::Disengaged)
            .unwrap();
        engage(deps.as_mut().storage, Events::Engaged).unwrap();
        assert_eq!(STATE.load(&deps.storage).unwrap(), State::Engaged);
        assert!(!is_contract_active(&deps.storage));
    }

    #[test]
    fn engage_should_correctly_set_state_when_engaged() {
        let mut deps = mock_dependencies();

        STATE.save(deps.as_mut().storage, &State::Engaged).unwrap();
        engage(deps.as_mut().storage, Events::Engaged).unwrap();
        assert_eq!(STATE.load(&deps.storage).unwrap(), State::Engaged);
        assert!(!is_contract_active(&deps.storage));
    }

    #[test]
    fn disengage_should_error_when_unset() {
        let mut deps = mock_dependencies();

        assert!(disengage(deps.as_mut().storage, Events::Disengaged).is_err());
    }

    #[test]
    fn disengage_should_correctly_set_state_when_disengaged() {
        let mut deps = mock_dependencies();

        STATE
            .save(deps.as_mut().storage, &State::Disengaged)
            .unwrap();
        disengage(deps.as_mut().storage, Events::Disengaged).unwrap();
        assert_eq!(STATE.load(&deps.storage).unwrap(), State::Disengaged);
        assert!(is_contract_active(&deps.storage));
    }

    #[test]
    fn disengage_should_correctly_set_state_when_engaged() {
        let mut deps = mock_dependencies();

        STATE.save(deps.as_mut().storage, &State::Engaged).unwrap();
        disengage(deps.as_mut().storage, Events::Engaged).unwrap();
        assert_eq!(STATE.load(&deps.storage).unwrap(), State::Disengaged);
        assert!(is_contract_active(&deps.storage));
    }

    #[test]
    fn engage_and_disengage_should_emit_event_when_state_changes() {
        let mut deps = mock_dependencies();

        init(deps.as_mut().storage, State::Disengaged).unwrap();

        let engaged_event: Event = Events::Engaged.into();
        let disengaged_event: Event = Events::Disengaged.into();

        let res = engage(deps.as_mut().storage, Events::Engaged).unwrap();
        assert!(res.events.into_iter().any(|event| event == engaged_event));

        let res = engage(deps.as_mut().storage, Events::Engaged).unwrap();
        assert_eq!(res.events.len(), 0);

        let res = disengage(deps.as_mut().storage, Events::Disengaged).unwrap();
        assert!(res
            .events
            .into_iter()
            .any(|event| event == disengaged_event));

        let res = disengage(deps.as_mut().storage, Events::Disengaged).unwrap();
        assert_eq!(res.events.len(), 0);
    }
}
