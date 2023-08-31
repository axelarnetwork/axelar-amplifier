use std::{collections::HashMap, fs, path::PathBuf};

use error_stack::{IntoReport, Result, ResultExt};
use serde::{Deserialize, Serialize};
use tendermint::block;
use thiserror::Error;
use tokio::sync::mpsc::Receiver;
use tokio_stream::wrappers::ReceiverStream;
use tokio_stream::{StreamExt, StreamMap};
use tracing::info;

use crate::types::PublicKey;

#[derive(Error, Debug)]
pub enum Error {
    #[error("invalid state file")]
    InvalidState,
    #[error("failed serializing the state")]
    SerializationFailure,
    #[error("failed writing the state file to disk")]
    WriteFailure,
}

#[derive(Serialize, Deserialize, Default)]
pub struct State {
    handlers: HashMap<String, block::Height>,
    pub pub_key: Option<PublicKey>,
}

impl State {
    pub fn min_handler_block_height(&self) -> Option<&block::Height> {
        self.handlers.values().min()
    }

    pub fn handler_block_height(&self, handler_name: &str) -> Option<&block::Height> {
        self.handlers.get(handler_name)
    }

    fn set_handler_block_height(&mut self, handler_name: String, height: block::Height) {
        self.handlers.insert(handler_name, height);
    }
}

pub struct StateUpdater {
    update_stream: StreamMap<String, ReceiverStream<block::Height>>,
    state_path: PathBuf,
    state: State,
}

impl StateUpdater {
    pub fn new(state_path: PathBuf) -> Result<Self, Error> {
        let state = match fs::read_to_string(state_path.as_path()) {
            Ok(state) => serde_json::from_str(&state)
                .into_report()
                .change_context(Error::InvalidState)?,
            Err(_) => {
                info!("state does not exist, falling back to default");

                State::default()
            }
        };

        Ok(Self {
            update_stream: StreamMap::new(),
            state_path,
            state,
        })
    }

    pub fn state(&self) -> &State {
        &self.state
    }

    pub fn register_event(
        &mut self,
        label: impl Into<String>,
        height_changed: Receiver<block::Height>,
    ) {
        self.update_stream
            .insert(label.into(), ReceiverStream::new(height_changed));
    }

    pub async fn run(mut self) -> Result<(), Error> {
        while let Some((handler, height)) = self.update_stream.next().await {
            info!(handler, height = height.value(), "state updated");
            self.state.set_handler_block_height(handler, height);
        }

        self.flush()
    }

    fn flush(self) -> Result<(), Error> {
        info!("persisting state to disk");

        let state = serde_json::to_string(&self.state)
            .into_report()
            .change_context(Error::SerializationFailure)?;

        fs::write(self.state_path, state)
            .into_report()
            .change_context(Error::WriteFailure)?;

        Ok(())
    }
}

impl AsMut<State> for StateUpdater {
    fn as_mut(&mut self) -> &mut State {
        &mut self.state
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::{fs, panic};

    use tokio::sync::mpsc;

    use super::{State, StateUpdater};

    fn run_test<T>(state_path: &PathBuf, test: T)
    where
        T: FnOnce() + panic::UnwindSafe,
    {
        let result = panic::catch_unwind(test);
        let _ = fs::remove_file(state_path);
        assert!(result.is_ok())
    }

    #[test]
    fn new_state_updater_should_read_from_the_file() {
        let state_path = PathBuf::from("./new_state_updater_should_read_from_the_file.json");

        run_test(&state_path, || {
            let state_updater = StateUpdater::new(state_path.clone()).unwrap();
            let state = state_updater.state();
            assert_eq!(state.handlers.len(), 0);

            fs::write(
                state_path.clone(),
                String::from("{\"handlers\":{\"a\":\"2\",\"b\":\"3\"}}"),
            )
            .unwrap();
            let state_updater = StateUpdater::new(state_path.clone()).unwrap();
            let state = state_updater.state();
            assert_eq!(state.handlers.len(), 2);
            assert_eq!(state.handler_block_height("a"), Some(&2_u32.into()));
            assert_eq!(state.handler_block_height("b"), Some(&3_u32.into()));
            assert_eq!(state.handler_block_height("c"), None);
        });
    }

    #[tokio::test]
    async fn state_updater_run_should_write_to_the_file() {
        let state_path = PathBuf::from("./state_updater_run_should_write_to_the_file.json");
        let (a_tx, a_rx) = mpsc::channel(5);
        let (b_tx, b_rx) = mpsc::channel(5);

        let mut state_updater = StateUpdater::new(state_path.clone()).unwrap();
        state_updater.register_event("a", a_rx);
        state_updater.register_event("b", b_rx);

        let handle = tokio::spawn(state_updater.run());

        a_tx.send(5_u32.into()).await.unwrap();
        a_tx.send(6_u32.into()).await.unwrap();
        a_tx.send(7_u32.into()).await.unwrap();
        b_tx.send(10_u32.into()).await.unwrap();

        drop(a_tx);
        drop(b_tx);

        let _ = handle.await;

        run_test(&state_path, || {
            let state = fs::read_to_string(state_path.as_path()).unwrap();
            let state: State = serde_json::from_str(&state).unwrap();

            assert_eq!(state.handlers.len(), 2);
            assert_eq!(state.handler_block_height("a"), Some(&7_u32.into()));
            assert_eq!(state.handler_block_height("b"), Some(&10_u32.into()));
            assert_eq!(state.handler_block_height("c"), None);
        });
    }
}
