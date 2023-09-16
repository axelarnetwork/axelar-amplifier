use std::path::Path;
use std::{collections::HashMap, fs};

use error_stack::{Result, ResultExt};
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
    #[error("failed to serialize the state")]
    SerializationFailure,
    #[error("failed to write the state file to disk")]
    WriteFailure,
}

#[derive(Serialize, Deserialize, Default, Clone, Debug, PartialEq, Eq)]
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

    pub fn set_handler_block_height(
        &mut self,
        handler_name: impl Into<String>,
        height: impl Into<block::Height>,
    ) {
        self.handlers.insert(handler_name.into(), height.into());
    }
}

pub struct StateUpdater {
    update_stream: StreamMap<String, ReceiverStream<block::Height>>,
    state: State,
}

impl StateUpdater {
    pub fn new(state: State) -> Self {
        Self {
            update_stream: StreamMap::new(),
            state,
        }
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

    pub async fn run(mut self) -> State {
        while let Some((handler, height)) = self.update_stream.next().await {
            info!(handler, height = height.value(), "state updated");
            self.state.set_handler_block_height(handler, height);
        }

        self.state
    }
}

impl AsMut<State> for StateUpdater {
    fn as_mut(&mut self) -> &mut State {
        &mut self.state
    }
}

pub fn load(path: impl AsRef<Path>) -> Result<State, Error> {
    info!("loading state from disk");

    match fs::read_to_string(path) {
        Ok(state) => serde_json::from_str(&state).change_context(Error::InvalidState),
        Err(_) => {
            info!("state file does not exist, starting from current blockchain state");
            Ok(State::default())
        }
    }
}

pub fn flush(state: &State, path: impl AsRef<Path>) -> Result<(), Error> {
    info!("persisting state to disk");

    let state = serde_json::to_string(state).change_context(Error::SerializationFailure)?;
    ensure_parent_dirs_exist(&path)?;

    fs::write(&path, state)
        .change_context(Error::WriteFailure)
        .attach_printable(format!("{}", path.as_ref().display()))?;

    Ok(())
}

fn ensure_parent_dirs_exist(path: impl AsRef<Path>) -> Result<(), Error> {
    match path.as_ref().parent() {
        Some(parent) if !parent.exists() => fs::create_dir_all(parent)
            .change_context(Error::WriteFailure)
            .attach_printable(format!("{}", parent.display())),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use crate::state;
    use ecdsa::signature::rand_core::OsRng;
    use std::path::{Path, PathBuf};
    use std::{fs, panic};
    use tokio::sync::mpsc;

    use super::{State, StateUpdater};

    fn run_test<T>(state_path: impl AsRef<Path>, test: T)
    where
        T: FnOnce() + panic::UnwindSafe,
    {
        let result = panic::catch_unwind(test);
        let _ = fs::remove_file(&state_path);
        let _ = state_path.as_ref().parent().map(fs::remove_dir);
        assert!(result.is_ok())
    }

    #[test]
    fn can_load_and_flush_state() {
        let path = PathBuf::from("./state_subfolder/can_load_and_flush_state.json");
        run_test(&path, || {
            let mut state = State::default();
            state.pub_key = Some(ecdsa::SigningKey::random(&mut OsRng).verifying_key().into());
            state.set_handler_block_height("handler1", 10u16);
            state.set_handler_block_height("handler2", 15u16);
            state.set_handler_block_height("handler3", 7u16);

            state::flush(&state, &path).unwrap();
            let loaded_state = state::load(&path).unwrap();

            assert_eq!(state, loaded_state);
        });
    }

    #[tokio::test]
    async fn can_update_state() {
        let mut state_updater = StateUpdater::new(State::default());
        let state = state_updater.state();
        assert_eq!(state.handlers.len(), 0);

        let (tx1, rx1) = mpsc::channel(10);
        let (tx2, rx2) = mpsc::channel(10);
        state_updater.register_event("handler1", rx1);
        state_updater.register_event("handler2", rx2);

        let pub_key = Some(ecdsa::SigningKey::random(&mut OsRng).verifying_key().into());
        state_updater.as_mut().pub_key = pub_key;

        let handle1 = tokio::spawn(async move {
            tx1.send(1u16.into()).await.unwrap();
            tx1.send(2u16.into()).await.unwrap();
            tx1.send(3u16.into()).await.unwrap();
        });

        let handle2 = tokio::spawn(async move {
            tx2.send(1u16.into()).await.unwrap();
            tx2.send(2u16.into()).await.unwrap();
            tx2.send(3u16.into()).await.unwrap();
            tx2.send(4u16.into()).await.unwrap();
        });

        let state_runner = state_updater.run();

        assert!(handle1.await.is_ok());
        assert!(handle2.await.is_ok());

        let modified_state = state_runner.await;

        let mut expected_state = State {
            pub_key,
            ..State::default()
        };
        expected_state.set_handler_block_height("handler1", 3u16);
        expected_state.set_handler_block_height("handler2", 4u16);

        assert_eq!(modified_state, expected_state);

        assert_eq!(
            modified_state.min_handler_block_height(),
            Some(&3u16.into())
        );
    }
}
