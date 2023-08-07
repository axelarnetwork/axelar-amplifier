use std::{collections::HashMap, fs, path::PathBuf};

use error_stack::{IntoReport, Result, ResultExt};
use tendermint::block;
use thiserror::Error;
use tokio::sync::mpsc::Receiver;
use tokio_stream::wrappers::ReceiverStream;
use tokio_stream::{StreamExt, StreamMap};
use tracing::info;

#[derive(Error, Debug)]
pub enum Error {
    #[error("invalid state file")]
    InvalidState,
    #[error("failed serializing the state")]
    SerializationFailure,
    #[error("failed writing the state file to disk")]
    WriteFailure,
}

pub struct State<'a> {
    state: HashMap<String, block::Height>,
    path: &'a PathBuf,
}

impl<'a> State<'a> {
    pub fn new(path: &'a PathBuf) -> Result<Self, Error> {
        let state = fs::read_to_string(path.as_path()).into_report().unwrap_or_else(|_| {
            info!("state does not exist, falling back to default");

            "{}".into()
        });

        Ok(Self {
            state: serde_json::from_str(&state)
                .into_report()
                .change_context(Error::InvalidState)?,
            path,
        })
    }

    pub fn min(&self) -> Option<&block::Height> {
        self.state.values().min()
    }

    pub fn get(&self, label: &str) -> Option<&block::Height> {
        self.state.get(label)
    }

    pub fn set(&mut self, label: String, height: block::Height) {
        self.state.insert(label, height);
    }

    fn flush(self) -> Result<(), Error> {
        let state = serde_json::to_string(&self.state)
            .into_report()
            .change_context(Error::SerializationFailure)?;

        fs::write(self.path, state)
            .into_report()
            .change_context(Error::WriteFailure)?;

        Ok(())
    }
}

#[derive(Default)]
pub struct Updater {
    update_stream: StreamMap<String, ReceiverStream<block::Height>>,
}

impl Updater {
    pub fn register_event(&mut self, label: impl Into<String>, height_changed: Receiver<block::Height>) {
        self.update_stream
            .insert(label.into(), ReceiverStream::new(height_changed));
    }

    pub async fn run(mut self, mut state: State<'_>) -> Result<(), Error> {
        while let Some((handler, height)) = self.update_stream.next().await {
            info!(handler, height = height.value(), "state updated");
            state.set(handler, height);
        }

        info!("persisting state to disk");

        state.flush()
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::{fs, panic};

    use super::State;

    fn run_test<T>(state_path: &PathBuf, test: T)
    where
        T: FnOnce() + panic::UnwindSafe,
    {
        let result = panic::catch_unwind(test);
        let _ = fs::remove_file(state_path);
        assert!(result.is_ok())
    }

    #[test]
    fn new_state_should_read_from_the_file() {
        let state_path = PathBuf::from("./new_state_should_read_from_the_file.json");

        run_test(&state_path, || {
            let state = State::new(&state_path).unwrap();
            assert_eq!(state.state.len(), 0);

            fs::write(&state_path, String::from("{\"a\": \"2\", \"b\": \"3\"}")).unwrap();
            let state = State::new(&state_path).unwrap();
            assert_eq!(state.state.len(), 2);
            assert_eq!(state.get("a"), Some(&2_u32.into()));
            assert_eq!(state.get("b"), Some(&3_u32.into()));
            assert_eq!(state.get("c"), None);
        });
    }

    #[test]
    fn get_set_should_work() {
        let state_path = PathBuf::from("./get_set_should_work.json");

        run_test(&state_path, || {
            let mut state = State::new(&state_path).unwrap();
            assert_eq!(state.state.len(), 0);

            state.set("a".into(), 2_u32.into());
            assert_eq!(state.state.len(), 1);
            assert_eq!(state.get("a"), Some(&2_u32.into()));

            state.set("b".into(), 3_u32.into());
            assert_eq!(state.state.len(), 2);
            assert_eq!(state.get("b"), Some(&3_u32.into()));
        });
    }

    #[test]
    fn flush_should_work() {
        let state_path = PathBuf::from("./flush_should_work.json");

        run_test(&state_path, || {
            let mut state = State::new(&state_path).unwrap();
            assert_eq!(state.state.len(), 0);

            state.set("a".into(), 2_u32.into());
            state.set("b".into(), 3_u32.into());
            state.flush().unwrap();

            let state = State::new(&state_path).unwrap();
            assert_eq!(state.state.len(), 2);
            assert_eq!(state.get("a"), Some(&2_u32.into()));
            assert_eq!(state.get("b"), Some(&3_u32.into()));
        });
    }
}
