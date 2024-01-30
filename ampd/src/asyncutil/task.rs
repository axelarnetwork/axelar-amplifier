use axelar_wasm_std::error::extend_err;
use error_stack::{Context, Result, ResultExt};
use std::future::Future;
use std::pin::Pin;
use thiserror::Error;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tracing::info;

/// The Task trait defines a container that allows easy creation, movement, storage and execution of cancellable async behaviour
pub trait Task {
    type Output;

    fn create<Fut>(task: impl FnOnce(CancellationToken) -> Fut + Send + 'static) -> Self
    where
        Fut: Future<Output = Self::Output> + Send + 'static;

    async fn run(self, token: CancellationToken) -> Self::Output;
}

/// This type represents an awaitable action that can be cancelled. It abstracts away the necessary boxing and pinning
/// to make it work in async contexts
pub type CancellableTask<Output> =
    Box<dyn FnOnce(CancellationToken) -> Pin<Box<dyn Future<Output = Output> + Send>> + Send>;

impl<T> Task for CancellableTask<T> {
    type Output = T;

    fn create<Fut>(task: impl FnOnce(CancellationToken) -> Fut + Send + 'static) -> Self
    where
        Fut: Future<Output = Self::Output> + Send + 'static,
    {
        Box::new(move |token: CancellationToken| Box::pin(task(token)))
    }

    async fn run(self, token: CancellationToken) -> Self::Output {
        self(token).await
    }
}

pub struct TaskManager<E>
where
    E: From<TaskError> + Context,
{
    tasks: Vec<CancellableTask<Result<(), E>>>,
}

impl<E> TaskManager<E>
where
    E: From<TaskError> + Context,
{
    pub fn new() -> Self {
        TaskManager { tasks: vec![] }
    }

    pub fn add_task(mut self, task: CancellableTask<Result<(), E>>) -> Self {
        self.tasks.push(task);
        self
    }

    pub async fn run(self, token: CancellationToken) -> Result<(), E> {
        let mut running_tasks = start_tasks(self.tasks, token.child_token());
        wait_for_completion(&mut running_tasks, &token).await
    }
}

fn start_tasks<T>(tasks: Vec<CancellableTask<T>>, token: CancellationToken) -> JoinSet<T>
where
    T: Send + 'static,
{
    let mut join_set = JoinSet::new();

    for task in tasks.into_iter() {
        // tasks clean up on their own after the cancellation token is triggered, so we discard the abort handles
        join_set.spawn(task(token.clone()));
    }
    join_set
}

async fn wait_for_completion<E>(
    running_tasks: &mut JoinSet<Result<(), E>>,
    token: &CancellationToken,
) -> Result<(), E>
where
    E: From<TaskError> + Context,
{
    let mut final_result = Ok(());
    let total_task_count = running_tasks.len();
    while let Some(task_result) = running_tasks.join_next().await {
        // if one task stops, all others should stop as well, so we cancel the token.
        // Any call to this after the first is a no-op, so no need to guard it.
        token.cancel();
        info!(
            "shutting down sub-tasks ({}/{})",
            total_task_count - running_tasks.len(),
            total_task_count
        );

        final_result = match task_result.change_context(E::from(TaskError {})) {
            Err(err) | Ok(Err(err)) => extend_err(final_result, err),
            Ok(_) => final_result,
        };
    }

    final_result
}

#[derive(Error, Debug)]
#[error("task failed")]
pub struct TaskError;

#[cfg(test)]
mod test {
    use crate::asyncutil::task::{CancellableTask, Task, TaskError, TaskManager};
    use error_stack::report;
    use tokio_util::sync::CancellationToken;

    #[tokio::test]
    async fn running_no_tasks_returns_no_error() {
        let tasks: TaskManager<TaskError> = TaskManager::new();
        assert!(tasks.run(CancellationToken::new()).await.is_ok());
    }

    #[tokio::test]
    async fn when_one_task_ends_cancel_all_others() {
        let waiting_task = |token: CancellationToken| async move {
            token.cancelled().await;
            Ok(())
        };

        let tasks: TaskManager<TaskError> = TaskManager::new()
            .add_task(CancellableTask::create(waiting_task))
            .add_task(CancellableTask::create(waiting_task))
            .add_task(CancellableTask::create(|_| async { Ok(()) }))
            .add_task(CancellableTask::create(waiting_task));
        assert!(tasks.run(CancellationToken::new()).await.is_ok());
    }

    #[tokio::test]
    async fn collect_all_errors_on_completion() {
        let tasks = TaskManager::new()
            .add_task(CancellableTask::create(|_| async { Ok(()) }))
            .add_task(CancellableTask::create(|_| async {
                Err(report!(TaskError {}))
            }))
            .add_task(CancellableTask::create(|_| async {
                Err(report!(TaskError {}))
            }))
            .add_task(CancellableTask::create(|_| async {
                Err(report!(TaskError {}))
            }))
            .add_task(CancellableTask::create(|_| async { Ok(()) }))
            .add_task(CancellableTask::create(|_| async {
                Err(report!(TaskError {}))
            }));
        let result = tasks.run(CancellationToken::new()).await;
        let err = result.unwrap_err();
        assert_eq!(err.current_frames().len(), 4);
    }

    #[tokio::test]
    async fn shutdown_gracefully_on_task_panic() {
        let tasks = TaskManager::new()
            .add_task(CancellableTask::create(|_| async { Ok(()) }))
            .add_task(CancellableTask::create(|_| async { panic!("panic") }))
            .add_task(CancellableTask::create(|_| async {
                Err(report!(TaskError {}))
            }))
            .add_task(CancellableTask::create(|_| async { Ok(()) }))
            .add_task(CancellableTask::create(|_| async {
                Err(report!(TaskError {}))
            }));
        let result = tasks.run(CancellationToken::new()).await;
        let err = result.unwrap_err();
        assert_eq!(err.current_frames().len(), 3);
    }
}
