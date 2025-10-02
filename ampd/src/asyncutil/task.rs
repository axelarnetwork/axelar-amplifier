use std::future::Future;
use std::pin::Pin;

use axelar_wasm_std::error::extend_err;
use error_stack::{report, Context, Result, ResultExt};
use thiserror::Error;
use tokio::io::Error as IoError;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

type PinnedFuture<T> = Pin<Box<dyn Future<Output = T> + Send>>;
/// This type represents an awaitable action that can be cancelled. It abstracts away the necessary boxing and pinning
/// to make it work in async contexts. It can be freely moved around and stored in collections.
pub struct CancellableTask<T> {
    run_task: Box<dyn FnOnce(CancellationToken) -> PinnedFuture<T> + Send>,
}

impl<T> CancellableTask<T> {
    /// Creates a movable task from an async function or closure.
    pub fn create<Fut>(func: impl FnOnce(CancellationToken) -> Fut + Send + 'static) -> Self
    where
        Fut: Future<Output = T> + Send + 'static,
    {
        Self {
            run_task: Box::new(move |token: CancellationToken| Box::pin(func(token))),
        }
    }

    pub async fn run(self, token: CancellationToken) -> T {
        (self.run_task)(token).await
    }
}

pub struct TaskGroup<E>
where
    E: Context,
{
    name: String,
    tasks: Vec<(String, CancellableTask<Result<(), E>>)>,
}

impl<E> TaskGroup<E>
where
    E: Context,
{
    pub fn new(name: impl Into<String>) -> Self {
        TaskGroup {
            name: name.into(),
            tasks: vec![],
        }
    }

    /// The added tasks won't be started until [Self::run] is called
    pub fn add_task(
        mut self,
        task_name: impl Into<String>,
        task: CancellableTask<Result<(), E>>,
    ) -> Self {
        self.tasks.push((task_name.into(), task));
        self
    }

    /// Runs all tasks concurrently. If one task fails, all others are cancelled and the collection of errors is returned.
    /// If a task panics, it still returns an error to the manager, so the parent process can shut down all tasks gracefully.
    pub async fn run(self, token: CancellationToken) -> Result<(), TaskGroupError> {
        // running tasks and waiting for them is tightly coupled, so they both share a cloned token
        let mut running_tasks = start_tasks(self.tasks, token.clone());
        wait_for_completion(self.name, &mut running_tasks, &token).await
    }
}

fn start_tasks<T>(
    tasks: Vec<(String, CancellableTask<T>)>,
    token: CancellationToken,
) -> JoinSet<(String, T)>
where
    T: Send + 'static,
{
    let mut join_set = JoinSet::new();

    for (task_name, task) in tasks.into_iter() {
        // tasks clean up on their own after the cancellation token is triggered, so we discard the abort handles.
        // However, we don't know what tasks will do with their token, so we need to create new child tokens here,
        // so each task can act independently
        let child_token = token.child_token();
        join_set.spawn(async move {
            let result = task.run(child_token).await;
            (task_name, result)
        });
    }
    join_set
}

async fn wait_for_completion<E>(
    group_name: String,
    running_tasks: &mut JoinSet<(String, Result<(), E>)>,
    token: &CancellationToken,
) -> Result<(), TaskGroupError>
where
    E: Context,
{
    let mut final_result = Ok(());
    let total_task_count = running_tasks.len();
    while let Some(task_result) = running_tasks.join_next().await {
        // if one task stops, all others should stop as well, so we cancel the token.
        // Any call to this after the first is a no-op, so no need to guard it.
        token.cancel();

        match task_result {
            Ok((task_name, task_result)) => {
                info!(
                    "shutting down {} sub-tasks ({}/{}) - task '{}' completed",
                    group_name,
                    total_task_count.saturating_sub(running_tasks.len()),
                    total_task_count,
                    task_name
                );

                final_result = match task_result {
                    Err(err) => extend_err(final_result, err.change_context(TaskError {})),
                    Ok(()) => final_result,
                };
            }
            Err(join_error) => {
                warn!(
                    "shutting down {} sub-tasks ({}/{}) - task aborted or panicked: {}",
                    group_name,
                    total_task_count.saturating_sub(running_tasks.len()),
                    total_task_count,
                    join_error
                );

                final_result = extend_err(
                    final_result,
                    report!(IoError::from(join_error)).change_context(TaskError {}),
                );
            }
        }
    }

    final_result.change_context(TaskGroupError {})
}

#[derive(Error, Debug)]
#[error("task failed")]
pub struct TaskError;

#[derive(Error, Debug)]
#[error("task group execution failed")]
pub struct TaskGroupError;

#[cfg(test)]
mod test {
    use error_stack::report;
    use strip_ansi_escapes::strip;
    use temp_env::async_with_vars;
    use tokio_util::sync::CancellationToken;

    use crate::asyncutil::task::{CancellableTask, TaskError, TaskGroup};

    #[tokio::test]
    async fn running_no_tasks_returns_no_error() {
        let tasks: TaskGroup<TaskError> = TaskGroup::new("test");
        assert!(tasks.run(CancellationToken::new()).await.is_ok());
    }

    #[tokio::test]
    async fn when_one_task_ends_cancel_all_others() {
        let waiting_task = |token: CancellationToken| async move {
            token.cancelled().await;
            Ok(())
        };

        let tasks: TaskGroup<TaskError> = TaskGroup::new("test")
            .add_task("waiting_task_1", CancellableTask::create(waiting_task))
            .add_task("waiting_task_2", CancellableTask::create(waiting_task))
            .add_task(
                "immediate_task",
                CancellableTask::create(|_| async { Ok(()) }),
            )
            .add_task("waiting_task_3", CancellableTask::create(waiting_task));
        assert!(tasks.run(CancellationToken::new()).await.is_ok());
    }

    #[tokio::test]
    async fn collect_all_errors_on_completion() {
        async_with_vars([("RUST_BACKTRACE", Some("0"))], async {
            let tasks = TaskGroup::new("test")
                .add_task(
                    "error_task_1",
                    CancellableTask::create(|token| async move {
                        token.cancelled().await;
                        Err(report!(TaskError {}))
                    }),
                )
                .add_task(
                    "error_task_2",
                    CancellableTask::create(|token| async move {
                        token.cancelled().await;
                        Err(report!(TaskError {}))
                    }),
                )
                .add_task(
                    "success_task_1",
                    CancellableTask::create(|_| async { Ok(()) }),
                )
                .add_task(
                    "error_task_3",
                    CancellableTask::create(|token| async move {
                        token.cancelled().await;
                        Err(report!(TaskError {}))
                    }),
                )
                .add_task(
                    "success_task_2",
                    CancellableTask::create(|_| async { Ok(()) }),
                )
                .add_task(
                    "error_task_4",
                    CancellableTask::create(|token| async move {
                        token.cancelled().await;
                        Err(report!(TaskError {}))
                    }),
                );
            let result = tasks.run(CancellationToken::new()).await;
            let err = result.unwrap_err();

            let error_output = String::from_utf8(strip(format!("{:?}", err))).unwrap();
            goldie::assert!(error_output);
        })
        .await;
    }

    #[tokio::test]
    async fn shutdown_gracefully_on_task_panic() {
        async_with_vars([("RUST_BACKTRACE", Some("0"))], async {
            let tasks = TaskGroup::new("test")
                .add_task(
                    "success_task_1",
                    CancellableTask::create(|_| async { Ok(()) }),
                )
                .add_task(
                    "panic_task",
                    CancellableTask::create(|_| async { panic!("panic") }),
                )
                .add_task(
                    "error_task",
                    CancellableTask::create(|_| async { Err(report!(TaskError {})) }),
                )
                .add_task(
                    "success_task_2",
                    CancellableTask::create(|_| async { Ok(()) }),
                )
                .add_task(
                    "error_task_2",
                    CancellableTask::create(|_| async { Err(report!(TaskError {})) }),
                );
            let result = tasks.run(CancellationToken::new()).await;
            let err = result.unwrap_err();

            let error_output = String::from_utf8(strip(format!("{:?}", err))).unwrap();
            goldie::assert!(error_output);
        })
        .await;
    }
}
