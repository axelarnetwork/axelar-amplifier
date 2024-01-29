use axelar_wasm_std::error::extend_err;
use error_stack::{Context, Result, ResultExt};
use std::future::Future;
use std::pin::Pin;
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
            "shutting down sub-tasks ({}/{})...",
            running_tasks.len(),
            total_task_count
        );

        final_result = match task_result.change_context(E::from(TaskError {})) {
            Err(err) | Ok(Err(err)) => extend_err(final_result, err),
            Ok(_) => final_result,
        };
    }

    final_result
}

pub struct TaskError {}
