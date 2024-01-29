use std::future::Future;
use std::pin::Pin;
use tokio_util::sync::CancellationToken;

/// The Task trait defines a container that allows easy creation, movement, storage and execution of cancellable async behaviour
pub trait Task {
    type Output;

    fn create<Fut>(task: impl FnOnce(CancellationToken) -> Fut + Send + 'static) -> Self
    where
        Fut: Future<Output = Self::Output> + Send + 'static;

    async fn execute(self, token: CancellationToken) -> Self::Output;
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

    async fn execute(self, token: CancellationToken) -> Self::Output {
        self(token).await
    }
}
