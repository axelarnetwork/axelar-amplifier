use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use futures::{Future, FutureExt};
use tokio::time;

pub fn with_retry<F, Fut, R, Err>(
    future: F,
    policy: RetryPolicy,
) -> impl Future<Output = Result<R, Err>>
where
    F: Fn() -> Fut,
    Fut: Future<Output = Result<R, Err>>,
{
    RetriableFuture::new(future, policy)
}

pub enum RetryPolicy {
    RepeatConstant { sleep: Duration, max_attempts: u64 },
}

struct RetriableFuture<F, Fut, R, Err>
where
    F: Fn() -> Fut,
    Fut: Future<Output = Result<R, Err>>,
{
    future: F,
    inner: Pin<Box<Fut>>,
    policy: RetryPolicy,
    err_count: u64,
}

impl<F, Fut, R, Err> Unpin for RetriableFuture<F, Fut, R, Err>
where
    F: Fn() -> Fut,
    Fut: Future<Output = Result<R, Err>>,
{
}

impl<F, Fut, R, Err> RetriableFuture<F, Fut, R, Err>
where
    F: Fn() -> Fut,
    Fut: Future<Output = Result<R, Err>>,
{
    fn new(get_future: F, policy: RetryPolicy) -> Self {
        let future = get_future();

        Self {
            future: get_future,
            inner: Box::pin(future),
            policy,
            err_count: 0,
        }
    }

    fn handle_err(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        error: Err,
    ) -> Poll<Result<R, Err>> {
        self.err_count = self.err_count.saturating_add(1);

        match self.policy {
            RetryPolicy::RepeatConstant {
                sleep,
                max_attempts,
            } => {
                if self.err_count >= max_attempts {
                    return Poll::Ready(Err(error));
                }

                self.inner = Box::pin((self.future)());

                let waker = cx.waker().clone();
                tokio::spawn(time::sleep(sleep).then(|_| async {
                    waker.wake();
                }));

                Poll::Pending
            }
        }
    }
}

impl<F, Fut, R, Err> Future for RetriableFuture<F, Fut, R, Err>
where
    F: Fn() -> Fut,
    Fut: Future<Output = Result<R, Err>>,
{
    type Output = Result<R, Err>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.inner.as_mut().poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(result)) => Poll::Ready(Ok(result)),
            Poll::Ready(Err(error)) => self.handle_err(cx, error),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::future;
    use std::sync::Mutex;

    use tokio::time::Instant;

    use super::*;

    #[tokio::test]
    async fn should_return_ok_when_the_internal_future_returns_ok_immediately() {
        let fut = with_retry(
            || future::ready(Ok::<(), ()>(())),
            RetryPolicy::RepeatConstant {
                sleep: Duration::from_secs(1),
                max_attempts: 3,
            },
        );
        let start = Instant::now();

        assert!(fut.await.is_ok());
        assert!(start.elapsed() < Duration::from_secs(1));
    }

    #[tokio::test(start_paused = true)]
    async fn should_return_ok_when_the_internal_future_returns_ok_eventually() {
        let max_attempts = 3;
        let count = Mutex::new(0);
        let fut = with_retry(
            || async {
                *count.lock().unwrap() += 1;
                time::sleep(Duration::from_secs(1)).await;

                if *count.lock().unwrap() < max_attempts - 1 {
                    Err::<(), ()>(())
                } else {
                    Ok::<(), ()>(())
                }
            },
            RetryPolicy::RepeatConstant {
                sleep: Duration::from_secs(1),
                max_attempts,
            },
        );
        let start = Instant::now();

        assert!(fut.await.is_ok());
        assert!(start.elapsed() >= Duration::from_secs(3));
        assert!(start.elapsed() < Duration::from_secs(4));
    }

    #[tokio::test(start_paused = true)]
    async fn should_return_error_when_the_internal_future_returns_error_after_max_attempts() {
        let fut = with_retry(
            || future::ready(Err::<(), ()>(())),
            RetryPolicy::RepeatConstant {
                sleep: Duration::from_secs(1),
                max_attempts: 3,
            },
        );
        let start = Instant::now();

        assert!(fut.await.is_err());
        assert!(start.elapsed() >= Duration::from_secs(2));
    }
}
