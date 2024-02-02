use futures::{Future, FutureExt};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::time::sleep;

pub fn with_retry<F, Fut, R, Err>(
    get_future: F,
    policy: RetryPolicy,
) -> impl Future<Output = Result<R, Err>>
where
    F: Fn() -> Fut,
    Fut: Future<Output = Result<R, Err>>,
{
    FutureRetry::new(get_future, policy)
}

pub enum RetryPolicy {
    RepeatConstant(Duration, u64),
}

struct FutureRetry<F, Fut, R, Err>
where
    F: Fn() -> Fut,
    Fut: Future<Output = Result<R, Err>>,
{
    get_future: F,
    future: Pin<Box<Fut>>,
    policy: RetryPolicy,
    err_count: u64,
}

impl<F, Fut, R, Err> Unpin for FutureRetry<F, Fut, R, Err>
where
    F: Fn() -> Fut,
    Fut: Future<Output = Result<R, Err>>,
{
}

impl<F, Fut, R, Err> FutureRetry<F, Fut, R, Err>
where
    F: Fn() -> Fut,
    Fut: Future<Output = Result<R, Err>>,
{
    fn new(get_future: F, policy: RetryPolicy) -> Self {
        let future = get_future();

        Self {
            get_future,
            future: Box::pin(future),
            policy,
            err_count: 0,
        }
    }

    fn handle_err(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        error: Err,
    ) -> Poll<Result<R, Err>> {
        self.err_count += 1;

        match self.policy {
            RetryPolicy::RepeatConstant(timeout, max_attempts) => {
                if self.err_count >= max_attempts {
                    return Poll::Ready(Err(error));
                }

                self.future = Box::pin((self.get_future)());

                let waker = cx.waker().clone();
                tokio::spawn(sleep(timeout).then(|_| async {
                    waker.wake();
                }));

                Poll::Pending
            }
        }
    }
}

impl<F, Fut, R, Err> Future for FutureRetry<F, Fut, R, Err>
where
    F: Fn() -> Fut,
    Fut: Future<Output = Result<R, Err>>,
{
    type Output = Result<R, Err>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.future.as_mut().poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(result)) => Poll::Ready(Ok(result)),
            Poll::Ready(Err(error)) => self.handle_err(cx, error),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{sync::Mutex, time::Instant};

    use super::*;

    #[tokio::test]
    async fn should_return_ok_when_the_inter_future_returns_ok_immediately() {
        let fut = with_retry(
            || async { Ok::<(), ()>(()) },
            RetryPolicy::RepeatConstant(Duration::from_secs(1), 3),
        );
        let start = Instant::now();

        assert!(fut.await.is_ok());
        assert!(start.elapsed().as_secs() < 1);
    }

    #[tokio::test]
    async fn should_return_ok_when_the_inter_future_returns_ok_eventually() {
        let max_attempts = 3;
        let count = Mutex::new(0);
        let fut = with_retry(
            || async {
                *count.lock().unwrap() += 1;
                sleep(Duration::from_secs(1)).await;

                if *count.lock().unwrap() < max_attempts - 1 {
                    Err::<(), ()>(())
                } else {
                    Ok::<(), ()>(())
                }
            },
            RetryPolicy::RepeatConstant(Duration::from_secs(1), max_attempts),
        );
        let start = Instant::now();

        assert!(fut.await.is_ok());
        assert!(start.elapsed().as_secs() >= 3);
        assert!(start.elapsed().as_secs() < 4);
    }

    #[tokio::test]
    async fn should_return_error_when_the_inter_future_returns_error_after_max_attempts() {
        let fut = with_retry(
            || async { Err::<(), ()>(()) },
            RetryPolicy::RepeatConstant(Duration::from_secs(1), 3),
        );
        let start = Instant::now();

        assert!(fut.await.is_err());
        assert!(start.elapsed().as_secs() >= 2);
    }

    #[tokio::test]
    async fn should_return_ok_when_the_inter_future_returns_ok_within_max_attempts() {
        let max_attempts = 3;
        let count = Mutex::new(0);
        let fut = with_retry(
            || async {
                *count.lock().unwrap() += 1;

                if *count.lock().unwrap() < max_attempts {
                    Err::<(), ()>(())
                } else {
                    Ok::<(), ()>(())
                }
            },
            RetryPolicy::RepeatConstant(Duration::from_secs(1), max_attempts),
        );
        let start = Instant::now();

        assert!(fut.await.is_ok());
        assert!(start.elapsed().as_secs() >= 2);
        assert!(start.elapsed().as_secs() < 3);
    }
}
