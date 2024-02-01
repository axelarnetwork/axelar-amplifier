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
    use std::time::SystemTime;

    use super::*;

    #[tokio::test]
    async fn try_something() {
        let a = with_retry(
            || async {
                sleep(Duration::from_secs(2)).await;

                if SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap()
                    .as_millis()
                    % 3
                    == 0
                {
                    Ok::<i32, ()>(5)
                } else {
                    Err(())
                }
            },
            RetryPolicy::RepeatConstant(Duration::from_secs(1), 10),
        )
        .await
        .unwrap();

        println!("a {:?}", a);
    }
}
