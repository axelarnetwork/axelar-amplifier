use std::time::Duration;

use futures::Future;
use tokio::time;

pub async fn with_retry<F, Fut, R, Err>(mut future: F, policy: RetryPolicy) -> Result<R, Err>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<R, Err>>,
{
    let mut attempt_count = 0u64;
    loop {
        match future().await {
            Ok(result) => return Ok(result),
            Err(err) => {
                attempt_count = attempt_count.saturating_add(1);

                match enact_policy(attempt_count, policy).await {
                    PolicyAction::Retry => continue,
                    PolicyAction::Abort => return Err(err),
                }
            }
        }
    }
}

async fn enact_policy(attempt_count: u64, policy: RetryPolicy) -> PolicyAction {
    match policy {
        RetryPolicy::RepeatConstant {
            sleep,
            max_attempts,
        } => {
            if attempt_count >= max_attempts {
                PolicyAction::Abort
            } else {
                time::sleep(sleep).await;
                PolicyAction::Retry
            }
        }
    }
}

enum PolicyAction {
    Retry,
    Abort,
}

#[derive(Copy, Clone, Debug)]
pub enum RetryPolicy {
    RepeatConstant { sleep: Duration, max_attempts: u64 },
}

impl RetryPolicy {
    pub fn repeat_constant(sleep: Duration, max_attempts: u64) -> Self {
        Self::RepeatConstant {
            sleep,
            max_attempts,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::future;
    use std::sync::Mutex;

    use tokio::time::Instant;

    use super::*;

    #[tokio::test(start_paused = true)]
    async fn should_return_ok_when_the_internal_future_returns_ok_immediately() {
        let max_attempts = 3;
        let fut = with_retry(
            || future::ready(Ok::<(), ()>(())),
            RetryPolicy::repeat_constant(Duration::from_secs(1), max_attempts),
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
            RetryPolicy::repeat_constant(Duration::from_secs(1), max_attempts),
        );
        let start = Instant::now();

        assert!(fut.await.is_ok());
        assert!(start.elapsed() >= Duration::from_secs(3));
        assert!(start.elapsed() < Duration::from_secs(4));
    }

    #[tokio::test(start_paused = true)]
    async fn should_return_error_when_the_internal_future_returns_error_after_max_attempts() {
        let max_attempts = 3;
        let fut = with_retry(
            || future::ready(Err::<(), ()>(())),
            RetryPolicy::repeat_constant(Duration::from_secs(1), max_attempts),
        );
        let start = Instant::now();

        assert!(fut.await.is_err());
        assert!(start.elapsed() >= Duration::from_secs(2));
    }
}
