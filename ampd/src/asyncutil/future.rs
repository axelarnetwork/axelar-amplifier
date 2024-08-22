use std::time::Duration;

use futures::Future;
use tokio::time;

pub async fn with_retry<F, Fut, R, Err>(mut future: F, policy: RetryPolicy) -> Result<R, Err>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<R, Err>>,
{
    let mut err_count = 0u64;
    loop {
        match future().await {
            Ok(result) => return Ok(result),
            Err(err) => {
                err_count = err_count.saturating_add(1);
                handle_err(err, err_count, policy).await?
            }
        }
    }
}

async fn handle_err<Err>(err: Err, err_count: u64, policy: RetryPolicy) -> Result<(), Err> {
    match policy {
        RetryPolicy::RepeatConstant {
            sleep,
            max_attempts,
        } => {
            if err_count >= max_attempts {
                return Err(err);
            }

            time::sleep(sleep).await;

            Ok(())
        }
    }
}

#[derive(Copy, Clone)]
pub enum RetryPolicy {
    RepeatConstant { sleep: Duration, max_attempts: u64 },
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
