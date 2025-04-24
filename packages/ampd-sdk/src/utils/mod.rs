use std::time::Duration;

use futures::Future;
use tokio::time::sleep;

#[derive(Copy, Clone)]
pub enum RetryPolicy {
    RepeatConstant { sleep: Duration, max_attempts: u64 },
    NoRetry,
}

impl RetryPolicy {
    fn max_attempts(&self) -> u64 {
        match self {
            RetryPolicy::RepeatConstant { max_attempts, .. } => *max_attempts,
            RetryPolicy::NoRetry => 1,
        }
    }

    fn delay(&self) -> Option<Duration> {
        match self {
            RetryPolicy::RepeatConstant { sleep, .. } => Some(*sleep),
            RetryPolicy::NoRetry => None,
        }
    }
}

pub async fn with_retry<F, Fut, R, Err>(mut future: F, policy: RetryPolicy) -> Result<R, Err>
// move this dude to ampd-sdk from ampd
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<R, Err>>,
{
    let mut attempts = 0;

    loop {
        match future().await {
            Ok(result) => return Ok(result),
            Err(err) => {
                attempts += 1;

                if attempts >= policy.max_attempts() {
                    return Err(err);
                }

                if let Some(delay) = policy.delay() {
                    sleep(delay).await;
                }
            }
        }
    }
}
