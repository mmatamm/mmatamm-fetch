use futures::{future::join_all, Future};
use kanal::ReceiveError;

/// Executes a given function concurrently on items from an iterator, on a pull of workers.
///
/// # Arguments
///
/// * `operation` - The function to be applied to each item.
/// * `input_iter` - The iterator providing the input items.
/// * `workers` - The maximum number of concurrent operations.
pub async fn concurrent_for_each<T, F, Fut, I>(
    operation: F,
    input_iter: I,
    workers: u8,
) -> anyhow::Result<()>
where
    F: Fn(T) -> Fut,
    Fut: Future,
    I: IntoIterator,
    I::Item: Into<T>,
    I::IntoIter: ExactSizeIterator,
{
    // Convert the input iterator into a concrete iterator
    let concrete_iter = input_iter.into_iter();

    // Create a bounded channel for work distribution
    let (work_sender, work_receiver) = kanal::bounded_async(concrete_iter.len());

    // Send all work items to the channel
    for item in concrete_iter {
        work_sender.send(item).await?;
    }

    // Create and execute worker tasks
    let worker_tasks = (0..workers).map(async |_| -> Result<(), ReceiveError> {
        while !work_receiver.is_empty() {
            operation(work_receiver.recv().await?.into()).await;
        }

        Ok(())
    });

    // Wait for all worker tasks to complete
    join_all(worker_tasks).await;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use tokio::time::{sleep, Duration};

    // Helper function to create a test operation
    async fn test_operation(_: i32) {
        sleep(Duration::from_millis(10)).await;
    }

    #[tokio::test]
    async fn test_concurrent_for_each_basic() -> anyhow::Result<()> {
        let input = vec![1, 2, 3, 4, 5];
        let processed = Arc::new(Mutex::new(Vec::new()));

        let operation = |item: i32| {
            let processed = Arc::clone(&processed);
            async move {
                test_operation(item).await;
                processed.lock().unwrap().push(item);
            }
        };

        concurrent_for_each(operation, input.clone(), 3).await?;

        let result = processed.lock().unwrap();
        assert_eq!(result.len(), input.len());
        assert!(result.iter().all(|&item| input.contains(&item)));

        Ok(())
    }

    #[tokio::test]
    async fn test_concurrent_for_each_empty_input() -> anyhow::Result<()> {
        let input: Vec<i32> = vec![];
        let processed = Arc::new(Mutex::new(Vec::new()));

        let operation = |item: i32| {
            let processed = Arc::clone(&processed);
            async move {
                test_operation(item).await;
                processed.lock().unwrap().push(item);
            }
        };

        concurrent_for_each(operation, input, 3).await?;

        let result = processed.lock().unwrap();
        assert_eq!(result.len(), 0);

        Ok(())
    }

    #[tokio::test]
    async fn test_concurrent_for_each_single_concurrency() -> anyhow::Result<()> {
        let input = vec![1, 2, 3, 4, 5];
        let processed = Arc::new(Mutex::new(Vec::new()));

        let operation = |item: i32| {
            let processed = Arc::clone(&processed);
            async move {
                test_operation(item).await;
                processed.lock().unwrap().push(item);
            }
        };

        concurrent_for_each(operation, input.clone(), 1).await?;

        let result = processed.lock().unwrap();
        assert_eq!(result.len(), input.len());
        assert_eq!(*result, input); // Should be processed in order

        Ok(())
    }
}
