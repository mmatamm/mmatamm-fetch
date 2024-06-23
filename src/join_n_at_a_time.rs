use futures::{future::join_all, Future};

// TODO
pub async fn join_n_at_a_time<I>(iter: I) -> Vec<<I::Item as Future>::Output>
where
    I: IntoIterator,
    I::Item: Future,
{
    // TODO take(10) should DELME
    join_all(iter.into_iter().take(1)).await
}
