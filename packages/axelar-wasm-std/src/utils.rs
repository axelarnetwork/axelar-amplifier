pub fn try_map<T, B, F, E>(vec: Vec<T>, f: F) -> Result<Vec<B>, E>
where
    F: FnMut(T) -> Result<B, E>,
{
    vec.into_iter().map(f).collect::<Result<Vec<B>, E>>()
}
