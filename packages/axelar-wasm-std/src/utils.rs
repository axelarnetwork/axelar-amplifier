pub fn try_map<T, B, F, E>(vec: Vec<T>, f: F) -> Result<Vec<B>, E>
where
    F: FnMut(T) -> Result<B, E>,
{
    vec.into_iter().map(f).collect::<Result<Vec<B>, E>>()
}

pub trait InspectorResult<T, E> {
    /// This function has a trailing underscore to avoid name collision with the unstable [core::result::Result::inspect](https://doc.rust-lang.org/core/result/enum.Result.html#method.inspect) function.
    fn inspect_<F>(self, f: F) -> Self
    where
        F: FnOnce(&T);

    /// This function has a trailing underscore to avoid name collision with the unstable [core::result::Result::inspect_err](https://doc.rust-lang.org/core/result/enum.Result.html#method.inspect_err) function.
    fn inspect_err_<F>(self, f: F) -> Self
    where
        F: FnOnce(&E);
}

impl<T, E> InspectorResult<T, E> for Result<T, E> {
    fn inspect_<F>(self, f: F) -> Self
    where
        F: FnOnce(&T),
    {
        self.map(|t| {
            f(&t);
            t
        })
    }

    fn inspect_err_<F>(self, f: F) -> Self
    where
        F: FnOnce(&E),
    {
        self.map_err(|e| {
            f(&e);
            e
        })
    }
}
