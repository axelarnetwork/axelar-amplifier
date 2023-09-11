pub fn try_map<T, B, F, E>(vec: Vec<T>, f: F) -> Result<Vec<B>, E>
where
    F: FnMut(T) -> Result<B, E>,
{
    vec.into_iter().map(f).collect::<Result<Vec<B>, E>>()
}

pub trait InspectorResult<T, E> {
    /// This function should be called `inspect`, but would have a name collision with the unstable [core::result::Result::inspect](https://doc.rust-lang.org/core/result/enum.Result.html#method.inspect) function.
    fn tap<F>(self, f: F) -> Self
    where
        F: FnOnce(&T);

    /// This function should be called `inspect_err`, but would have a name collision with the unstable [core::result::Result::inspect_err](https://doc.rust-lang.org/core/result/enum.Result.html#method.inspect_err) function.
    fn tap_err<F>(self, f: F) -> Self
    where
        F: FnOnce(&E);
}

impl<T, E> InspectorResult<T, E> for Result<T, E> {
    /// Use this to create a side effect without consuming the result.
    ///
    /// Example:
    /// ```
    ///# fn main() -> Result<i32, String> {
    /// use axelar_wasm_std::utils::InspectorResult;
    ///
    /// let result = Ok(1);
    /// result.tap(|x| println!("result is {}", x)).map(|x| x + 1)
    ///# }
    /// ```
    fn tap<F>(self, f: F) -> Self
    where
        F: FnOnce(&T),
    {
        self.map(|t| {
            f(&t);
            t
        })
    }

    /// Use this to create a side effect without consuming the error.
    ///
    /// Example:
    /// ```
    ///# fn main() -> Result<i32, String> {
    /// use axelar_wasm_std::utils::InspectorResult;
    ///
    /// let result = Err("wrong value");
    /// result.tap_err(|x| println!("result is {}", x)).map_err(|x| x + 1)
    ///# }
    /// ```
    fn tap_err<F>(self, f: F) -> Self
    where
        F: FnOnce(&E),
    {
        self.map_err(|e| {
            f(&e);
            e
        })
    }
}
