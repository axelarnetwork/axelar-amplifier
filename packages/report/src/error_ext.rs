use error_stack::{Context, Report};

pub trait ErrorExt<Err>
where
    Self: Into<Err>,
    Err: Context,
{
    /// Converts self into a `Report<Err>` instance.
    ///
    /// This method takes ownership of `self` and converts it into the error type `Err`
    /// (using the `Into<Err>` trait bound), then wraps it in a new `Report`.
    ///
    /// # Examples
    ///
    /// ```
    /// use thiserror::Error;
    /// use error_stack::Report;
    ///
    /// use report::ErrorExt;
    ///
    /// #[derive(Error, Debug)]
    /// enum OriginalError {
    ///     #[error("An original error occurred")]
    ///     Original,
    /// }
    ///
    /// #[derive(Error, Debug)]
    /// enum ConvertedError {
    ///     #[error("an converted error occurred")]
    ///     Converted(#[from] OriginalError),
    ///     #[error("another converted error occurred")]
    ///     AnotherConverted
    /// }
    ///
    /// let error: Report<ConvertedError> = OriginalError::Original.into_report();
    ///
    /// assert!(matches!(
    ///     error.current_context(),
    ///     ConvertedError::Converted(OriginalError::Original)
    /// ));
    /// ```
    fn into_report(self) -> Report<Err> {
        Report::new(self.into())
    }
}

impl<T, Err> ErrorExt<Err> for T
where
    T: Into<Err>,
    Err: Context,
{
}
