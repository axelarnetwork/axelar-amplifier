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
    /// enum InnerError {
    ///     #[error("An inner error occurred")]
    ///     Inner,
    /// }
    ///
    /// #[derive(Error, Debug)]
    /// enum OutterError {
    ///     #[error("An outter error occurred")]
    ///     Outter(#[from] InnerError),
    ///     #[error("Another outter error occurred")]
    ///     AnotherOutter
    /// }
    ///
    /// let error: Report<OutterError> = InnerError::Inner.into_report();
    ///
    /// assert!(matches!(
    ///     error.current_context(),
    ///     OutterError::Outter(InnerError::Inner)
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
