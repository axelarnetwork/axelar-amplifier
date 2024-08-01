use error_stack::{Context, IntoReportCompat, Report};
use eyre::Report as EyreReport;

pub trait ResultCompatExt {
    type Ok;

    fn change_context<C>(self, context: C) -> Result<Self::Ok, Report<C>>
    where
        C: Context;
}

impl<T> ResultCompatExt for Result<T, EyreReport> {
    type Ok = T;

    fn change_context<C>(self, context: C) -> Result<T, Report<C>>
    where
        C: Context,
    {
        self.into_report()
            .map_err(|report| report.change_context(context))
    }
}
