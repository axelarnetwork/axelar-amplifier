pub use error_stack::ResultExt as _;
use error_stack::{Context, Report};
use eyre::Report as EyreReport;

use crate::ErrorExt;

pub trait ResultExt<E>: error_stack::ResultExt
where
    E: Context,
{
    type T;
    type Err: Into<E>;
    fn into_report(self) -> Result<Self::T, Report<E>>;
}

impl<T, E1, E2> ResultExt<E2> for Result<T, E1>
where
    E1: Context + Into<E2>,
    E2: Context,
{
    type T = T;
    type Err = E1;

    fn into_report(self) -> Result<Self::T, Report<E2>> {
        self.map_err(|err| err.into_report())
    }
}

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
        error_stack::IntoReportCompat::into_report(self)
            .map_err(|report| report.change_context(context))
    }
}
