pub trait AuthModule<'a> {
    type Err;

    type InitAuthModuleParameters;
    type InitAuthModuleResult;
    type InitializeAuthSessionParameters;
    type InitializeAuthSessionResult;
    type SubmitWorkerValidationParameters;
    type SubmitWorkerValidationResult;
    type FinalizePendingSessionsParameters;
    type FinalizePendingSessionsResult;

    fn init_auth_module(
        &self,
        parameters: Self::InitAuthModuleParameters,
    ) -> Result<Self::InitAuthModuleResult, Self::Err>;

    fn initialize_auth_session(
        &self,
        parameters: Self::InitializeAuthSessionParameters,
    ) -> Result<Self::InitializeAuthSessionResult, Self::Err>;

    fn submit_worker_validation(
        &self,
        parameters: Self::SubmitWorkerValidationParameters,
    ) -> Result<Self::SubmitWorkerValidationResult, Self::Err>;

    fn finalize_open_sessions(
        &self,
        parameters: Self::FinalizePendingSessionsParameters,
    ) -> Result<Self::FinalizePendingSessionsResult, Self::Err>;
}
