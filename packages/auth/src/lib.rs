pub trait AuthModule<'a> {
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
    ) -> Self::InitAuthModuleResult;

    fn initialize_auth_session(
        &self,
        parameters: Self::InitializeAuthSessionParameters,
    ) -> Self::InitializeAuthSessionResult;

    fn submit_worker_validation(
        &self,
        parameters: Self::SubmitWorkerValidationParameters,
    ) -> Self::SubmitWorkerValidationResult;

    fn finalize_pending_sessions(
        &self,
        parameters: Self::FinalizePendingSessionsParameters,
    ) -> Self::FinalizePendingSessionsResult;
}
