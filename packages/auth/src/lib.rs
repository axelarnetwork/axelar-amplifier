pub trait AuthModule<PA, RA, PB, RB, PC, RC> {
    fn initialize_auth_session(&self, parameters: PA) -> RA;

    fn submit_worker_validation(&self, parameters: PB) -> RB;

    fn finalize_pending_sessions(&self, parameters: PC) -> RC;
}
