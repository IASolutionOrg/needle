use needle_core::{ChangeId, LifecyclePhase};
use needle_platform_codex::{CodexLifecycleActionAdapter, CodexWorker};
use needle_runtime::{
    FreshLifecycleExploreAdapter, LifecycleExecutionError, LifecycleExecutionKernel,
    LifecycleExecutionOutcome, LifecyclePhaseAdapters, NeverCancel, RuntimeStore,
    SemanticLifecycleExploreActionResolver,
};
use std::path::PathBuf;
use thiserror::Error;

pub(super) trait LifecycleStepHost: Send + Sync {
    fn step(
        &self,
        change_id: &ChangeId,
    ) -> Result<LifecycleExecutionOutcome, LifecycleStepHostError>;
}

#[derive(Debug, Error)]
pub(super) enum LifecycleStepHostError {
    #[error("lifecycle adapter initialization failed: {0}")]
    AdapterInitialization(String),
    #[error(transparent)]
    Execution(#[from] LifecycleExecutionError),
}

pub(super) struct CodexLifecycleStepHost {
    store: RuntimeStore,
    data_directory: PathBuf,
    repository_root: PathBuf,
}

impl CodexLifecycleStepHost {
    pub(super) fn new(
        store: RuntimeStore,
        data_directory: PathBuf,
        repository_root: PathBuf,
    ) -> Self {
        Self { store, data_directory, repository_root }
    }
}

impl LifecycleStepHost for CodexLifecycleStepHost {
    fn step(
        &self,
        change_id: &ChangeId,
    ) -> Result<LifecycleExecutionOutcome, LifecycleStepHostError> {
        let explore = FreshLifecycleExploreAdapter::new(
            self.store.clone(),
            CodexWorker::new(&self.data_directory),
            &self.repository_root,
        )
        .map_err(LifecycleStepHostError::AdapterInitialization)?;
        let implement = CodexLifecycleActionAdapter::new(
            self.store.clone(),
            &self.data_directory,
            &self.repository_root,
            LifecyclePhase::Implement,
        )
        .map_err(LifecycleStepHostError::AdapterInitialization)?;
        let test = CodexLifecycleActionAdapter::new(
            self.store.clone(),
            &self.data_directory,
            &self.repository_root,
            LifecyclePhase::Test,
        )
        .map_err(LifecycleStepHostError::AdapterInitialization)?;
        let review = CodexLifecycleActionAdapter::new(
            self.store.clone(),
            &self.data_directory,
            &self.repository_root,
            LifecyclePhase::Review,
        )
        .map_err(LifecycleStepHostError::AdapterInitialization)?;
        let verify = CodexLifecycleActionAdapter::new(
            self.store.clone(),
            &self.data_directory,
            &self.repository_root,
            LifecyclePhase::Verify,
        )
        .map_err(LifecycleStepHostError::AdapterInitialization)?;
        let resolver = SemanticLifecycleExploreActionResolver::new(self.store.clone());
        let adapters = LifecyclePhaseAdapters {
            explore: &explore,
            implement: &implement,
            test: &test,
            review: &review,
            verify: &verify,
        };
        LifecycleExecutionKernel::new_with_explore_resolver(
            &self.store,
            adapters,
            &NeverCancel,
            &resolver,
        )
        .step(change_id)
        .map_err(LifecycleStepHostError::from)
    }
}

#[cfg(test)]
pub(super) struct UnavailableLifecycleStepHost;

#[cfg(test)]
impl LifecycleStepHost for UnavailableLifecycleStepHost {
    fn step(
        &self,
        _change_id: &ChangeId,
    ) -> Result<LifecycleExecutionOutcome, LifecycleStepHostError> {
        Err(LifecycleStepHostError::AdapterInitialization(
            "test lifecycle host is unavailable".to_owned(),
        ))
    }
}
