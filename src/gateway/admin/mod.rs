pub mod avm;
pub mod capabilities;
pub mod credentials;
pub mod curl_util;
pub mod diagnostics;
pub mod engine;
pub mod mikrotik;
pub mod mock;
pub mod openwrt;
pub mod persistence;
pub mod plan;
pub mod provider;
pub mod registry;
pub mod ssh;
pub mod unifi;
pub mod views;

pub use avm::{
    calculate_digest_response, md5_digest, AvmAdminProvider, AvmTransport, HttpAvmTransport,
    MockAvmTransport,
};
pub use capabilities::{CapabilityClassification, RouterCapabilityMatrix};
pub use credentials::{
    dpapi_decrypt, dpapi_encrypt, load_protected_credentials, save_protected_credentials,
    zero_slice, ProtectedBuffer, ProtectedString, RouterCredentials,
};
pub use curl_util::{execute_with_operation_retry, find_curl, AutoCleanFile};
pub use diagnostics::{
    sanitize_endpoint, unix_to_iso8601, ConnectionDiagnostic, DataSource, DiagnosticResult,
    EvidenceValidationReport, NormalizedRouterInventoryItem, ProviderConnectionState,
    RouterDeviceEntry, RouterDiagnosticReport, RouterEvidenceBundle,
};
pub use engine::{
    sanitize_error, sanitize_text, MutationPreflightReport, PolicyExecutionEngine,
    PolicyExecutionRecord,
};
pub use mikrotik::{
    base64_encode, HttpsMikroTikTransport, MikroTikAdminProvider, MikroTikTransport,
    MockMikroTikTransport,
};
pub use mock::MockRouterAdminProvider;
pub use openwrt::{
    HttpOpenWrtTransport, MockOpenWrtTransport, OpenWrtAdminProvider, OpenWrtTransport,
};
pub use persistence::{
    atomic_write_file, default_policy_store_path, PersistentPolicyState, PolicyStore,
    RecoveryMechanism, RecoveryVerificationStatus, CURRENT_SCHEMA_VERSION,
};
pub use plan::{
    ActivePolicyStatus, AdminError, OperationPlan, OperationPlanRequest, OperationSemantics,
    PolicyDuration, PolicyLifecycleState, PolicyPersistence, PolicyScope, RouterIdentity,
};
pub use provider::RouterAdminProvider;
pub use registry::{ProviderDescriptor, RegistryStatus, RouterRegistry};
pub use ssh::{
    escape_posix_single_quotes, find_ssh_client, validate_ip_str, validate_mac_str,
    validate_policy_id, validate_shell_arg, MockSshExecutor, ProcessSshExecutor,
    SshCommandExecutor, SshConfig, SshOpenWrtTransport, SshOutput,
};
pub use unifi::{
    HttpUnifiTransport, MockUnifiTransport, UnifiAdminProvider, UnifiClientEntry, UnifiTransport,
};
pub use views::{
    PolicyConfirmationState, PolicyDetailView, PolicyRecoveryStatus, UnifiedPolicyEntry,
};
