"""Fixed V0 constants. No model, provider, or runtime dependencies."""

TRUSTED_RELEASE_BINDING_COMMIT = "24b6418c0ee2dada5a08f78ff6752bb43f9d8e16"
TRUSTED_WHEEL_SHA256 = "56c9f6c930b21d600a2e8f10da7a3e92f5cfbf1c6d91490d170d1790e5555603"
TRUSTED_BUNDLE_SHA256 = "12e492ec2dce11b4227d10bdf9385705a60bc12a88fec0073ff48a87b2a57a57"
TRUSTED_IMPLEMENTATION_COMMIT = "1211861edbb512aaefae8c20b207f590fac34c35"
TRUSTED_WHEEL_FILENAME = "capy_script_devkit-0.1.0-py3-none-any.whl"

CANDIDATE_SCHEMA_V1 = "capy.application-release-candidate/v1"
CANDIDATE_SCHEMA_V0 = "capy.application-release-candidate/v0"
EXECUTION_CONTRACT = "capy.script/dev-v0"
INTERACTION_CONTRACT = "capy.application-interaction/dev-v0"
PROFILE_SCHEMA = "capy.application-acceptance-profile/v0"
ACCEPT_SCHEMA = "capy.independent-application-acceptance/v0"
REJECT_SCHEMA = "capy.independent-application-rejection/v0"
CONNECTION_MANIFEST_SCHEMA = "capy.connection-manifest/v0"
DEVKIT_BUNDLE_SCHEMA = "capy.devkit-authoring-bundle/v1"
RECEIPT_SCHEMA = "capy.development-verification-receipt/v1"
RECEIPT_PIPELINE = "capy.development-verification-pipeline/v1"

OUTER_CANDIDATE_MEMBERS = (
    "RELEASE-CANDIDATE.json",
    "application/application.zip",
    "application/interaction.json",
    "evidence/verification.json",
    "toolchain/authoring-bundle.zip",
)

EXPECTED_HANDOFF = {
    "binding": "not_performed",
    "deployment": "not_performed",
    "independent_acceptance": "required",
    "installation": "not_performed",
    "interaction_contract": "included_unaccepted",
    "publication": "not_performed",
    "publisher_signature": "not_present",
    "rollback": "not_assessed",
    "runtime_import": "not_performed",
    "runtime_version_digest": "not_assigned",
    "secret_scan": "not_performed",
    "state_migration": "not_assessed",
    "verification": "passed",
}

EXPECTED_STAGE_ORDER = (
    "toolchain_install",
    "check",
    "interaction_check",
    "test",
    "conform",
    "source_mutation_check",
    "pack_a",
    "pack_b",
    "package_compare",
    "archive_preserve",
    "interaction_preserve",
)

NULL_EXIT_STAGES = frozenset({"source_mutation_check", "package_compare", "archive_preserve"})

LIMIT_CEILINGS = {
    "max_cases": 32,
    "max_resources_per_case": 16,
    "max_fixture_bytes": 8388608,
    "max_expected_artifact_bytes": 8388608,
    "max_request_bytes": 65536,
    "timeout_seconds": 30,
    "max_stdout_bytes": 1048576,
    "max_stderr_bytes": 1048576,
    "max_total_artifact_bytes": 8388608,
}

LIMIT_KEYS = (
    "max_cases",
    "max_resources_per_case",
    "max_fixture_bytes",
    "max_expected_artifact_bytes",
    "max_request_bytes",
    "timeout_seconds",
    "max_stdout_bytes",
    "max_stderr_bytes",
    "max_total_artifact_bytes",
)

NON_GOALS = [
    "safe_execution_of_malicious_arbitrary_code",
    "connection_bearing_application_acceptance",
    "stateful_application_acceptance",
    "external_effect_acceptance",
    "runtime_compatibility_beyond_bounded_portable_contract",
    "application_installation",
    "workspace_binding",
    "publication",
    "activation",
    "deployment",
    "publisher_identity_or_signing",
    "owner_approval_transport",
    "marketplace_distribution",
    "remote_acceptance_service",
    "multi_user_authorization",
    "private_code_suitability_for_contributor",
    "model_superiority",
    "model_reliability_outside_this_task",
    "private_chain_of_thought_observability",
]

SECRET_CANARY = "CAPY_ACCEPTOR_SECRET_CANARY_V0"

# Bounded sizes for candidate validation.
OUTER_MAX_BYTES = 64 * 1024 * 1024
MANIFEST_MAX_BYTES = 1024 * 1024
RECEIPT_MAX_BYTES = 1024 * 1024
INTERACTION_MAX_BYTES = 1024 * 1024
APP_ZIP_MAX_BYTES = 32 * 1024 * 1024
APP_EXPANDED_MAX_BYTES = 64 * 1024 * 1024
APP_MAX_MEMBERS = 2048
BUNDLE_MAX_BYTES = 16 * 1024 * 1024

PROFILE_MAX_BYTES = 32 * 1024 * 1024
PROFILE_MAX_MEMBERS = 1024

ENV_SETUP_TIMEOUT = 60

WINDOWS_RESERVED = frozenset({
    "con", "prn", "aux", "nul",
    "com1", "com2", "com3", "com4", "com5", "com6", "com7", "com8", "com9",
    "lpt1", "lpt2", "lpt3", "lpt4", "lpt5", "lpt6", "lpt7", "lpt8", "lpt9",
})
