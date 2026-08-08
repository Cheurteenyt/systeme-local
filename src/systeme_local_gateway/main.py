from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from secrets import token_hex
from typing import TYPE_CHECKING, cast

import anyio
from fastapi import FastAPI, HTTPException, Request, Response

from .approvals import ApprovalStore
from .audit_runtime import create_configured_audit_log
from .auth import ReplayGuardUnavailableError, SQLiteReplayGuard, verify_task
from .config import settings
from .executor import CapabilityExecutor
from .models import TaskEnvelope, TaskResult
from .policy import PolicyEngine
from .task_processor import (
    PolicyEngineProtocol,
    TaskAuthenticationError,
    TaskProcessor,
    TaskServiceUnavailableError,
    TaskVerifierProtocol,
)

if TYPE_CHECKING:
    from .mcp_tools import McpToolRegistry

logger = logging.getLogger(__name__)
policy = PolicyEngine(settings.policy_file)

c0_probe = None
c9_coordinator = None
c9_control_router = None
c9_handler = None
c9_renderer = None
mcp_registry: McpToolRegistry | None = None
if settings.mcp_enabled:
    from .mcp_tools import McpToolRegistry

    if settings.provider_runtime_mode == "chatgpt_chat_c4":
        from .c4_admission import (
            RuntimeAdmissionAction,
            build_admitted_mcp_registry,
            build_current_c4_adapter_registry,
            commit_runtime_admission_request,
            create_committed_runtime_admission_controller,
        )

        if settings.provider_runtime_root is None:
            raise RuntimeError("C4 provider runtime root is missing")
        evaluated_at = datetime.now(UTC)
        reviewed_registry = build_current_c4_adapter_registry()
        adapter = reviewed_registry.adapters[0]
        request = commit_runtime_admission_request(
            identity=adapter.identity,
            action=RuntimeAdmissionAction.TOOL_SURFACE_EXPOSURE,
            requested_tools=adapter.approved_tools,
            evaluated_at=evaluated_at,
            request_correlation="c4_" + token_hex(16),
        )
        controller = create_committed_runtime_admission_controller(
            root=settings.provider_runtime_root,
            c3_registry_path=(
                settings.provider_runtime_root / "governance" / "c3-capability-registry.json"
            ),
            c4_registry_path=(
                settings.provider_runtime_root / "governance" / "c4-runtime-adapters.json"
            ),
            evaluated_at=evaluated_at,
        )
        decision = controller.decide(request)
        if not decision.allowed:
            raise RuntimeError(
                f"C4 provider runtime admission denied: {decision.reason_code.value}"
            )
        mcp_registry = build_admitted_mcp_registry(
            policy=policy,
            decision=decision,
            controller=controller,
            c0_mode=settings.c0_enabled,
        )
    elif settings.provider_runtime_mode == "chatgpt_work_c8":
        from .c8_live_cycle import load_live_cycle_bundle, verify_live_cycle_bundle

        if settings.provider_runtime_root is None:
            raise RuntimeError("C8 provider runtime root is missing")
        if settings.c8_live_cycle_file is None:
            raise RuntimeError("C8 live-cycle evidence file is missing")
        c8_decision = verify_live_cycle_bundle(
            bundle=load_live_cycle_bundle(settings.c8_live_cycle_file),
            root=settings.provider_runtime_root,
            audit_key=settings.audit_key,
            evaluated_at=datetime.now(UTC),
        )
        if not c8_decision.live_actions_allowed or c8_decision.effective_tool_count != 1:
            raise RuntimeError("C8 provider runtime admission denied")
        mcp_registry = McpToolRegistry(policy, c0_mode=settings.c0_enabled)
    elif settings.provider_runtime_mode == "chatgpt_web_c9":
        from .c9_attachment_security import C9AttachmentSecurity
        from .c9_control import C9LocalControlGuard
        from .c9_control_api import C9LocalControlPlane, build_c9_control_router
        from .c9_git import c9_git_text
        from .c9_handoff_runtime import (
            C9DynamicMcpRegistry,
            C9HandoffCapabilityHandler,
            C9HandoffCoordinator,
            C9HandoffRenderer,
        )
        from .c9_local_ai import (
            C9LocalAICapabilities,
            C9LocalAIConfig,
            C9LocalAIRuntimeObservation,
            c9_local_ai_runtime_observation_sha256,
        )
        from .c9_manual_export import C9ManualExportManager
        from .c9_mcp_tool import (
            C9_ATTACHMENT_HANDOFF_TOOL_NAME,
            c9_attachment_handoff_tool,
        )
        from .c9_private_state import C9PrivateStateError, C9PrivateStateGuard
        from .c9_work_bridge import (
            C9CapabilityEvidence,
            C9McpHostCapabilities,
            C9RichSurface,
            commit_mcp_host_capabilities,
        )

        if settings.provider_runtime_root is None:
            raise RuntimeError("C9 provider runtime root is missing")
        if settings.c9_state_directory is None:
            raise RuntimeError("C9 state directory is missing")
        if settings.c9_admission_file is None:
            raise RuntimeError("C9 admission file is missing")
        if settings.c9_control_token is None:
            raise RuntimeError("C9 control token is missing")
        if settings.c9_server_build_commit is None:
            raise RuntimeError("C9 server build commit is missing")
        if settings.c9_local_ai_endpoint is None or settings.c9_local_ai_model is None:
            raise RuntimeError("C9 local-AI configuration is missing")
        if settings.c9_local_ai_runtime_observation_file is None:
            raise RuntimeError("C9 local-AI runtime observation file is missing")

        current_commit = c9_git_text(
            settings.provider_runtime_root,
            "rev-parse",
            "HEAD",
        )
        if current_commit != settings.c9_server_build_commit:
            raise RuntimeError("C9 configured build commit does not match repository HEAD")

        c9_private_state = C9PrivateStateGuard.initialize_layout(
            provider_runtime_root=settings.provider_runtime_root,
            state_directory=settings.c9_state_directory,
            admission_file=settings.c9_admission_file,
        )
        try:
            c9_local_ai_runtime_observation = C9LocalAIRuntimeObservation.model_validate_json(
                c9_private_state.read_regular(
                    settings.c9_local_ai_runtime_observation_file,
                    max_bytes=64 * 1024,
                )
            )
        except (C9PrivateStateError, ValueError) as error:
            raise RuntimeError("C9 local-AI runtime observation is invalid") from error
        c9_local_ai_runtime_observation_sha = c9_local_ai_runtime_observation_sha256(
            c9_local_ai_runtime_observation
        )
        c9_private_state.unlink_regular(
            settings.c9_admission_file,
            missing_ok=True,
        )
        c9_manual_export_root = c9_private_state.ensure_directory(
            settings.c9_state_directory / "manual-exports"
        )
        c9_fixture_root = c9_private_state.ensure_directory(
            settings.c9_state_directory / "synthetic-fixtures"
        )
        try:
            static_c9_registry = McpToolRegistry(
                policy,
                additional_tools=(c9_attachment_handoff_tool(),),
                effective_tool_names=frozenset({C9_ATTACHMENT_HANDOFF_TOOL_NAME}),
            )
        except RuntimeError as error:
            raise RuntimeError(
                "C9 policy must admit exactly the attachment handoff tool"
            ) from error
        if tuple(tool.name for tool in static_c9_registry.list_tools()) != (
            C9_ATTACHMENT_HANDOFF_TOOL_NAME,
        ):
            raise RuntimeError("C9 policy must admit exactly the attachment handoff tool")

        now = datetime.now(UTC)
        initial_evidence = C9CapabilityEvidence.DOCUMENTED_AND_LOCAL_SERVER_VALIDATED
        c9_capabilities: dict[C9RichSurface | str, C9McpHostCapabilities] = {
            C9RichSurface.WORK: commit_mcp_host_capabilities(
                surface=C9RichSurface.WORK,
                call_tool_result_content=initial_evidence,
                image_content=initial_evidence,
                embedded_text_resource=initial_evidence,
                window_openai_upload_file_available=False,
                window_openai_image_ids_available=False,
                observed_at=now,
                expires_at=now + timedelta(minutes=10),
            )
        }
        c9_coordinator = C9HandoffCoordinator(
            security=C9AttachmentSecurity(),
            local_ai_config=C9LocalAIConfig(
                endpoint=settings.c9_local_ai_endpoint,
                visible_model_label=settings.c9_local_ai_model,
                runtime_observation_sha256=(c9_local_ai_runtime_observation_sha),
                capabilities=C9LocalAICapabilities(
                    image_input=True,
                    utf8_document_input=True,
                    structured_json_output=True,
                ),
            ),
            local_ai_runtime_observation=c9_local_ai_runtime_observation,
            manual_manager=C9ManualExportManager(
                c9_manual_export_root,
                started_at=now,
            ),
            mcp_capabilities=c9_capabilities,
            repository_root=settings.provider_runtime_root,
            admission_file=settings.c9_admission_file,
            audit_key=settings.audit_key,
            private_state_guard=c9_private_state,
        )
        mcp_registry = cast(McpToolRegistry, C9DynamicMcpRegistry(c9_coordinator))
        c9_handler = C9HandoffCapabilityHandler(c9_coordinator)
        c9_renderer = C9HandoffRenderer(c9_coordinator)
        c9_control = C9LocalControlPlane(
            coordinator=c9_coordinator,
            fixture_root=c9_fixture_root,
            private_state_guard=c9_private_state,
            audit_key=settings.audit_key,
        )
        c9_control_router = build_c9_control_router(
            guard=C9LocalControlGuard(token=settings.c9_control_token),
            control=c9_control,
        )
    else:
        mcp_registry = McpToolRegistry(policy, c0_mode=settings.c0_enabled)
    if settings.c0_enabled:
        from .c0_probe import (
            C0_TOOL_NAME,
            C0ConnectivityProbe,
            C0ProbeContext,
        )

        if settings.c0_server_build_commit is None:
            raise RuntimeError("C0 is enabled without a server build commit")
        tool_names = tuple(tool.name for tool in mcp_registry.list_tools())
        if tool_names != (C0_TOOL_NAME,):
            raise RuntimeError("C0 policy must expose exactly systeme_local_connectivity_probe")
        c0_probe = C0ConnectivityProbe(
            C0ProbeContext(
                server_build_commit=settings.c0_server_build_commit,
                local_policy_sha256=policy.policy_sha256,
                tool_snapshot_sha256=mcp_registry.tool_snapshot_sha256,
            )
        )

executor = CapabilityExecutor(
    settings.workspace,
    settings.docker_image,
    policy.limits,
    sandbox_root=settings.sandbox_root,
    c0_probe=c0_probe,
    capability_handlers=(
        {"systeme_local_attachment_handoff": c9_handler} if c9_handler is not None else None
    ),
)
audit_log = create_configured_audit_log(settings)
audit_log.verify()
replay_guard = SQLiteReplayGuard(
    settings.replay_db,
    settings.shared_secret,
    max_entries=settings.replay_max_entries,
)
approval_store = ApprovalStore(
    settings.approval_db,
    settings.audit_key,
    max_entries=settings.approval_max_entries,
    ttl_seconds=settings.approval_ttl_seconds,
)
task_processor = TaskProcessor(
    shared_secret=settings.shared_secret,
    replay_guard=replay_guard,
    policy=cast(PolicyEngineProtocol, policy),
    executor=executor,
    audit_log=audit_log,
    approval_store=approval_store,
    task_verifier=cast(TaskVerifierProtocol, verify_task),
    replay_unavailable_error=ReplayGuardUnavailableError,
)

mcp_runtime = None
if settings.mcp_enabled:
    if settings.mcp_token is None:
        raise RuntimeError("MCP is enabled without a configured token")
    if mcp_registry is None:
        raise RuntimeError("MCP is enabled without an admitted registry")

    from .mcp_runtime import McpRuntime, McpToolRegistryProtocol

    mcp_runtime = McpRuntime(
        token=settings.mcp_token,
        shared_secret=settings.shared_secret,
        registry=cast(McpToolRegistryProtocol, mcp_registry),
        task_processor=task_processor,
        max_request_bytes=settings.mcp_max_request_bytes,
        requests_per_minute=settings.mcp_requests_per_minute,
        max_concurrency=settings.mcp_max_concurrency,
        result_renderer=c9_renderer,
        render_audit_log=audit_log if c9_renderer is not None else None,
        max_rendered_response_bytes=settings.mcp_max_rendered_response_bytes,
    )


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    try:
        if mcp_runtime is None:
            yield
        else:
            async with mcp_runtime.run():
                yield
    finally:
        if c9_coordinator is not None:
            try:
                await anyio.to_thread.run_sync(c9_coordinator.close)
            except Exception as error:
                logger.error(
                    "C9 coordinator shutdown failed with %s",
                    type(error).__name__,
                )


app = FastAPI(
    title="Système Local Agent Gateway",
    version="0.1.0",
    lifespan=lifespan,
)
if c9_control_router is not None:
    app.include_router(c9_control_router)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/v1/tasks", response_model=TaskResult)
def submit_task(task: TaskEnvelope) -> TaskResult:
    try:
        return task_processor.process(task)
    except TaskAuthenticationError as exc:
        raise HTTPException(status_code=401, detail=exc.detail) from exc
    except TaskServiceUnavailableError as exc:
        raise HTTPException(status_code=503, detail=exc.detail) from exc


if mcp_runtime is not None:
    admitted_mcp_runtime = mcp_runtime

    @app.api_route(
        "/mcp",
        methods=["GET", "POST", "DELETE"],
        include_in_schema=False,
    )
    async def mcp_endpoint(request: Request) -> Response:
        return await admitted_mcp_runtime.handle_http_request(request)
