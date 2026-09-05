"""Private application-independent Capy workbench UI."""

from .assets import STANDARD_SCRIPT, STANDARD_SCRIPT_SHA256, WORKBENCH_CSS
from .models import (
    UIAction,
    UIActivity,
    UIArtifact,
    UICollection,
    UIConfirmation,
    UIContext,
    UIEntity,
    UIFact,
    UIField,
    UIFieldGroup,
    UIForm,
    UIInspector,
    UINavItem,
    UINotice,
    UISection,
    UIStatus,
)
from .render import (
    render_action,
    render_actions,
    render_activity,
    render_artifacts,
    render_collection,
    render_confirmation,
    render_entity,
    render_form,
    render_inspector,
    render_message,
    render_notice,
    render_page_header,
    render_chat_workspace,
    render_empty_conversation,
    render_stack,
    render_status,
)
from .patterns import (
    render_activity_result,
    render_conversation_workspace,
    render_entity_detail,
    render_form_workflow,
    render_foundation_catalog,
    render_lab_section,
)
from .shell import (
    render_mobile_workspace_switcher,
    render_shell,
    render_shell_action,
    render_workspace_switcher,
)

__all__ = [
    "STANDARD_SCRIPT", "STANDARD_SCRIPT_SHA256", "WORKBENCH_CSS",
    "UIAction", "UIActivity", "UIArtifact", "UICollection", "UIConfirmation",
    "UIContext", "UIEntity", "UIFact", "UIField", "UIFieldGroup", "UIForm",
    "UIInspector", "UINavItem", "UINotice", "UISection", "UIStatus",
    "render_action", "render_actions", "render_activity", "render_artifacts", "render_collection",
    "render_confirmation", "render_entity", "render_form", "render_inspector",
    "render_message", "render_notice", "render_page_header", "render_shell",
    "render_chat_workspace", "render_empty_conversation", "render_stack",
    "render_status", "render_workspace_switcher", "render_mobile_workspace_switcher",
    "render_shell_action",
    "render_activity_result", "render_conversation_workspace", "render_entity_detail",
    "render_form_workflow", "render_foundation_catalog", "render_lab_section",
]
