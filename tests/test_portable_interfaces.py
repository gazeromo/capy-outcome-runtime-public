"""Pure grammar fixtures, not newly accepted applications."""
import copy
import hashlib
import io
import json
from pathlib import Path
import tomllib
import unittest
import zipfile

from capy_outcome_runtime.model import RuntimeFailure
from capy_outcome_runtime.portable_interfaces import (
    FORM_MARKER, PRESENCE_PREFIX, parse_portable_request, project_portable,
    project_portable_result, render_portable_fields,
)


def fixture():
    execution = {
        "id": "example.scalar", "version_digest": "a" * 64,
        "state_required": False, "connections": [], "resources": [], "side_effect": "read_only",
        "input_schema": {"type": "object", "additionalProperties": False,
            "required": ["count", "enabled", "name"], "properties": {
                "count": {"type": "integer", "minimum": 0},
                "enabled": {"type": "boolean"}, "name": {"type": "string"},
                "ratio": {"type": "number", "minimum": 0},
                "choice": {"type": "string", "enum": ["red", "<blue>"]},
                "options": {"type": "object", "additionalProperties": False,
                    "required": ["label"], "properties": {
                        "label": {"type": "string", "minLength": 1},
                        "limit": {"type": "integer"}}}}},
        "result_schema": {"type": "object", "additionalProperties": False,
            "required": ["stats"], "properties": {
                "stats": {"type": "object", "additionalProperties": False,
                    "required": ["count", "ok"], "properties": {
                        "count": {"type": "integer"}, "ok": {"type": "boolean"},
                        "private": {"type": "string"}}}}},
    }
    fields = []
    for path, kind, required, default in [
        ("count", "number", True, None), ("enabled", "boolean", True, None),
        ("name", "text", True, None), ("ratio", "number", False, 0),
        ("choice", "choice", False, None), ("options.label", "text", False, None),
        ("options.limit", "number", False, 3),
    ]:
        fields.append({"field_id": path, "label": path, "description": "<script>unsafe</script>",
                       "required": required, "input_kind": kind, "safe_default": default,
                       "examples": ["example"], "clarification_question": "Which value?"})
    interaction = {
        "schema": "capy.application-interaction/dev-v0", "application_id": execution["id"],
        "title": "Scalar app", "purpose": "Exercise scalar grammar.", "not_for": ["Other work"],
        "operation": {"operation_id": "scalar.run", "title": "Run", "user_outcome": "Scalar facts",
            "description": "Run once", "request_fields": fields, "resource_fields": [],
            "examples": ["Run this"], "common_misunderstandings": ["No other operations"],
            "result": {"presentation": "facts", "facts": [
                {"path": "stats.count", "label": "Count"}, {"path": "stats.ok", "label": "Okay"}],
                "artifacts": []}},
        "boundaries": [{"boundary_id": "scalar.other", "request_class": "Other work",
            "explanation": "Unavailable", "nearest_operation_ids": ["scalar.run"]}],
    }
    return execution, interaction


class PortableInterfaceTests(unittest.TestCase):
    def setUp(self):
        self.execution, self.interaction = fixture()
        self.contract = project_portable(self.execution, self.interaction, "import-test")
        self.op = self.contract["operations"][0]
        self.fields = {"count": "0", "enabled": "false", "name": ""}

    def test_exact_identity_digest_and_copy(self):
        data = copy.deepcopy(self.contract)
        digest = data.pop("digest")
        self.assertEqual(digest, hashlib.sha256(json.dumps(data, sort_keys=True,
            separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()).hexdigest())
        for key, value in [("version_digest", "b" * 64)]:
            ex = {**self.execution, key: value}
            self.assertNotEqual(digest, project_portable(ex, self.interaction, "import-test")["digest"])
        self.assertNotEqual(digest, project_portable(self.execution, self.interaction, "import-other")["digest"])
        changed = copy.deepcopy(self.interaction)
        changed["purpose"] = "Changed purpose"
        self.assertNotEqual(digest, project_portable(self.execution, changed, "import-test")["digest"])
        self.op["request_schema"]["properties"]["count"]["minimum"] = 5
        self.assertEqual(self.execution["input_schema"]["properties"]["count"]["minimum"], 0)

    def test_scalar_types_absence_and_defaults(self):
        self.assertEqual(parse_portable_request(self.op, self.fields),
                         {"count": 0, "enabled": False, "name": "", "ratio": 0})
        request = parse_portable_request(self.op, {**self.fields, "ratio": "1.25", "choice": "<blue>"})
        self.assertEqual(request["ratio"], 1.25)
        self.assertEqual(request["choice"], "<blue>")
        self.assertNotIn("options", request)

    def test_nested_default_does_not_activate_optional_object(self):
        self.assertNotIn("options", parse_portable_request(self.op, self.fields))
        request = parse_portable_request(self.op, {**self.fields, "options.label": "hello"})
        self.assertEqual(request["options"], {"label": "hello", "limit": 3})
        with self.assertRaises(RuntimeFailure):
            parse_portable_request(self.op, {**self.fields, "options.limit": "0"})

    def test_required_empty_object_preserved(self):
        ex, interaction = fixture()
        ex["input_schema"] = {"type": "object", "additionalProperties": False,
            "required": ["options"], "properties": {"options": {"type": "object",
                "additionalProperties": False, "properties": {"note": {"type": "string"}}}}}
        field = copy.deepcopy(interaction["operation"]["request_fields"][0])
        field.update(field_id="options.note", input_kind="text", required=False)
        interaction["operation"]["request_fields"] = [field]
        op = project_portable(ex, interaction, "import-test")["operations"][0]
        self.assertEqual(parse_portable_request(op, {}), {"options": {}})

    def test_invalid_submissions(self):
        for key, value in [("count", "1.2"), ("count", "true"), ("count", "-1"),
                           ("enabled", "False"), ("enabled", "on"), ("choice", "green"),
                           ("ratio", "NaN"), ("ratio", "Infinity"), ("ratio", "1e999"),
                           ("ratio", " 1"), ("ratio", ""), ("unknown", "x")]:
            with self.subTest(key=key, value=value), self.assertRaises(RuntimeFailure):
                parse_portable_request(self.op, {**self.fields, key: value})
        with self.assertRaises(RuntimeFailure):
            parse_portable_request(self.op, {**self.fields, "count": ["1", "2"]})
        with self.assertRaises(RuntimeFailure):
            parse_portable_request(self.op, {"name": ""})

    def test_browser_presence(self):
        values = {**self.fields, FORM_MARKER: "1", "choice": "", "options.label": "", "options.limit": "3"}
        request = parse_portable_request(self.op, values)
        self.assertNotIn("choice", request)
        self.assertNotIn("options", request)
        values.update({PRESENCE_PREFIX + "options.label": "1", "options.label": "yes"})
        self.assertEqual(parse_portable_request(self.op, values)["options"], {"label": "yes", "limit": 3})
        for extra in [{FORM_MARKER: "bad"}, {PRESENCE_PREFIX + "choice": "true"},
                      {PRESENCE_PREFIX + "fake": "1"}]:
            with self.assertRaises(RuntimeFailure):
                parse_portable_request(self.op, {**values, **extra})

    def test_escaped_rendering(self):
        rendered = render_portable_fields(self.op["human_fields"])
        self.assertNotIn("<script>", rendered)
        self.assertIn("&lt;script&gt;", rendered)
        self.assertIn("&lt;blue&gt;", rendered)
        self.assertIn('step="any"', rendered)
        self.assertIn('step="1"', rendered)
        self.assertIn('value="false"', rendered)
        self.assertIn('Include options.label', rendered)
        self.assertIn('name="__portable_form" value="1"', rendered)

    def test_resources_and_nested_result(self):
        ex, interaction = fixture()
        ex["resources"] = [{"name": "inputs", "required": False, "min_items": 0, "max_items": 3}]
        interaction["operation"]["resource_fields"] = [{"slot": "inputs", "label": "Inputs",
            "description": "Any files", "required": False, "minimum_count": 0, "maximum_count": 3,
            "input_kind": "file", "examples": ["data.bin"], "clarification_question": "Which files?"}]
        op = project_portable(ex, interaction, "import-test")["operations"][0]
        self.assertEqual(op["resources"], ex["resources"])
        rendered = render_portable_fields(op["human_fields"])
        self.assertIn(' multiple', rendered)
        self.assertNotIn('.csv', rendered)
        self.assertEqual(project_portable_result(op, {"stats": {"count": 0, "ok": False, "private": "hidden"}}, []),
                         ({"stats.count": 0, "stats.ok": False}, []))
        with self.assertRaises(RuntimeFailure):
            project_portable_result(op, {"stats": {"count": float("nan"), "ok": False}}, [])

    def test_optional_false_default_and_exact_text(self):
        ex, interaction = fixture()
        ex["input_schema"]["required"].remove("enabled")
        field = interaction["operation"]["request_fields"][1]
        field.update(required=False, safe_default=False)
        op = project_portable(ex, interaction, "import-test")["operations"][0]
        self.assertIs(parse_portable_request(op, {"count": "0", "name": "  text  "})["enabled"], False)
        self.assertEqual(parse_portable_request(op, {"count": "0", "name": "  text  "})["name"], "  text  ")
        self.assertIs(parse_portable_request(op, {"count": "0", "name": "", "enabled": "true"})["enabled"], True)
        rendered = render_portable_fields(op["human_fields"])
        self.assertIn('name="__present__.enabled" value="1" checked', rendered)
        self.assertIn('<option value="false" selected>', rendered)
        self.assertIn('name="input.name" value="">', rendered)

    def test_artifact_allowlist(self):
        ex, interaction = fixture()
        ex["side_effect"] = "artifact_generation"
        ex["result_schema"]["properties"]["artifact_filenames"] = {
            "type": "array", "items": {"type": "string", "enum": ["output.json"]}}
        interaction["operation"]["result"].update(presentation="artifact_result",
            artifacts=[{"filename": "output.json", "label": "Output"}])
        op = project_portable(ex, interaction, "import-test")["operations"][0]
        artifacts = [{"filename": "output.json", "digest": "a" * 64},
                     {"filename": "hidden.json", "digest": "b" * 64}]
        facts, visible = project_portable_result(op, {
            "stats": {"count": 0, "ok": True}, "artifact_filenames": ["output.json"]}, artifacts)
        self.assertEqual(visible, artifacts[:1])
        self.assertEqual(facts, {"stats.count": 0, "stats.ok": True})
        self.assertEqual(op["result"]["artifact_labels"], {"output.json": "Output"})

    def test_ordinary_runtime_projection_shape(self):
        ex, interaction = fixture()
        ex["resources"] = [{"name": "source", "required": True, "min_items": 1, "max_items": 2}]
        interaction["operation"]["resource_fields"] = [{"slot": "source", "label": "Source",
            "description": "Supplied files", "required": True, "minimum_count": 1, "maximum_count": 2,
            "input_kind": "file", "examples": ["data.bin"], "clarification_question": "Which files?"}]
        expected = project_portable(ex, interaction, "import-test")
        # Pure dict matching RuntimeStore._capability_projection: no authoring
        # descriptor schema, entrypoint or resources key.
        projection = {key: copy.deepcopy(ex[key]) for key in (
            "id", "version_digest", "side_effect", "input_schema", "result_schema", "connections", "state_required")}
        projection.update(name="Scalar app", description="Scalar grammar", acceptance_digest="b" * 64,
            state_available=False, resource_requirements=copy.deepcopy(ex["resources"]))
        self.assertEqual(project_portable(projection, interaction, "import-test"), expected)
        self.assertEqual(projection["resource_requirements"], ex["resources"])
        self.assertNotIn("resources", projection)
        with self.assertRaises(RuntimeFailure):
            project_portable({**projection, "resources": []}, interaction, "import-test")
        for bad in [None, [{**ex["resources"][0], "min_items": True}], ex["resources"] * 2]:
            with self.subTest(bad=bad), self.assertRaises(RuntimeFailure):
                project_portable({**projection, "resource_requirements": bad}, interaction, "import-test")

    def test_app_controls_namespace_preserves_metadata_named_fields(self):
        ex, interaction = fixture()
        properties = {
            "csrf": {"type": "string"},
            "application_version": {"type": "string", "enum": ["one", "two"]},
            "contract_digest": {"type": "number"},
            "submission": {"type": "boolean"},
            "notes": {"type": "string"},
            "input": {"type": "object", "additionalProperties": False,
                      "properties": {"csrf": {"type": "string"}}},
        }
        ex["input_schema"] = {"type": "object", "additionalProperties": False,
                              "properties": properties}
        fields = []
        for key, kind in [("csrf", "text"), ("application_version", "choice"),
                          ("contract_digest", "number"), ("submission", "boolean"),
                          ("notes", "long_text"), ("input.csrf", "text")]:
            field = copy.deepcopy(interaction["operation"]["request_fields"][0])
            field.update(field_id=key, input_kind=kind, required=False, safe_default=None)
            fields.append(field)
        interaction["operation"]["request_fields"] = fields
        ex["resources"] = [{"name": "workspace_membership_id", "required": False,
                            "min_items": 0, "max_items": 2}]
        interaction["operation"]["resource_fields"] = [{
            "slot": "workspace_membership_id", "label": "Input files", "description": "Files",
            "required": False, "minimum_count": 0, "maximum_count": 2, "input_kind": "file",
            "examples": ["data.bin"], "clarification_question": "Which files?"}]
        op = project_portable(ex, interaction, "import-test")["operations"][0]
        rendered = render_portable_fields(op["human_fields"])
        for key in [*map(lambda field: field["field_id"], fields), "workspace_membership_id"]:
            self.assertIn(f'name="input.{key}"', rendered)
            if key != "input.csrf":  # input.csrf is csrf's namespaced control.
                self.assertNotIn(f'name="{key}"', rendered)
        self.assertIn('name="__present__.csrf"', rendered)
        self.assertNotIn('name="__present__.input.notes"', rendered)
        self.assertEqual([f["field_id"] for f in op["human_fields"]],
                         [f["field_id"] for f in fields] + ["workspace_membership_id"])
        # The HTTP adapter removes exactly one input. prefix. The pure parser
        # still consumes raw application IDs, including a literal input parent.
        raw = {"csrf": "app value", "application_version": "two", "contract_digest": "0.25",
               "submission": "false", "notes": "", "input.csrf": "nested value"}
        browser = {**raw, FORM_MARKER: "1", **{PRESENCE_PREFIX + key: "1" for key in raw}}
        expected = {"csrf": "app value", "application_version": "two", "contract_digest": 0.25,
                    "submission": False, "notes": "", "input": {"csrf": "nested value"}}
        self.assertEqual(parse_portable_request(op, raw), expected)
        self.assertEqual(parse_portable_request(op, browser), expected)

    def test_reject_contract_mismatch(self):
        for mutation in [lambda x: x.update(schema="wrong"),
                         lambda x: x.update(application_id="wrong.app"),
                         lambda x: x.update(extra=True),
                         lambda x: x["operation"]["request_fields"].pop(),
                         lambda x: x["operation"]["request_fields"][0].update(required=False),
                         lambda x: x["operation"]["result"]["facts"][0].update(path="stats")]:
            changed = copy.deepcopy(self.interaction)
            mutation(changed)
            with self.assertRaises(RuntimeFailure):
                project_portable(self.execution, changed, "import-test")

    def test_accepted_candidate_projections(self):
        root = Path(__file__).resolve().parents[1] / "campaigns/accepted_release_import_preview_v0/inputs"
        # Exact campaign handoff bytes; pure projection only, no accepted execution claim.
        for name in ["B_verified_mean", "C_verified_artifact"]:
            with self.subTest(name=name), zipfile.ZipFile(root / name / "candidate.capyrc") as candidate:
                with zipfile.ZipFile(io.BytesIO(candidate.read("application/application.zip"))) as application:
                    ex = tomllib.loads(application.read("capability.toml").decode())
                ex["version_digest"] = "a" * 64
                interaction = json.loads(candidate.read("application/interaction.json"))
                op = project_portable(ex, interaction, "import-test")["operations"][0]
                self.assertEqual(parse_portable_request(op, {}), {})
                self.assertEqual(op["capability_id"], ex["id"])


if __name__ == "__main__":
    unittest.main()
