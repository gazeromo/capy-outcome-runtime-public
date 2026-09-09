"""One owner-approved managed connection for an exact checked release.

This surface selects only an already-approved exact app/version source grant
in its existing workspace. Workspace ownership never confers connection
redelegation authority. No credentials or independent grants are created.
"""
from __future__ import annotations

import hashlib
import io
import json
import zipfile
from types import SimpleNamespace
from pathlib import PurePosixPath

from .account_readiness import AccountReadiness
from .connections import BROKER_OPERATION_POLICY
from .model import ConnectionRequirement
from .release_admission import _trusted
from .release_workflow import fail
from .store import canonical_json, sha256


class ReleaseConnectionSetup:
    def __init__(self, workflow, control, *, team=None, readiness_probe=None):
        self.workflow, self.control, self.team = workflow, control, team
        self.readiness_probe = readiness_probe

    def _snapshot(self, actor, submission_id):
        source = self.workflow._row(submission_id, actor)
        attempt = self.workflow.status(actor, submission_id)['attempt']
        if not attempt or attempt['status'] != 'ACCEPTED':
            fail('RELEASE_CHECKS_REQUIRED')
        trust, candidate_bytes, receipt_bytes = self.workflow.bridge.export(
            owner=source['owner'], submission_id=submission_id, attempt_id=attempt['attempt_id'])
        candidate, _ = _trusted(trust, candidate_bytes, receipt_bytes, source['owner'],
                                submission_id, attempt['attempt_id'])
        raw = candidate.descriptor
        # Match the admitted application tree identity without writing or
        # publishing a single file during a GET of the setup page.
        with zipfile.ZipFile(io.BytesIO(candidate.members['application/application.zip'])) as archive:
            modes = {i.filename: bool((i.external_attr >> 16) & 0o111) for i in archive.infolist()}
        hasher = hashlib.sha256()
        for name, data in sorted(candidate.application_members.items(), key=lambda item: PurePosixPath(item[0]).parts):
            hasher.update(canonical_json(dict(path=name, executable=modes[name], size=len(data))))
            hasher.update(b'\0'); hasher.update(data); hasher.update(b'\0')
        version = hasher.hexdigest()
        descriptor = SimpleNamespace(id=raw['id'], name=raw['name'], side_effect=raw['side_effect'],
            state_required=raw['state_required'], connections=tuple(r['name'] for r in raw['connections']),
            connection_requirements=tuple(ConnectionRequirement(
                r['name'], r['contract'], tuple(r['operations']), r['required']) for r in raw['connections']))
        if not descriptor.connections:
            return descriptor, version, [], None
        if len(descriptor.connections) != 1 or descriptor.side_effect not in {'read_only', 'artifact_generation'} or descriptor.state_required:
            fail('APPLICATION_CONNECTION_SETUP_UNSUPPORTED')
        requirement = descriptor.connection_requirements[0]
        if not set(requirement.operations) <= BROKER_OPERATION_POLICY.get(requirement.contract, frozenset()):
            fail('APPLICATION_CONNECTION_SETUP_UNSUPPORTED')
        workspaces = self.workflow.access.workspaces(actor)
        targets = [a for a in workspaces if a.membership_kind == 'owner']
        preview_owner = next((a for a in targets if a.membership_id == source['owner']['membership_id']), None)
        if preview_owner is None:
            fail('RELEASE_TARGET_AUTHORITY_DENIED')
        # Existing access is the authority input. Display labels are data and
        # never select or imply access to an instance.
        options = []
        with self.control.store.connect() as db:
            for owner in targets:
                rows = db.execute("""SELECT g.*, i.display_json FROM connection_grants g
                    JOIN connection_instances i ON i.id=g.connection_id
                    WHERE g.scope_id=? AND g.status='active' AND i.status='active'
                    AND g.contract=? AND i.contract=g.contract
                    AND g.capability_id=? AND g.version_digest=?
                    AND g.id NOT IN (SELECT grant_id FROM derived_connection_grants)
                    ORDER BY g.id""", (owner.execution_scope_id, requirement.contract, descriptor.id, version)).fetchall()
                for row in rows:
                    if not set(requirement.operations) <= set(json.loads(row['operations_json'])):
                        continue
                    fingerprint = self.control._source_fingerprint(row)
                    # A separate workspace needs its own existing exact
                    # approval. Never transfer the selected source grant.
                    preview_sources = db.execute("""SELECT g.* FROM connection_grants g
                        JOIN connection_instances i ON i.id=g.connection_id
                        WHERE g.scope_id=? AND g.connection_id=? AND g.capability_id=? AND g.version_digest=?
                        AND g.contract=? AND g.status='active' AND i.status='active' AND i.contract=g.contract
                        AND g.id NOT IN (SELECT grant_id FROM derived_connection_grants)
                        ORDER BY g.id""", (preview_owner.execution_scope_id, row['connection_id'],
                        descriptor.id, version, requirement.contract)).fetchall()
                    for preview_source in preview_sources:
                        if not set(requirement.operations) <= set(json.loads(preview_source['operations_json'])):
                            continue
                        selection = dict(submission_id=submission_id, application_id=descriptor.id,
                            version_digest=version, membership_id=owner.membership_id,
                            source_grant_id=row['id'], source_fingerprint=fingerprint,
                            preview_grant_id=preview_source['id'],
                            preview_fingerprint=self.control._source_fingerprint(preview_source))
                        label = json.loads(row['display_json']).get('label', 'Publisher-managed connection')
                        options.append(dict(selection, choice_id=sha256(canonical_json(selection)),
                            label=label if isinstance(label, str) else 'Publisher-managed connection',
                            workspace=owner.team_name, connection_id=row['connection_id'], target=owner))
        return descriptor, version, options, preview_owner

    def view(self, actor, submission_id):
        with self.workflow.access.guarded_actor(actor):
            descriptor, version, options, preview_owner = self._snapshot(actor, submission_id)
            return dict(application_id=descriptor.id, version_digest=version, title=descriptor.name,
                requirements=[dict(name=r.name, contract=r.contract, operations=list(r.operations))
                              for r in descriptor.connection_requirements],
                preview_status=(self.control.application_status(preview_owner.team_id, descriptor, version)['status']
                                if preview_owner is not None else 'configured'),
                choices=[{k: option[k] for k in ('choice_id', 'label', 'workspace')}
                         for option in options])

    def readiness(self, actor, submission_id, choice_id, version_digest):
        """Observe only a currently authorized exact account, without granting access.

        The probe is host-injected, never chosen by the application or request.
        Until custody/service observation is wired, report unknown, not ready.
        A quote proof must be fresh and bound to this exact submission/version.
        """
        with self.workflow.access.guarded_actor(actor):
            _, version, options, _ = self._snapshot(actor, submission_id)
            selected = next((o for o in options if o['choice_id'] == choice_id), None)
            if selected is None or version_digest != version:
                fail('APPLICATION_CONNECTION_SELECTION_CHANGED')
            if self.readiness_probe is None:
                observation = AccountReadiness()
            else:
                try:
                    observation = self.readiness_probe(
                        connection_id=selected['connection_id'],
                        workspace_id=selected['target'].team_id,
                        submission_id=submission_id, version_digest=version)
                    if type(observation) is not AccountReadiness:
                        raise ValueError('Invalid readiness result')
                except Exception:
                    # Provider/custody exceptions can contain secrets or paths.
                    # Never serialize, log or attach the original exception.
                    observation = AccountReadiness(service='unavailable')
            return observation.public_status()

    def approve(self, actor, submission_id, choice_id, version_digest):
        with self.workflow.access.guarded_actor(actor):
            descriptor, version, options, preview_owner = self._snapshot(actor, submission_id)
            selected = next((o for o in options if o['choice_id'] == choice_id), None)
            if selected is None or version_digest != version:
                fail('APPLICATION_CONNECTION_SELECTION_CHANGED')
            requirement = descriptor.connection_requirements[0]
            # Owner selection activates only the existing exact source grants;
            # it grants no connection management or cross-workspace authority.
            scopes = {preview_owner.execution_scope_id: (preview_owner, selected['preview_grant_id'], selected['preview_fingerprint']),
                      selected['target'].execution_scope_id: (selected['target'], selected['source_grant_id'], selected['source_fingerprint'])}
            with self.control.store.transaction():
                for target, grant_id, fingerprint in scopes.values():
                    current = self.control.resolve_grant(grant_id, scope_id=target.execution_scope_id,
                        capability_id=descriptor.id, version_digest=version, contract=requirement.contract)
                    if (self.control._source_fingerprint(current) != fingerprint
                            or current['connection_id'] != selected['connection_id']
                            or current['capability_id'] != descriptor.id or current['version_digest'] != version):
                        fail('APPLICATION_CONNECTION_SELECTION_CHANGED')
                    self.control.configure_application(target.team_id, descriptor.id, version,
                        source_scope_id=target.execution_scope_id, connections={requirement.name: grant_id})
                    binding = self.control.store.binding_or_none(target.execution_scope_id, descriptor.id)
                    if binding is not None and binding.version_digest == version:
                        if target.workspace_kind == 'team' and self.team is not None:
                            self.team.reconcile_team(target.team_id)
                        elif target.workspace_kind == 'personal':
                            self.control.check_application_binding_identity(binding.connections, descriptor, version,
                                workspace_id=target.team_id, scope_id=target.execution_scope_id,
                                membership_id=target.membership_id)
                            replacement = self.control.application_bindings(descriptor, version,
                                workspace_id=target.team_id, scope_id=target.execution_scope_id,
                                membership_id=target.membership_id)
                            if replacement != binding.connections:
                                self.control.revoke_bindings(binding.connections)
                                self.control.store.bind(target.execution_scope_id, descriptor.id, version, replacement)
            return dict(status='configured', application_id=descriptor.id, version_digest=version,
                        membership_id=selected['target'].membership_id, workspace=selected['workspace'])
