# Rollback and key-rotation readiness

> **Record state: `DRAFT_OPERATOR_INPUT_REQUIRED`**
> **Release decision: `BLOCKED`**

This tracked template is not an operational plan and does not assert that an
owner, rollback target, retention policy, or key-rotation procedure exists. An
operator may complete a candidate-specific copy under local policy; do not edit
this tracked template into apparent evidence. Record key identifiers or
custodial roles, never SSH private-key material, approval HMAC key bytes,
tokens, passwords, or site secrets.

## Candidate and rollback identity

| Field | Pending value |
|---|---|
| Release identifier | `PENDING_RELEASE_ID` |
| Exact source Git commit | `PENDING_SOURCE_GIT_COMMIT` |
| Prior reviewed release | `PENDING_ROLLBACK_RELEASE` |
| Prior reviewed source commit | `PENDING_ROLLBACK_SOURCE_GIT_COMMIT` |
| Rollback owner | `PENDING_ROLLBACK_OWNER` |

## Key ownership and rotation

| Field | Pending value |
|---|---|
| Approval HMAC key-rotation owner | `PENDING_HMAC_KEY_ROTATION_OWNER` |
| Constrained SSH key-rotation owner | `PENDING_SSH_KEY_ROTATION_OWNER` |
| Rotation/revocation procedure reference | `PENDING_KEY_ROTATION_PROCEDURE` |
| Validation date | `PENDING_KEY_ROTATION_REVIEW_DATE` |

## Operational evidence ownership

| Field | Pending value |
|---|---|
| Backup owner | `PENDING_BACKUP_OWNER` |
| Retention owner | `PENDING_RETENTION_OWNER` |
| Monitoring owner | `PENDING_MONITORING_OWNER` |
| Capacity owner | `PENDING_CAPACITY_OWNER` |
| Incident-response owner | `PENDING_INCIDENT_RESPONSE_OWNER` |
| Secure-disposal owner | `PENDING_SECURE_DISPOSAL_OWNER` |

## Required operator procedure

The completed procedure must explain how operators stop new approvals, revoke
or disable constrained credentials, restore the prior reviewed controller and
remote agents, preserve active-run and audit evidence, and verify the restored
state. Every item remains `PENDING_OPERATOR_PROCEDURE` in this template.
