# Test Plan: Resource Conflict Detection to Prevent Overwriting Unmanaged Resources

**Sources:** ADR: N/A; PR: https://github.com/openshift/zero-trust-workload-identity-manager/pull/118; Jira: SPIRE-344
**Date:** 2026-06-03
**Mode:** PR
**Scope:** Add `CheckResourceConflict` / `HandleCreateConflict` utilities that validate the `app.kubernetes.io/managed-by` label before resource creation, integrating conflict checks into all 4 controllers (SpireServer, SpireAgent, SpiffeCSIDriver, SpireOIDCDiscoveryProvider).

## Source Conflicts
None

## PR Analysis

### Changed files categorized

| Category | Files | Test implication |
| --- | --- | --- |
| Condition contract | `api/v1alpha1/conditions.go` | New `ReasonResourceConflict` constant — E2E must verify this reason appears in CR conditions |
| Ownership helpers | `pkg/controller/utils/resource_ownership.go`, `resource_ownership_test.go` | `CheckResourceConflict`, `HandleCreateConflict`, `IsResourceConflictOnCreate`, `ResourceConflictError` — covered by existing unit tests |
| ConfigMap data-key constants | `pkg/controller/utils/constants.go` | `SpireAgentConfigKey`, `SpireServerConfigKey`, `SpireControllerManagerConfigKey` — no new E2E needed |
| Reconciler conflict gating | `pkg/controller/spire-server/*`, `spire-agent/*`, `spiffe-csi-driver/*`, `spire-oidc-discovery-provider/*` | All 4 controllers now detect create-time conflicts via `HandleCreateConflict` — E2E must verify at least one resource per controller |
| Unit tests | `pkg/controller/**/*_test.go` | Updated with managed-by labels and conflict test cases — no E2E action needed |

### Key architectural insight

The operator uses a **label-filtered cache** (`pkg/client/client.go:224-229`): the cache only contains resources with `app.kubernetes.io/managed-by: zero-trust-workload-identity-manager`. Removing this label from a resource causes:
1. Cache returns `NotFound` on Get
2. Operator attempts Create
3. API server returns `AlreadyExists`
4. `HandleCreateConflict` detects the conflict and sets condition to `ResourceConflict` / `ConditionFalse`

## Testable Requirements

| ID | Requirement | Category | Source | Confidence |
| --- | --- | --- | --- | --- |
| PR-REQ-001 | When the managed-by label is removed from a SpireServer-managed ConfigMap, the operator detects the conflict on next reconcile and sets `ServerConfigMapAvailable=False` with reason `ResourceConflict` | Functional | `pkg/controller/spire-server/configmap.go:L77` | High |
| PR-REQ-002 | When the managed-by label is removed from a SpireAgent-managed ServiceAccount, the operator detects the conflict and sets `ServiceAccountAvailable=False` with reason `ResourceConflict` | Functional | `pkg/controller/spire-agent/service_account.go:L49` | High |
| PR-REQ-003 | When the managed-by label is removed from a SpiffeCSIDriver-managed ServiceAccount, the operator detects the conflict and sets `ServiceAccountAvailable=False` with reason `ResourceConflict` | Functional | `pkg/controller/spiffe-csi-driver/service_account.go:L49` | High |
| PR-REQ-004 | When the managed-by label is removed from SpireOIDCDiscoveryProvider-managed Service, the operator detects the conflict and sets `ServiceAvailable=False` with reason `ResourceConflict` | Functional | `pkg/controller/spire-oidc-discovery-provider/service.go:L49` | High |
| PR-REQ-005 | After the conflict is resolved (label restored), the operator recovers and sets the condition back to True | Functional | PR description: "Normal updates proceed if the managed-by label is present" | High |
| PR-REQ-006 | The `ReasonResourceConflict` condition reason is used consistently across all controllers | Functional | `api/v1alpha1/conditions.go:L42` | High |
| PR-REQ-007 | The operator continues to function normally for non-conflicting resources while a conflict exists on one resource | Regression | PR diff: conflict is per-resource, not global | Medium |
| PR-REQ-008 | Conflict detection does not interfere with CreateOnlyMode behavior | Regression | PR diff: createOnlyMode checks preserved | Medium |
| PR-REQ-009 | Operator pod restart preserves conflict detection capability | Operational | Implied by stateless reconcile design | Medium |

## Test Cases

### E2E

#### E2E-001: SpireServer detects resource conflict when managed-by label is removed from ConfigMap and recovers after restoration
**Priority:** Critical
**Methodology:** Black box
**Requirement(s):** PR-REQ-001, PR-REQ-005, PR-REQ-006
**Traceability:** `pkg/controller/spire-server/configmap.go:L74-78`, `pkg/client/client.go:L224-229`
**Preconditions:** SpireServer CR `cluster` exists and all conditions are True
**Steps:**
1. Get the `spire-server` ConfigMap in the operator namespace and record its current state
   - **Expected:** ConfigMap exists with `app.kubernetes.io/managed-by: zero-trust-workload-identity-manager` label
2. Remove the `app.kubernetes.io/managed-by` label from the ConfigMap via kubectl/client patch
   - **Expected:** Patch succeeds
3. Wait for SpireServer condition `ServerConfigMapAvailable` to transition to `False` with reason containing `ResourceConflict`
   - **Expected:** Condition is `False` within 5 minutes (DefaultTimeout)
4. Restore the `app.kubernetes.io/managed-by: zero-trust-workload-identity-manager` label on the ConfigMap
   - **Expected:** Patch succeeds
5. Wait for SpireServer condition `ServerConfigMapAvailable` to transition back to `True`
   - **Expected:** Condition is `True` within 5 minutes
6. Verify SpireServer `Ready` condition is `True`
   - **Expected:** SpireServer is fully recovered
**Cleanup:** DeferCleanup restores managed-by label if test fails mid-execution
**Failure Impact:** Conflict detection is broken for SpireServer ConfigMap resources — pre-existing resources could be silently overwritten

#### E2E-002: SpireAgent detects resource conflict when managed-by label is removed from Service
**Priority:** High
**Methodology:** Black box
**Requirement(s):** PR-REQ-002, PR-REQ-005
**Traceability:** `pkg/controller/spire-agent/service.go:L60-62`
**Preconditions:** SpireAgent CR `cluster` exists and all conditions are True
**Steps:**
1. Get the `spire-agent` Service in the operator namespace
   - **Expected:** Service exists with managed-by label
2. Remove the `app.kubernetes.io/managed-by` label
   - **Expected:** Patch succeeds
3. Wait for SpireAgent condition `ServiceAvailable` to become `False` with reason containing `ResourceConflict`
   - **Expected:** Condition transitions within DefaultTimeout
4. Restore the managed-by label
   - **Expected:** Patch succeeds
5. Wait for SpireAgent `ServiceAvailable` condition to return to `True`
   - **Expected:** Full recovery within DefaultTimeout
**Cleanup:** DeferCleanup restores label
**Failure Impact:** SpireAgent conflict detection broken for Service resources

#### E2E-003: SpiffeCSIDriver detects resource conflict when managed-by label is removed from ServiceAccount
**Priority:** High
**Methodology:** Black box
**Requirement(s):** PR-REQ-003, PR-REQ-005
**Traceability:** `pkg/controller/spiffe-csi-driver/service_account.go:L48-50`
**Preconditions:** SpiffeCSIDriver CR `cluster` exists and all conditions are True
**Steps:**
1. Get the SpiffeCSIDriver ServiceAccount in the operator namespace
   - **Expected:** ServiceAccount exists with managed-by label
2. Remove the managed-by label
   - **Expected:** Patch succeeds
3. Wait for SpiffeCSIDriver condition `ServiceAccountAvailable` to become `False`
   - **Expected:** Reason contains `ResourceConflict`
4. Restore the managed-by label
   - **Expected:** Recovery — condition becomes `True`
**Cleanup:** DeferCleanup restores label
**Failure Impact:** SpiffeCSIDriver conflict detection broken

#### E2E-004: SpireOIDCDiscoveryProvider detects resource conflict when managed-by label is removed from Service
**Priority:** High
**Methodology:** Black box
**Requirement(s):** PR-REQ-004, PR-REQ-005
**Traceability:** `pkg/controller/spire-oidc-discovery-provider/service.go:L48-50`
**Preconditions:** SpireOIDCDiscoveryProvider CR `cluster` exists
**Steps:**
1. Get the OIDC Discovery Provider Service
   - **Expected:** Exists with managed-by label
2. Remove managed-by label
   - **Expected:** Patch succeeds
3. Wait for `ServiceAvailable` to become `False` with ResourceConflict
   - **Expected:** Transitions within DefaultTimeout
4. Restore label and verify recovery
   - **Expected:** `ServiceAvailable` returns to `True`
**Cleanup:** DeferCleanup restores label
**Failure Impact:** OIDC provider conflict detection broken

### Negative/Destructive

#### NEG-001: Operator pod restart preserves resource conflict detection
**Priority:** Critical
**Methodology:** Black box
**Requirement(s):** PR-REQ-009
**Traceability:** Stateless reconcile design; `pkg/controller/spire-server/configmap.go`
**Preconditions:** SpireServer CR `cluster` exists and all conditions are True
**Steps:**
1. Remove managed-by label from SpireServer ConfigMap (BEFORE check)
   - **Expected:** ConfigMap loses label
2. Wait for SpireServer `ServerConfigMapAvailable=False` with ResourceConflict
   - **Expected:** Conflict detected
3. Delete operator pod (destructive action)
   - **Expected:** Operator pod is recreated by Deployment controller
4. Wait for new operator pod to be Running
   - **Expected:** Pod reaches Running state
5. Verify `ServerConfigMapAvailable` remains `False` with ResourceConflict (AFTER check)
   - **Expected:** Conflict persists after restart
6. Restore managed-by label
   - **Expected:** Recovery — condition returns to `True`
**Cleanup:** DeferCleanup restores managed-by label and waits for operator pod ready
**Failure Impact:** Operator loses conflict detection state after restart — critical safety regression

#### NEG-002: Multiple simultaneous resource conflicts across controllers
**Priority:** High
**Methodology:** Black box
**Requirement(s):** PR-REQ-007
**Traceability:** PR description: conflict checks integrated into all 4 controllers independently
**Preconditions:** All operand CRs exist and are Ready
**Steps:**
1. Simultaneously remove managed-by label from SpireServer ConfigMap AND SpireAgent Service (BEFORE check)
   - **Expected:** Both labels removed
2. Wait for SpireServer `ServerConfigMapAvailable=False` AND SpireAgent `ServiceAvailable=False`
   - **Expected:** Both conditions show ResourceConflict
3. Verify that SpiffeCSIDriver and SpireOIDCDiscoveryProvider remain Ready (non-conflicting operands unaffected)
   - **Expected:** No impact on other operands
4. Restore both managed-by labels
   - **Expected:** Both operands recover
**Cleanup:** DeferCleanup restores both labels
**Failure Impact:** Conflict in one controller bleeds into others — isolation broken

### Manual QE

#### MQE-001: Verify ResourceConflict condition message is human-readable in oc/kubectl output
**Priority:** Medium
**Methodology:** Black box (human)
**Requirement(s):** PR-REQ-006
**Traceability:** `api/v1alpha1/conditions.go:L42`
**Preconditions:** A resource conflict has been triggered
**Steps:**
1. Run `oc get spireserver cluster -o yaml` and inspect `.status.conditions`
   - **Expected:** The `ResourceConflict` condition has a clear message like "resource <ns>/<name> already exists but is not managed by the operator"
2. Run `oc describe spireserver cluster` and verify the condition is visible in the Events/Conditions section
   - **Expected:** Condition is displayed clearly
**Cleanup:** None
**Failure Impact:** Operators cannot diagnose conflict issues from CLI output

## Traceability Matrix

| Requirement | UT | INT | E2E | NEG | MQE | NFT | Status |
| --- | --- | --- | --- | --- | --- | --- | --- |
| PR-REQ-001 | resource_ownership_test.go | - | E2E-001 | NEG-001 | - | - | Covered |
| PR-REQ-002 | service_account_test.go | - | E2E-002 | - | - | - | Covered |
| PR-REQ-003 | service_account_test.go | - | E2E-003 | - | - | - | Covered |
| PR-REQ-004 | service_test.go | - | E2E-004 | - | - | - | Covered |
| PR-REQ-005 | - | - | E2E-001, E2E-002, E2E-003, E2E-004 | NEG-001 | - | - | Covered |
| PR-REQ-006 | - | - | E2E-001 | - | MQE-001 | - | Covered |
| PR-REQ-007 | - | - | - | NEG-002 | - | - | Covered |
| PR-REQ-008 | - | - | - | - | - | - | NOT COVERED — CreateOnlyMode + conflict interaction not tested; risk is low since code paths are independent |
| PR-REQ-009 | - | - | - | NEG-001 | - | - | Covered |

## Uncovered Requirements
- **PR-REQ-008:** CreateOnlyMode + conflict interaction — Not covered because the code paths are independent (createOnlyMode check occurs after Get success, while conflict detection occurs after Create failure). Risk is low.

## Coverage Summary

| Tier | Count | Critical | High | Medium |
| --- | --- | --- | --- | --- |
| Unit | 0 | 0 | 0 | 0 |
| Integration | 0 | 0 | 0 | 0 |
| E2E | 4 | 1 | 3 | 0 |
| Negative/Destructive | 2 | 1 | 1 | 0 |
| Manual QE | 1 | 0 | 0 | 1 |
| Non-Functional | 0 | 0 | 0 | 0 |
| **Total** | **7** | **2** | **4** | **1** |

## Gaps and Recommendations
- **Cannot determine without ADR:** Whether conflict detection should also trigger Upgradeable=False (currently only operand readiness affects Upgradeable)
- **Recommend ADR review for:** Whether the operator should attempt automatic conflict resolution (e.g., adopt the unmanaged resource by adding the label)
- **Existing tests that may need update:** None — existing E2E tests in `test/e2e/e2e_test.go` are unaffected by this PR

## Generation Stats

| Metric | Value |
| --- | --- |
| Test cases generated | 7 |
| Requirements identified | 9 |
| Requirements covered | 8/9 |
| Approx. output words | 1200 |
| Estimated output tokens | 1560 |
