# Test Plan: Resource Conflict Detection (PR #118)
<!-- Source: https://github.com/openshift/zero-trust-workload-identity-manager/pull/118 -->
<!-- Repo: openshift/zero-trust-workload-identity-manager -->
<!-- Framework: Ginkgo v2 / controller-runtime -->

## Summary
PR #118 adds resource conflict detection using the `app.kubernetes.io/managed-by` label. When the operator attempts to create a resource that already exists without this label, it reports a `ResourceConflict` condition and refuses to overwrite. This test plan covers managed-by label verification on all operands, conflict condition reporting, and drift correction of the managed-by label.

## Test Cases

### PR-118-TC-001: Managed-by label present on all operand resources
**Priority:** Critical
**Domain:** reconciliation, controller-manager
**Category:** 1 (Core)
**OpenShift-specific:** no
**Coverage Gap:** No e2e test verifies managed-by labels on operator-created resources
**Scope:** app.kubernetes.io/managed-by label on ServiceAccount, ConfigMap, DaemonSet, StatefulSet, Deployment, Service, ClusterRole, ClusterRoleBinding, Role, RoleBinding
**Prerequisites:** Operator installed, all 4 operands created
**Steps:**
1. List all operand workloads (StatefulSet spire-server, DaemonSet spire-agent, DaemonSet spire-spiffe-csi-driver, Deployment spire-spiffe-oidc-discovery-provider)
   **Expected:** Each has label `app.kubernetes.io/managed-by: zero-trust-workload-identity-manager`
2. List ServiceAccounts for each operand
   **Expected:** Each has the managed-by label
3. List ConfigMaps for spire-server and spire-agent
   **Expected:** Each has the managed-by label
**Stop condition:** Missing label means conflict detection will false-positive on upgrades
**Environment notes:** Any OCP version
**Red Hat certification angle:** Validates operator resource ownership tracking

### PR-118-TC-002: ResourceConflict condition reported for SpireServer when pre-existing resource exists
**Priority:** Critical
**Domain:** reconciliation, controller-manager
**Category:** 6 (Errors)
**OpenShift-specific:** no
**Coverage Gap:** No e2e test validates the ResourceConflict condition
**Scope:** SpireServer CR, ServiceAccount, ResourceConflict condition
**Prerequisites:** Operator installed, no SpireServer CR active
**Steps:**
1. Create a ServiceAccount named `spire-server` in operator namespace WITHOUT managed-by label
   **Expected:** ServiceAccount created successfully
2. Create SpireServer CR named `cluster`
   **Expected:** SpireServer CR accepted
3. Wait for SpireServer conditions; check for `ResourceConflict` reason in any condition
   **Expected:** At least one condition has reason `ResourceConflict` with status False
4. `DeferCleanup`: Delete the pre-existing ServiceAccount and SpireServer CR
**Stop condition:** Operator silently overwrites user resources if conflict detection fails
**Environment notes:** Any OCP version
**Red Hat certification angle:** Validates operator safety around pre-existing resources

### PR-118-TC-003: ResourceConflict condition reported for SpireAgent when pre-existing resource exists
**Priority:** High
**Domain:** reconciliation, controller-manager
**Category:** 6 (Errors)
**OpenShift-specific:** no
**Coverage Gap:** No e2e test for SpireAgent conflict detection
**Scope:** SpireAgent CR, ServiceAccount, ResourceConflict condition
**Prerequisites:** Operator installed, no SpireAgent CR active for conflict test
**Steps:**
1. Create a ServiceAccount named `spire-agent` in operator namespace WITHOUT managed-by label
   **Expected:** ServiceAccount created successfully
2. Create SpireAgent CR named `cluster`
   **Expected:** SpireAgent CR accepted
3. Wait and check SpireAgent conditions for `ResourceConflict` reason
   **Expected:** At least one condition has reason `ResourceConflict` with status False
4. `DeferCleanup`: Delete the pre-existing ServiceAccount and SpireAgent CR
**Stop condition:** SpireAgent overwrites user-managed resources
**Environment notes:** Any OCP version
**Red Hat certification angle:** Resource ownership safety

### PR-118-TC-004: Managed-by label on SCC resources
**Priority:** High
**Domain:** openshift-scc, security-context
**Category:** 9 (Security)
**OpenShift-specific:** yes
**Coverage Gap:** No test verifies managed-by label on SCC resources
**Scope:** SecurityContextConstraints for spire-agent and spiffe-csi-driver
**Prerequisites:** SpireAgent and SpiffeCSIDriver operands installed
**Steps:**
1. Get SCC `spire-agent` and verify it has label `app.kubernetes.io/managed-by: zero-trust-workload-identity-manager`
   **Expected:** Label present
2. Get SCC `spire-spiffe-csi-driver` and verify it has the same managed-by label
   **Expected:** Label present
**Stop condition:** SCC without ownership label could be overwritten or conflict with user SCCs
**Environment notes:** OpenShift only
**Red Hat certification angle:** SCC ownership and safety

### PR-118-TC-005: Managed-by label drift correction on workloads
**Priority:** High
**Domain:** reconciliation, controller-manager
**Category:** 3 (Dynamic)
**OpenShift-specific:** no
**Coverage Gap:** No drift correction test for managed-by labels
**Scope:** StatefulSet spire-server, managed-by label removal and reconciliation
**Prerequisites:** SpireServer operand installed
**Steps:**
1. Get StatefulSet `spire-server` and verify managed-by label exists
   **Expected:** Label `app.kubernetes.io/managed-by: zero-trust-workload-identity-manager` present
2. Remove the managed-by label from the StatefulSet
   **Expected:** Label removed (confirmed by Get)
3. Wait for the operator to reconcile and restore the label
   **Expected:** Eventually the managed-by label is restored within DefaultTimeout
**Stop condition:** Operator cannot self-heal label drift, breaking future conflict detection
**Environment notes:** Any OCP version
**Red Hat certification angle:** Validates operator reconciliation and self-healing

### PR-118-TC-006: Managed-by label on RBAC resources (ClusterRoles and ClusterRoleBindings)
**Priority:** Medium
**Domain:** rbac, openshift-rbac-scoping
**Category:** 5 (Multi-tenant / NS)
**OpenShift-specific:** no
**Coverage Gap:** No test verifies managed-by label on RBAC resources
**Scope:** ClusterRole and ClusterRoleBinding for spire-server, spire-agent
**Prerequisites:** SpireServer and SpireAgent operands installed
**Steps:**
1. Get ClusterRole `spire-server` and verify managed-by label
   **Expected:** Label present
2. Get ClusterRoleBinding `spire-server` and verify managed-by label
   **Expected:** Label present
3. Get ClusterRole `spire-agent` and verify managed-by label
   **Expected:** Label present
4. Get ClusterRoleBinding `spire-agent` and verify managed-by label
   **Expected:** Label present
**Stop condition:** RBAC resources without labels vulnerable to accidental overwrite
**Environment notes:** Any OCP version
**Red Hat certification angle:** RBAC least-privilege and ownership

### PR-118-TC-007: ConfigMap data key standardization
**Priority:** Medium
**Domain:** configmap, reconciliation
**Category:** 3 (Dynamic)
**OpenShift-specific:** no
**Coverage Gap:** No test explicitly verifies ConfigMap data key names
**Scope:** ConfigMap data keys for spire-server, spire-agent, spire-controller-manager
**Prerequisites:** All operands installed
**Steps:**
1. Get ConfigMap `spire-server` and verify it has key `server.conf`
   **Expected:** Key exists and is non-empty
2. Get ConfigMap `spire-agent` and verify it has key `agent.conf`
   **Expected:** Key exists and is non-empty
3. Get ConfigMap `spire-controller-manager-config` and verify it has key `controller-manager-config.yaml`
   **Expected:** Key exists and is non-empty
**Stop condition:** Wrong key name breaks SPIRE processes that mount ConfigMaps
**Environment notes:** Any OCP version
**Red Hat certification angle:** Configuration integrity validation

## Coverage Map
| Scenario | Existing spec | Domain | Decision |
| --- | --- | --- | --- |
| Managed-by label on workloads | none | reconciliation | new-in-file |
| ResourceConflict condition (SpireServer) | none | reconciliation, controller-manager | new-in-file |
| ResourceConflict condition (SpireAgent) | none | reconciliation, controller-manager | new-in-file |
| Managed-by label on SCCs | none | openshift-scc | new-in-file |
| Managed-by label drift correction | none | reconciliation | new-in-file |
| Managed-by label on RBAC | none | rbac | new-in-file |
| ConfigMap data key verification | none | configmap | new-in-file |

## OLM Coverage
- Subscription install: covered (existing)
- Channel switching: not covered
- Upgrade path: not covered
- Dependency management: not covered
- Uninstall cleanup: not covered

## OpenShift Coverage
- SCC validation: covered (TC-004)
- RBAC scoping: covered (TC-006)
- Image scanning: not covered
- Prometheus metrics: not covered
- Audit logging: not covered
- Version compatibility: not covered

## Red Hat Certification Checklist
- [x] OLM install
- [x] SCC validation
- [x] RBAC least-privilege
- [ ] Image scanning / signing
- [ ] Prometheus metrics
- [ ] Audit logging
- [ ] OCP version compatibility
- [ ] Uninstall cleanup
- [x] Security context

> ⚠ Red Hat certification likely requires tests for: Image scanning / signing, Prometheus metrics, Audit logging, OCP version compatibility, Uninstall cleanup
