/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package e2e

import (
	"context"
	"fmt"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	operatorv1alpha1 "github.com/openshift/zero-trust-workload-identity-manager/api/v1alpha1"
	"github.com/openshift/zero-trust-workload-identity-manager/test/e2e/utils"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	storagev1 "k8s.io/api/storage/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	managedByLabelKey   = "app.kubernetes.io/managed-by"
	managedByLabelValue = "zero-trust-workload-identity-manager"
)

var _ = Describe("Resource Conflict Detection", Ordered, func() {
	var testCtx context.Context
	var appDomain string
	var conflictJwtIssuer string

	BeforeAll(func() {
		ctx := context.Background()

		By("Getting cluster base domain for conflict tests")
		baseDomain, err := utils.GetClusterBaseDomain(ctx, configClient)
		Expect(err).NotTo(HaveOccurred(), "failed to get cluster base domain")

		appDomain = fmt.Sprintf("apps.%s", baseDomain)
		conflictJwtIssuer = fmt.Sprintf("https://oidc-discovery.%s", appDomain)

		By("Verifying operator is installed and available")
		utils.WaitForDeploymentAvailable(ctx, clientset, utils.OperatorDeploymentName, utils.OperatorNamespace, utils.ShortTimeout)

		By("Ensuring ZeroTrustWorkloadIdentityManager CR exists")
		ztwim := &operatorv1alpha1.ZeroTrustWorkloadIdentityManager{}
		err = k8sClient.Get(ctx, client.ObjectKey{Name: "cluster"}, ztwim)
		if kerrors.IsNotFound(err) {
			ztwim = &operatorv1alpha1.ZeroTrustWorkloadIdentityManager{
				ObjectMeta: metav1.ObjectMeta{
					Name: "cluster",
				},
				Spec: operatorv1alpha1.ZeroTrustWorkloadIdentityManagerSpec{
					BundleConfigMap: "spire-bundle",
					TrustDomain:     appDomain,
					ClusterName:     "test01",
				},
			}
			Expect(k8sClient.Create(ctx, ztwim)).To(Succeed(), "failed to create ZTWIM CR")
		} else {
			Expect(err).NotTo(HaveOccurred(), "failed to get ZTWIM CR")
		}

		By("Cleaning up any existing operand CRs from prior test suites")
		cleanupOperandCRs(ctx)
	})

	BeforeEach(func() {
		var cancel context.CancelFunc
		testCtx, cancel = context.WithTimeout(context.Background(), utils.TestContextTimeout)
		DeferCleanup(cancel)
	})

	// ─── Journey 1: SpireServer Multi-Resource Conflict Detection & Data Preservation ───

	It("SpireServer multi-resource conflict detection and data preservation", func() {
		By("Creating pre-existing ServiceAccount 'spire-server' with custom labels and annotations (no managed-by label)")
		preExistingSA := &corev1.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "spire-server",
				Namespace: utils.OperatorNamespace,
				Labels: map[string]string{
					"custom-team":  "platform-eng",
					"environment":  "staging",
				},
				Annotations: map[string]string{
					"note": "manually-created-for-testing",
				},
			},
		}
		_, err := clientset.CoreV1().ServiceAccounts(utils.OperatorNamespace).Create(testCtx, preExistingSA, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred(), "failed to create pre-existing ServiceAccount")

		By("Recording ServiceAccount resourceVersion and UID for later comparison")
		createdSA, err := clientset.CoreV1().ServiceAccounts(utils.OperatorNamespace).Get(testCtx, "spire-server", metav1.GetOptions{})
		Expect(err).NotTo(HaveOccurred())
		originalResourceVersion := createdSA.ResourceVersion
		originalUID := createdSA.UID
		fmt.Fprintf(GinkgoWriter, "recorded SA resourceVersion=%s uid=%s\n", originalResourceVersion, originalUID)

		By("Creating pre-existing ConfigMap 'spire-server' with custom data (no managed-by label)")
		preExistingCM := &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "spire-server",
				Namespace: utils.OperatorNamespace,
				Labels:    map[string]string{"custom": "cm"},
			},
			Data: map[string]string{
				"server.conf": "custom-config",
			},
		}
		_, err = clientset.CoreV1().ConfigMaps(utils.OperatorNamespace).Create(testCtx, preExistingCM, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred(), "failed to create pre-existing ConfigMap")

		By("Creating pre-existing ClusterRole 'spire-server' with dummy rules (no managed-by label)")
		preExistingCR := &rbacv1.ClusterRole{
			ObjectMeta: metav1.ObjectMeta{
				Name:   "spire-server",
				Labels: map[string]string{"pre-existing": "true"},
			},
			Rules: []rbacv1.PolicyRule{
				{
					APIGroups: []string{""},
					Resources: []string{"pods"},
					Verbs:     []string{"get"},
				},
			},
		}
		_, err = clientset.RbacV1().ClusterRoles().Create(testCtx, preExistingCR, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred(), "failed to create pre-existing ClusterRole")

		DeferCleanup(func(ctx context.Context) {
			By("Cleaning up Journey 1 resources")
			_ = k8sClient.Delete(ctx, &operatorv1alpha1.SpireServer{ObjectMeta: metav1.ObjectMeta{Name: "cluster"}})
			utils.WaitForResourceGone(ctx, k8sClient, &operatorv1alpha1.SpireServer{ObjectMeta: metav1.ObjectMeta{Name: "cluster"}}, utils.DefaultTimeout)
			_ = clientset.CoreV1().ServiceAccounts(utils.OperatorNamespace).Delete(ctx, "spire-server", metav1.DeleteOptions{})
			_ = clientset.CoreV1().ConfigMaps(utils.OperatorNamespace).Delete(ctx, "spire-server", metav1.DeleteOptions{})
			_ = clientset.RbacV1().ClusterRoles().Delete(ctx, "spire-server", metav1.DeleteOptions{})
		})

		By("Creating SpireServer CR 'cluster' with valid spec")
		spireServer := newSpireServerCR(conflictJwtIssuer, appDomain)
		err = k8sClient.Create(testCtx, spireServer)
		Expect(err).NotTo(HaveOccurred(), "failed to create SpireServer CR")

		By("Waiting for ServiceAccountAvailable condition to show ResourceConflict")
		utils.WaitForSpireServerConditionReason(testCtx, k8sClient, "cluster",
			"ServiceAccountAvailable", metav1.ConditionFalse, operatorv1alpha1.ReasonResourceConflict, utils.DefaultTimeout)

		By("Verifying ServiceAccountAvailable condition message contains resource identifier")
		cr := &operatorv1alpha1.SpireServer{}
		Expect(k8sClient.Get(testCtx, client.ObjectKey{Name: "cluster"}, cr)).To(Succeed())
		saCond := utils.GetConditionByType(cr.Status.Conditions, "ServiceAccountAvailable")
		Expect(saCond).NotTo(BeNil())
		Expect(saCond.Message).To(ContainSubstring("spire-server already exists but is not managed by the operator"),
			"condition message should identify the conflicting resource")
		fmt.Fprintf(GinkgoWriter, "ServiceAccountAvailable message: %s\n", saCond.Message)

		By("Asserting ServerConfigMapAvailable condition shows ResourceConflict")
		utils.WaitForSpireServerConditionReason(testCtx, k8sClient, "cluster",
			"ServerConfigMapAvailable", metav1.ConditionFalse, operatorv1alpha1.ReasonResourceConflict, utils.DefaultTimeout)

		By("Asserting RBACAvailable condition shows ResourceConflict")
		utils.WaitForSpireServerConditionReason(testCtx, k8sClient, "cluster",
			"RBACAvailable", metav1.ConditionFalse, operatorv1alpha1.ReasonResourceConflict, utils.DefaultTimeout)

		By("Asserting Ready condition is False (aggregate health degraded)")
		utils.WaitForSpireServerConditions(testCtx, k8sClient, "cluster", map[string]metav1.ConditionStatus{
			"Ready": metav1.ConditionFalse,
		}, utils.DefaultTimeout)

		By("Verifying pre-existing ServiceAccount was NOT modified")
		refetchedSA, err := clientset.CoreV1().ServiceAccounts(utils.OperatorNamespace).Get(testCtx, "spire-server", metav1.GetOptions{})
		Expect(err).NotTo(HaveOccurred())
		Expect(refetchedSA.Labels).To(HaveKeyWithValue("custom-team", "platform-eng"),
			"original label 'custom-team' should be preserved")
		Expect(refetchedSA.Labels).To(HaveKeyWithValue("environment", "staging"),
			"original label 'environment' should be preserved")
		Expect(refetchedSA.Labels).NotTo(HaveKey(managedByLabelKey),
			"managed-by label should NOT have been added by the operator")
		Expect(refetchedSA.Annotations).To(HaveKeyWithValue("note", "manually-created-for-testing"),
			"original annotation should be preserved")
		Expect(refetchedSA.ResourceVersion).To(Equal(originalResourceVersion),
			"resourceVersion should be unchanged — operator must not have written to the SA")
		fmt.Fprintf(GinkgoWriter, "pre-existing SA is untouched: resourceVersion=%s (original=%s)\n",
			refetchedSA.ResourceVersion, originalResourceVersion)

		By("Verifying pre-existing ConfigMap data was NOT overwritten")
		refetchedCM, err := clientset.CoreV1().ConfigMaps(utils.OperatorNamespace).Get(testCtx, "spire-server", metav1.GetOptions{})
		Expect(err).NotTo(HaveOccurred())
		Expect(refetchedCM.Data["server.conf"]).To(Equal("custom-config"),
			"original ConfigMap data should be preserved, not overwritten with operator-generated config")

		By("Verifying RBACAvailable condition message for cluster-scoped resource (no namespace prefix)")
		Expect(k8sClient.Get(testCtx, client.ObjectKey{Name: "cluster"}, cr)).To(Succeed())
		rbacCond := utils.GetConditionByType(cr.Status.Conditions, "RBACAvailable")
		Expect(rbacCond).NotTo(BeNil())
		Expect(rbacCond.Message).To(ContainSubstring("spire-server already exists but is not managed by the operator"),
			"RBAC condition message should reference the conflicting ClusterRole")
		fmt.Fprintf(GinkgoWriter, "RBACAvailable message: %s\n", rbacCond.Message)
	})

	// ─── Journey 2: Cross-Operand Conflict Detection ───

	It("Cross-operand conflict detection on SpireAgent, SpiffeCSIDriver, and OIDC", func() {

		// ── SpireAgent: DaemonSet conflict ──

		By("Creating pre-existing DaemonSet 'spire-agent' (no managed-by label)")
		preExistingDS := &appsv1.DaemonSet{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "spire-agent",
				Namespace: utils.OperatorNamespace,
				Labels:    map[string]string{"pre-existing": "true"},
			},
			Spec: appsv1.DaemonSetSpec{
				Selector: &metav1.LabelSelector{
					MatchLabels: map[string]string{"app": "conflict-test-agent"},
				},
				Template: corev1.PodTemplateSpec{
					ObjectMeta: metav1.ObjectMeta{
						Labels: map[string]string{"app": "conflict-test-agent"},
					},
					Spec: corev1.PodSpec{
						NodeSelector: map[string]string{"non-existent-conflict-test-label": "true"},
						Containers: []corev1.Container{{
							Name:    "busybox",
							Image:   "busybox",
							Command: []string{"sleep", "3600"},
							SecurityContext: &corev1.SecurityContext{
								AllowPrivilegeEscalation: ptr.To(false),
								Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
								RunAsNonRoot:             ptr.To(true),
								RunAsUser:                ptr.To(int64(1000)),
								SeccompProfile:           &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
							},
						}},
					},
				},
			},
		}
		_, err := clientset.AppsV1().DaemonSets(utils.OperatorNamespace).Create(testCtx, preExistingDS, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred(), "failed to create pre-existing DaemonSet")

		By("Creating SpireAgent CR 'cluster'")
		spireAgent := newSpireAgentCR()
		err = k8sClient.Create(testCtx, spireAgent)
		Expect(err).NotTo(HaveOccurred(), "failed to create SpireAgent CR")

		By("Waiting for SpireAgent DaemonSetAvailable to show ResourceConflict")
		utils.WaitForSpireAgentConditionReason(testCtx, k8sClient, "cluster",
			"DaemonSetAvailable", metav1.ConditionFalse, operatorv1alpha1.ReasonResourceConflict, utils.DefaultTimeout)

		By("Cleaning up SpireAgent conflict test resources")
		Expect(k8sClient.Delete(testCtx, &operatorv1alpha1.SpireAgent{ObjectMeta: metav1.ObjectMeta{Name: "cluster"}})).To(Succeed())
		utils.WaitForResourceGone(testCtx, k8sClient, &operatorv1alpha1.SpireAgent{ObjectMeta: metav1.ObjectMeta{Name: "cluster"}}, utils.DefaultTimeout)
		_ = clientset.AppsV1().DaemonSets(utils.OperatorNamespace).Delete(testCtx, "spire-agent", metav1.DeleteOptions{})

		// ── SpiffeCSIDriver: CSIDriver conflict ──

		By("Creating pre-existing CSIDriver 'csi.spiffe.io' (no managed-by label)")
		preExistingCSI := &storagev1.CSIDriver{
			ObjectMeta: metav1.ObjectMeta{
				Name:   "csi.spiffe.io",
				Labels: map[string]string{"pre-existing": "true"},
			},
			Spec: storagev1.CSIDriverSpec{
				AttachRequired: ptr.To(false),
			},
		}
		_, err = clientset.StorageV1().CSIDrivers().Create(testCtx, preExistingCSI, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred(), "failed to create pre-existing CSIDriver")

		By("Creating SpiffeCSIDriver CR 'cluster'")
		spiffeCSIDriver := &operatorv1alpha1.SpiffeCSIDriver{
			ObjectMeta: metav1.ObjectMeta{Name: "cluster"},
			Spec:       operatorv1alpha1.SpiffeCSIDriverSpec{},
		}
		err = k8sClient.Create(testCtx, spiffeCSIDriver)
		Expect(err).NotTo(HaveOccurred(), "failed to create SpiffeCSIDriver CR")

		By("Waiting for SpiffeCSIDriver CSIDriverAvailable to show ResourceConflict")
		utils.WaitForSpiffeCSIDriverConditionReason(testCtx, k8sClient, "cluster",
			"CSIDriverAvailable", metav1.ConditionFalse, operatorv1alpha1.ReasonResourceConflict, utils.DefaultTimeout)

		By("Verifying CSIDriver conflict message references cluster-scoped resource (no namespace prefix)")
		csiCR := &operatorv1alpha1.SpiffeCSIDriver{}
		Expect(k8sClient.Get(testCtx, client.ObjectKey{Name: "cluster"}, csiCR)).To(Succeed())
		csiCond := utils.GetConditionByType(csiCR.Status.Conditions, "CSIDriverAvailable")
		Expect(csiCond).NotTo(BeNil())
		Expect(csiCond.Message).To(ContainSubstring("csi.spiffe.io already exists but is not managed by the operator"),
			"CSIDriver condition message should reference cluster-scoped resource without namespace")
		fmt.Fprintf(GinkgoWriter, "CSIDriverAvailable message: %s\n", csiCond.Message)

		By("Cleaning up SpiffeCSIDriver conflict test resources")
		Expect(k8sClient.Delete(testCtx, &operatorv1alpha1.SpiffeCSIDriver{ObjectMeta: metav1.ObjectMeta{Name: "cluster"}})).To(Succeed())
		utils.WaitForResourceGone(testCtx, k8sClient, &operatorv1alpha1.SpiffeCSIDriver{ObjectMeta: metav1.ObjectMeta{Name: "cluster"}}, utils.DefaultTimeout)
		_ = clientset.StorageV1().CSIDrivers().Delete(testCtx, "csi.spiffe.io", metav1.DeleteOptions{})

		// ── SpireOIDCDiscoveryProvider: Deployment conflict ──

		By("Creating pre-existing Deployment 'spire-spiffe-oidc-discovery-provider' (no managed-by label)")
		preExistingDeploy := &appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "spire-spiffe-oidc-discovery-provider",
				Namespace: utils.OperatorNamespace,
				Labels:    map[string]string{"pre-existing": "true"},
			},
			Spec: appsv1.DeploymentSpec{
				Replicas: ptr.To(int32(1)),
				Selector: &metav1.LabelSelector{
					MatchLabels: map[string]string{"app": "conflict-test-oidc"},
				},
				Template: corev1.PodTemplateSpec{
					ObjectMeta: metav1.ObjectMeta{
						Labels: map[string]string{"app": "conflict-test-oidc"},
					},
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{{
							Name:    "busybox",
							Image:   "busybox",
							Command: []string{"sleep", "3600"},
							SecurityContext: &corev1.SecurityContext{
								AllowPrivilegeEscalation: ptr.To(false),
								Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
								RunAsNonRoot:             ptr.To(true),
								RunAsUser:                ptr.To(int64(1000)),
								SeccompProfile:           &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
							},
						}},
					},
				},
			},
		}
		_, err = clientset.AppsV1().Deployments(utils.OperatorNamespace).Create(testCtx, preExistingDeploy, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred(), "failed to create pre-existing Deployment")

		DeferCleanup(func(ctx context.Context) {
			By("Final cleanup for Journey 2")
			_ = k8sClient.Delete(ctx, &operatorv1alpha1.SpireOIDCDiscoveryProvider{ObjectMeta: metav1.ObjectMeta{Name: "cluster"}})
			utils.WaitForResourceGone(ctx, k8sClient, &operatorv1alpha1.SpireOIDCDiscoveryProvider{ObjectMeta: metav1.ObjectMeta{Name: "cluster"}}, utils.DefaultTimeout)
			_ = clientset.AppsV1().Deployments(utils.OperatorNamespace).Delete(ctx, "spire-spiffe-oidc-discovery-provider", metav1.DeleteOptions{})
		})

		By("Creating SpireOIDCDiscoveryProvider CR 'cluster'")
		oidcProvider := &operatorv1alpha1.SpireOIDCDiscoveryProvider{
			ObjectMeta: metav1.ObjectMeta{Name: "cluster"},
			Spec: operatorv1alpha1.SpireOIDCDiscoveryProviderSpec{
				JwtIssuer: conflictJwtIssuer,
			},
		}
		err = k8sClient.Create(testCtx, oidcProvider)
		Expect(err).NotTo(HaveOccurred(), "failed to create SpireOIDCDiscoveryProvider CR")

		By("Waiting for SpireOIDCDiscoveryProvider DeploymentAvailable to show ResourceConflict")
		utils.WaitForSpireOIDCDiscoveryProviderConditionReason(testCtx, k8sClient, "cluster",
			"DeploymentAvailable", metav1.ConditionFalse, operatorv1alpha1.ReasonResourceConflict, utils.DefaultTimeout)
	})

	// ─── Journey 3: Conflict Lifecycle — Persistence, Requeue & Recovery ───

	It("Conflict lifecycle — persistence across requeues and recovery after removal", func() {
		By("Creating pre-existing ServiceAccount 'spire-server' (no managed-by label)")
		blockingSA := &corev1.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "spire-server",
				Namespace: utils.OperatorNamespace,
				Labels:    map[string]string{"blocking": "true"},
			},
		}
		_, err := clientset.CoreV1().ServiceAccounts(utils.OperatorNamespace).Create(testCtx, blockingSA, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred(), "failed to create blocking ServiceAccount")

		DeferCleanup(func(ctx context.Context) {
			By("Cleaning up Journey 3 resources")
			_ = k8sClient.Delete(ctx, &operatorv1alpha1.SpireServer{ObjectMeta: metav1.ObjectMeta{Name: "cluster"}})
			utils.WaitForResourceGone(ctx, k8sClient, &operatorv1alpha1.SpireServer{ObjectMeta: metav1.ObjectMeta{Name: "cluster"}}, utils.DefaultTimeout)
			_ = clientset.CoreV1().ServiceAccounts(utils.OperatorNamespace).Delete(ctx, "spire-server", metav1.DeleteOptions{})
		})

		By("Creating SpireServer CR 'cluster'")
		spireServer := newSpireServerCR(conflictJwtIssuer, appDomain)
		err = k8sClient.Create(testCtx, spireServer)
		Expect(err).NotTo(HaveOccurred(), "failed to create SpireServer CR")

		By("Waiting for ServiceAccountAvailable to show ResourceConflict")
		utils.WaitForSpireServerConditionReason(testCtx, k8sClient, "cluster",
			"ServiceAccountAvailable", metav1.ConditionFalse, operatorv1alpha1.ReasonResourceConflict, utils.DefaultTimeout)

		By("Waiting 60 seconds to verify conflict persists across reconcile cycles")
		Consistently(func() bool {
			cr := &operatorv1alpha1.SpireServer{}
			if err := k8sClient.Get(testCtx, client.ObjectKey{Name: "cluster"}, cr); err != nil {
				fmt.Fprintf(GinkgoWriter, "failed to get SpireServer: %v\n", err)
				return false
			}
			cond := utils.GetConditionByType(cr.Status.Conditions, "ServiceAccountAvailable")
			if cond == nil {
				return false
			}
			return cond.Status == metav1.ConditionFalse && cond.Reason == operatorv1alpha1.ReasonResourceConflict
		}).WithPolling(utils.ShortInterval).WithTimeout(60 * time.Second).Should(BeTrue(),
			"ResourceConflict condition should persist across reconcile cycles")

		By("Deleting the conflicting ServiceAccount to allow recovery")
		err = clientset.CoreV1().ServiceAccounts(utils.OperatorNamespace).Delete(testCtx, "spire-server", metav1.DeleteOptions{})
		Expect(err).NotTo(HaveOccurred(), "failed to delete blocking ServiceAccount")

		By("Waiting for ServiceAccountAvailable to transition to True (operator recovery)")
		utils.WaitForSpireServerConditionReason(testCtx, k8sClient, "cluster",
			"ServiceAccountAvailable", metav1.ConditionTrue, operatorv1alpha1.ReasonReady, utils.DefaultTimeout)

		By("Verifying the new operator-created SA has the managed-by label")
		recoveredSA, err := clientset.CoreV1().ServiceAccounts(utils.OperatorNamespace).Get(testCtx, "spire-server", metav1.GetOptions{})
		Expect(err).NotTo(HaveOccurred(), "operator should have created a new SA after conflict resolution")
		Expect(recoveredSA.Labels).To(HaveKeyWithValue(managedByLabelKey, managedByLabelValue),
			"operator-created SA should have managed-by label")
		fmt.Fprintf(GinkgoWriter, "recovered SA has managed-by=%s\n", recoveredSA.Labels[managedByLabelKey])
	})

	// ─── Journey 4: Positive Path — No Conflicts & Managed-by Label Verification ───

	It("Positive path — no conflicts and managed-by label verification", func() {
		DeferCleanup(func(ctx context.Context) {
			By("Cleaning up Journey 4 SpireServer CR")
			_ = k8sClient.Delete(ctx, &operatorv1alpha1.SpireServer{ObjectMeta: metav1.ObjectMeta{Name: "cluster"}})
			utils.WaitForResourceGone(ctx, k8sClient, &operatorv1alpha1.SpireServer{ObjectMeta: metav1.ObjectMeta{Name: "cluster"}}, utils.DefaultTimeout)
		})

		By("Ensuring clean namespace — no pre-existing resources with operator resource names")
		_ = clientset.CoreV1().ServiceAccounts(utils.OperatorNamespace).Delete(testCtx, "spire-server", metav1.DeleteOptions{})
		_ = clientset.CoreV1().ConfigMaps(utils.OperatorNamespace).Delete(testCtx, "spire-server", metav1.DeleteOptions{})
		_ = clientset.RbacV1().ClusterRoles().Delete(testCtx, "spire-server", metav1.DeleteOptions{})

		By("Creating SpireServer CR 'cluster' with valid spec")
		spireServer := newSpireServerCR(conflictJwtIssuer, appDomain)
		err := k8sClient.Create(testCtx, spireServer)
		Expect(err).NotTo(HaveOccurred(), "failed to create SpireServer CR")

		By("Waiting for all SpireServer conditions to reach True")
		utils.WaitForSpireServerConditions(testCtx, k8sClient, "cluster", map[string]metav1.ConditionStatus{
			"ServiceAccountAvailable":          metav1.ConditionTrue,
			"ServiceAvailable":                 metav1.ConditionTrue,
			"RBACAvailable":                    metav1.ConditionTrue,
			"ValidatingWebhookAvailable":       metav1.ConditionTrue,
			"ServerConfigMapAvailable":         metav1.ConditionTrue,
			"ControllerManagerConfigAvailable": metav1.ConditionTrue,
			"BundleConfigAvailable":            metav1.ConditionTrue,
			"StatefulSetAvailable":             metav1.ConditionTrue,
			"TTLConfigurationValid":            metav1.ConditionTrue,
			"Ready":                            metav1.ConditionTrue,
		}, utils.DefaultTimeout)

		By("Asserting NO condition on SpireServer has reason=ResourceConflict")
		cr := &operatorv1alpha1.SpireServer{}
		Expect(k8sClient.Get(testCtx, client.ObjectKey{Name: "cluster"}, cr)).To(Succeed())
		for _, cond := range cr.Status.Conditions {
			Expect(cond.Reason).NotTo(Equal(operatorv1alpha1.ReasonResourceConflict),
				"condition '%s' should not have reason ResourceConflict on a clean install", cond.Type)
		}

		By("Verifying managed-by label on operator-created ServiceAccount")
		sa, err := clientset.CoreV1().ServiceAccounts(utils.OperatorNamespace).Get(testCtx, "spire-server", metav1.GetOptions{})
		Expect(err).NotTo(HaveOccurred())
		Expect(sa.Labels).To(HaveKeyWithValue(managedByLabelKey, managedByLabelValue),
			"SA should have managed-by label")

		By("Verifying managed-by label on operator-created ConfigMap")
		cm, err := clientset.CoreV1().ConfigMaps(utils.OperatorNamespace).Get(testCtx, "spire-server", metav1.GetOptions{})
		Expect(err).NotTo(HaveOccurred())
		Expect(cm.Labels).To(HaveKeyWithValue(managedByLabelKey, managedByLabelValue),
			"ConfigMap should have managed-by label")

		By("Verifying managed-by label on operator-created StatefulSet")
		sts, err := clientset.AppsV1().StatefulSets(utils.OperatorNamespace).Get(testCtx, "spire-server", metav1.GetOptions{})
		Expect(err).NotTo(HaveOccurred())
		Expect(sts.Labels).To(HaveKeyWithValue(managedByLabelKey, managedByLabelValue),
			"StatefulSet should have managed-by label")

		By("Verifying managed-by label on operator-created ClusterRole (cluster-scoped)")
		clusterRole, err := clientset.RbacV1().ClusterRoles().Get(testCtx, "spire-server", metav1.GetOptions{})
		Expect(err).NotTo(HaveOccurred())
		Expect(clusterRole.Labels).To(HaveKeyWithValue(managedByLabelKey, managedByLabelValue),
			"ClusterRole should have managed-by label")

		By("Spot-checking label filtering: listing namespaced resources by managed-by label")
		saList, err := clientset.CoreV1().ServiceAccounts(utils.OperatorNamespace).List(testCtx, metav1.ListOptions{
			LabelSelector: fmt.Sprintf("%s=%s", managedByLabelKey, managedByLabelValue),
		})
		Expect(err).NotTo(HaveOccurred())
		Expect(saList.Items).NotTo(BeEmpty(), "label-filtered list should include operator-managed ServiceAccounts")
		fmt.Fprintf(GinkgoWriter, "found %d ServiceAccounts with managed-by label\n", len(saList.Items))

		By("Spot-checking cluster-scoped label filtering")
		crList, err := clientset.RbacV1().ClusterRoles().List(testCtx, metav1.ListOptions{
			LabelSelector: fmt.Sprintf("%s=%s", managedByLabelKey, managedByLabelValue),
		})
		Expect(err).NotTo(HaveOccurred())
		Expect(crList.Items).NotTo(BeEmpty(), "label-filtered list should include operator-managed ClusterRoles")
		fmt.Fprintf(GinkgoWriter, "found %d ClusterRoles with managed-by label\n", len(crList.Items))
	})

	// ─── Journey 5: Conflict Isolation — No Cross-Operand Cascade ───

	It("Conflict isolation — SpireServer conflict does not cascade to other operands", func() {
		By("Creating conflicting ServiceAccount 'spire-server' (no managed-by label)")
		conflictSA := &corev1.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "spire-server",
				Namespace: utils.OperatorNamespace,
				Labels:    map[string]string{"conflict-test": "isolation"},
			},
		}
		_, err := clientset.CoreV1().ServiceAccounts(utils.OperatorNamespace).Create(testCtx, conflictSA, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred(), "failed to create conflicting SA")

		DeferCleanup(func(ctx context.Context) {
			By("Cleaning up Journey 5 resources")
			_ = k8sClient.Delete(ctx, &operatorv1alpha1.SpireOIDCDiscoveryProvider{ObjectMeta: metav1.ObjectMeta{Name: "cluster"}})
			_ = k8sClient.Delete(ctx, &operatorv1alpha1.SpiffeCSIDriver{ObjectMeta: metav1.ObjectMeta{Name: "cluster"}})
			_ = k8sClient.Delete(ctx, &operatorv1alpha1.SpireAgent{ObjectMeta: metav1.ObjectMeta{Name: "cluster"}})
			_ = k8sClient.Delete(ctx, &operatorv1alpha1.SpireServer{ObjectMeta: metav1.ObjectMeta{Name: "cluster"}})
			utils.WaitForResourceGone(ctx, k8sClient, &operatorv1alpha1.SpireServer{ObjectMeta: metav1.ObjectMeta{Name: "cluster"}}, utils.DefaultTimeout)
			utils.WaitForResourceGone(ctx, k8sClient, &operatorv1alpha1.SpireAgent{ObjectMeta: metav1.ObjectMeta{Name: "cluster"}}, utils.DefaultTimeout)
			utils.WaitForResourceGone(ctx, k8sClient, &operatorv1alpha1.SpiffeCSIDriver{ObjectMeta: metav1.ObjectMeta{Name: "cluster"}}, utils.DefaultTimeout)
			utils.WaitForResourceGone(ctx, k8sClient, &operatorv1alpha1.SpireOIDCDiscoveryProvider{ObjectMeta: metav1.ObjectMeta{Name: "cluster"}}, utils.DefaultTimeout)
			_ = clientset.CoreV1().ServiceAccounts(utils.OperatorNamespace).Delete(ctx, "spire-server", metav1.DeleteOptions{})
		})

		By("Creating ALL operand CRs simultaneously")
		spireServer := newSpireServerCR(conflictJwtIssuer, appDomain)
		Expect(k8sClient.Create(testCtx, spireServer)).To(Succeed(), "failed to create SpireServer CR")

		spireAgent := newSpireAgentCR()
		Expect(k8sClient.Create(testCtx, spireAgent)).To(Succeed(), "failed to create SpireAgent CR")

		spiffeCSIDriver := &operatorv1alpha1.SpiffeCSIDriver{
			ObjectMeta: metav1.ObjectMeta{Name: "cluster"},
			Spec:       operatorv1alpha1.SpiffeCSIDriverSpec{},
		}
		Expect(k8sClient.Create(testCtx, spiffeCSIDriver)).To(Succeed(), "failed to create SpiffeCSIDriver CR")

		oidcProvider := &operatorv1alpha1.SpireOIDCDiscoveryProvider{
			ObjectMeta: metav1.ObjectMeta{Name: "cluster"},
			Spec: operatorv1alpha1.SpireOIDCDiscoveryProviderSpec{
				JwtIssuer: conflictJwtIssuer,
			},
		}
		Expect(k8sClient.Create(testCtx, oidcProvider)).To(Succeed(), "failed to create SpireOIDCDiscoveryProvider CR")

		By("SpireServer check: verifying ServiceAccountAvailable shows ResourceConflict")
		utils.WaitForSpireServerConditionReason(testCtx, k8sClient, "cluster",
			"ServiceAccountAvailable", metav1.ConditionFalse, operatorv1alpha1.ReasonResourceConflict, utils.DefaultTimeout)

		By("SpireAgent check: verifying ServiceAccountAvailable is True (no cascaded conflict)")
		utils.WaitForSpireAgentConditions(testCtx, k8sClient, "cluster", map[string]metav1.ConditionStatus{
			"ServiceAccountAvailable": metav1.ConditionTrue,
		}, utils.DefaultTimeout)
		fmt.Fprintf(GinkgoWriter, "SpireAgent ServiceAccountAvailable=True — no cascade from SpireServer conflict\n")

		By("SpiffeCSIDriver check: verifying ServiceAccountAvailable is True (no cascaded conflict)")
		utils.WaitForSpiffeCSIDriverConditions(testCtx, k8sClient, "cluster", map[string]metav1.ConditionStatus{
			"ServiceAccountAvailable": metav1.ConditionTrue,
		}, utils.DefaultTimeout)
		fmt.Fprintf(GinkgoWriter, "SpiffeCSIDriver ServiceAccountAvailable=True — no cascade from SpireServer conflict\n")

		By("SpireOIDCDiscoveryProvider check: verifying ServiceAccountAvailable is True (no cascaded conflict)")
		utils.WaitForSpireOIDCDiscoveryProviderConditions(testCtx, k8sClient, "cluster", map[string]metav1.ConditionStatus{
			"ServiceAccountAvailable": metav1.ConditionTrue,
		}, utils.DefaultTimeout)
		fmt.Fprintf(GinkgoWriter, "SpireOIDCDiscoveryProvider ServiceAccountAvailable=True — no cascade from SpireServer conflict\n")

		By("Verifying SpireAgent does NOT have ResourceConflict on ServiceAccountAvailable")
		agentCR := &operatorv1alpha1.SpireAgent{}
		Expect(k8sClient.Get(testCtx, client.ObjectKey{Name: "cluster"}, agentCR)).To(Succeed())
		agentSACond := utils.GetConditionByType(agentCR.Status.Conditions, "ServiceAccountAvailable")
		Expect(agentSACond).NotTo(BeNil())
		Expect(agentSACond.Reason).NotTo(Equal(operatorv1alpha1.ReasonResourceConflict),
			"SpireAgent should not have ResourceConflict — its SA is 'spire-agent', not 'spire-server'")
	})
})

// ── Helper functions ──

// newSpireServerCR returns a SpireServer CR with a valid spec for conflict tests.
func newSpireServerCR(jwtIssuer, appDomain string) *operatorv1alpha1.SpireServer {
	return &operatorv1alpha1.SpireServer{
		ObjectMeta: metav1.ObjectMeta{
			Name: "cluster",
		},
		Spec: operatorv1alpha1.SpireServerSpec{
			JwtIssuer:           jwtIssuer,
			CAValidity:          metav1.Duration{Duration: 24 * time.Hour},
			DefaultX509Validity: metav1.Duration{Duration: 1 * time.Hour},
			DefaultJWTValidity:  metav1.Duration{Duration: 5 * time.Minute},
			CASubject: operatorv1alpha1.CASubject{
				CommonName:   appDomain,
				Country:      "US",
				Organization: "RH",
			},
			Persistence: operatorv1alpha1.Persistence{
				Size:       "1Gi",
				AccessMode: "ReadWriteOncePod",
			},
			Datastore: operatorv1alpha1.DataStore{
				DatabaseType:     "sqlite3",
				ConnectionString: "/run/spire/data/datastore.sqlite3",
				MaxOpenConns:     100,
				MaxIdleConns:     2,
				ConnMaxLifetime:  3600,
				DisableMigration: "false",
			},
		},
	}
}

// newSpireAgentCR returns a SpireAgent CR with a valid spec for conflict tests.
func newSpireAgentCR() *operatorv1alpha1.SpireAgent {
	return &operatorv1alpha1.SpireAgent{
		ObjectMeta: metav1.ObjectMeta{
			Name: "cluster",
		},
		Spec: operatorv1alpha1.SpireAgentSpec{
			NodeAttestor: &operatorv1alpha1.NodeAttestor{
				K8sPSATEnabled: "true",
			},
			WorkloadAttestors: &operatorv1alpha1.WorkloadAttestors{
				K8sEnabled: "true",
				WorkloadAttestorsVerification: &operatorv1alpha1.WorkloadAttestorsVerification{
					Type: "auto",
				},
			},
		},
	}
}

// cleanupOperandCRs deletes all operand CRs and waits for them to be fully removed.
func cleanupOperandCRs(ctx context.Context) {
	operandCRs := []client.Object{
		&operatorv1alpha1.SpireOIDCDiscoveryProvider{ObjectMeta: metav1.ObjectMeta{Name: "cluster"}},
		&operatorv1alpha1.SpiffeCSIDriver{ObjectMeta: metav1.ObjectMeta{Name: "cluster"}},
		&operatorv1alpha1.SpireAgent{ObjectMeta: metav1.ObjectMeta{Name: "cluster"}},
		&operatorv1alpha1.SpireServer{ObjectMeta: metav1.ObjectMeta{Name: "cluster"}},
	}

	for _, cr := range operandCRs {
		err := k8sClient.Delete(ctx, cr)
		if err != nil && !kerrors.IsNotFound(err) {
			fmt.Fprintf(GinkgoWriter, "warning: failed to delete %T: %v\n", cr, err)
		}
	}

	for _, cr := range operandCRs {
		key := client.ObjectKeyFromObject(cr)
		Eventually(func() bool {
			err := k8sClient.Get(ctx, key, cr)
			return kerrors.IsNotFound(err)
		}).WithTimeout(utils.DefaultTimeout).WithPolling(utils.ShortInterval).Should(BeTrue(),
			"operand CR '%s' should be deleted", key.Name)
	}

	// Clean up any pre-existing conflicting resources from prior test runs
	_ = clientset.CoreV1().ServiceAccounts(utils.OperatorNamespace).Delete(ctx, "spire-server", metav1.DeleteOptions{})
	_ = clientset.CoreV1().ConfigMaps(utils.OperatorNamespace).Delete(ctx, "spire-server", metav1.DeleteOptions{})
	_ = clientset.RbacV1().ClusterRoles().Delete(ctx, "spire-server", metav1.DeleteOptions{})
	_ = clientset.AppsV1().DaemonSets(utils.OperatorNamespace).Delete(ctx, "spire-agent", metav1.DeleteOptions{})
	_ = clientset.StorageV1().CSIDrivers().Delete(ctx, "csi.spiffe.io", metav1.DeleteOptions{})
	_ = clientset.AppsV1().Deployments(utils.OperatorNamespace).Delete(ctx, "spire-spiffe-oidc-discovery-provider", metav1.DeleteOptions{})
}
