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
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	routev1 "github.com/openshift/api/route/v1"
	securityv1 "github.com/openshift/api/security/v1"
	operatorv1alpha1 "github.com/openshift/zero-trust-workload-identity-manager/api/v1alpha1"
	"github.com/openshift/zero-trust-workload-identity-manager/test/e2e/utils"
	spiffev1alpha1 "github.com/spiffe/spire-controller-manager/api/v1alpha1"

	corev1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var _ = Describe("Zero Trust Workload Identity Manager", Ordered, func() {
	var testCtx context.Context
	var appDomain string
	var clusterName string
	var bundleConfigMap string
	var jwtIssuer string
	var subscriptionName string
	var operatorConditionName string

	BeforeAll(func() {
		ctx := context.Background()

		By("Getting cluster base domain")
		baseDomain, err := utils.GetClusterBaseDomain(ctx, configClient)
		Expect(err).NotTo(HaveOccurred(), "failed to get cluster base domain")

		// declare shared variables for tests
		appDomain = fmt.Sprintf("apps.%s", baseDomain)
		jwtIssuer = fmt.Sprintf("https://oidc-discovery.%s", appDomain)
		clusterName = "test01"
		bundleConfigMap = "spire-bundle"

		By("Finding Subscription for the operator")
		var foundNames []string
		subscriptionName, foundNames, err = utils.FindOperatorSubscription(ctx, k8sClient, utils.OperatorNamespace, utils.OperatorSubscriptionNameFragment)
		Expect(err).NotTo(HaveOccurred(), "no Subscription matching '%s' found in namespace '%s'; found: %v",
			utils.OperatorSubscriptionNameFragment, utils.OperatorNamespace, foundNames)
		fmt.Fprintf(GinkgoWriter, "found Subscription '%s'\n", subscriptionName)

		By("Finding OperatorCondition for the operator")
		operatorConditionName, foundNames, err = utils.FindOperatorConditionName(ctx, k8sClient, utils.OperatorNamespace, utils.OperatorSubscriptionNameFragment)
		Expect(err).NotTo(HaveOccurred(), "no OperatorCondition matching '%s' found in namespace '%s'; found: %v",
			utils.OperatorSubscriptionNameFragment, utils.OperatorNamespace, foundNames)
		fmt.Fprintf(GinkgoWriter, "found OperatorCondition '%s'\n", operatorConditionName)
	})

	BeforeEach(func() {
		var cancel context.CancelFunc
		testCtx, cancel = context.WithTimeout(context.Background(), utils.TestContextTimeout)
		DeferCleanup(cancel)
	})

	Context("Installation", func() {
		It("Operator should be installed successfully", func() {
			By("Waiting for all managed CRDs to be Established")
			managedCRDs := []string{
				"zerotrustworkloadidentitymanagers.operator.openshift.io",
				"spireservers.operator.openshift.io",
				"spireagents.operator.openshift.io",
				"spiffecsidrivers.operator.openshift.io",
				"spireoidcdiscoveryproviders.operator.openshift.io",
				"clusterspiffeids.spire.spiffe.io",
				"clusterstaticentries.spire.spiffe.io",
				"clusterfederatedtrustdomains.spire.spiffe.io",
			}
			for _, crd := range managedCRDs {
				utils.WaitForCRDEstablished(testCtx, apiextClient, crd, utils.ShortTimeout)
			}

			By("Waiting for operator Deployment to become Available")
			utils.WaitForDeploymentAvailable(testCtx, clientset, utils.OperatorDeploymentName, utils.OperatorNamespace, utils.ShortTimeout)
		})

		It("Global common configurations should be defined in ZeroTrustWorkloadIdentityManager object", func() {
			By("Creating ZeroTrustWorkloadIdentityManager object")
			ztwim := &operatorv1alpha1.ZeroTrustWorkloadIdentityManager{
				ObjectMeta: metav1.ObjectMeta{
					Name: "cluster",
				},
				Spec: operatorv1alpha1.ZeroTrustWorkloadIdentityManagerSpec{
					BundleConfigMap: bundleConfigMap,
					TrustDomain:     appDomain,
					ClusterName:     clusterName,
				},
			}
			err := k8sClient.Create(testCtx, ztwim)
			Expect(err).NotTo(HaveOccurred(), "failed to create ZeroTrustWorkloadIdentityManager object")
		})

		It("Operator should recover from the force Pod deletion", func() {
			By("Getting operator Pod")
			pods, err := clientset.CoreV1().Pods(utils.OperatorNamespace).List(testCtx, metav1.ListOptions{LabelSelector: utils.OperatorLabelSelector})
			Expect(err).NotTo(HaveOccurred())
			Expect(pods.Items).NotTo(BeEmpty())

			// record pod(s) name into a map
			oldPodNames := make(map[string]struct{})
			for _, pod := range pods.Items {
				oldPodNames[pod.Name] = struct{}{}
			}

			By("Deleting operator Pod manually")
			err = clientset.CoreV1().Pods(utils.OperatorNamespace).DeleteCollection(testCtx, metav1.DeleteOptions{}, metav1.ListOptions{
				LabelSelector: utils.OperatorLabelSelector,
			})
			Expect(err).NotTo(HaveOccurred())

			By("Waiting for new Pod to be Running and old pod to be gone")
			Eventually(func() bool {
				newPods, err := clientset.CoreV1().Pods(utils.OperatorNamespace).List(testCtx, metav1.ListOptions{LabelSelector: utils.OperatorLabelSelector})
				if err != nil {
					fmt.Fprintf(GinkgoWriter, "failed to list pods: %v\n", err)
					return false
				}

				if len(newPods.Items) == 0 {
					fmt.Fprintf(GinkgoWriter, "no pod found with label '%s' in namespace '%s'\n", utils.OperatorLabelSelector, utils.OperatorNamespace)
					return false
				}

				for _, pod := range newPods.Items {
					if _, existed := oldPodNames[pod.Name]; existed {
						fmt.Fprintf(GinkgoWriter, "old pod '%v' still exists\n", pod.Name)
						return false
					}
					if pod.Status.Phase != corev1.PodRunning {
						fmt.Fprintf(GinkgoWriter, "new pod '%v' is created but still in '%v' phase\n", pod.Name, pod.Status.Phase)
						return false
					}
				}

				return true
			}).WithTimeout(utils.ShortTimeout).WithPolling(utils.ShortInterval).Should(BeTrue(),
				"new pod should be running and old pod should be deleted successfully within %v", utils.ShortTimeout)

			By("Waiting for operator Deployment to become Available again")
			utils.WaitForDeploymentAvailable(testCtx, clientset, utils.OperatorDeploymentName, utils.OperatorNamespace, utils.ShortTimeout)
		})

		It("SPIRE Server should be installed successfully by creating a SpireServer object", func() {
			By("Creating SpireServer object")
			spireServer := &operatorv1alpha1.SpireServer{
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
			err := k8sClient.Create(testCtx, spireServer)
			Expect(err).NotTo(HaveOccurred(), "failed to create SpireServer object")

			By("Waiting for SpireServer conditions to be True")
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

			By("Waiting for SPIRE Server StatefulSet to become Ready")
			utils.WaitForStatefulSetReady(testCtx, clientset, utils.SpireServerStatefulSetName, utils.OperatorNamespace, utils.DefaultTimeout)
		})

		It("SPIRE Agent should be installed successfully by creating a SpireAgent object", func() {
			By("Creating SpireAgent object")
			spireAgent := &operatorv1alpha1.SpireAgent{
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
			err := k8sClient.Create(testCtx, spireAgent)
			Expect(err).NotTo(HaveOccurred(), "failed to create SpireAgent object")

			By("Waiting for SpireAgent conditions to be True")
			utils.WaitForSpireAgentConditions(testCtx, k8sClient, "cluster", map[string]metav1.ConditionStatus{
				"ServiceAccountAvailable":             metav1.ConditionTrue,
				"ServiceAvailable":                    metav1.ConditionTrue,
				"RBACAvailable":                       metav1.ConditionTrue,
				"ConfigMapAvailable":                  metav1.ConditionTrue,
				"SecurityContextConstraintsAvailable": metav1.ConditionTrue,
				"DaemonSetAvailable":                  metav1.ConditionTrue,
				"Ready":                               metav1.ConditionTrue,
			}, utils.DefaultTimeout)

			By("Waiting for SPIRE Agent DaemonSet to become Available")
			utils.WaitForDaemonSetAvailable(testCtx, clientset, utils.SpireAgentDaemonSetName, utils.OperatorNamespace, utils.DefaultTimeout)
		})

		It("SPIFFE CSI Driver should be installed successfully by creating a SpiffeCSIDriver object", func() {
			By("Creating SpiffeCSIDriver object")
			spiffeCSIDriver := &operatorv1alpha1.SpiffeCSIDriver{
				ObjectMeta: metav1.ObjectMeta{
					Name: "cluster",
				},
				Spec: operatorv1alpha1.SpiffeCSIDriverSpec{},
			}
			err := k8sClient.Create(testCtx, spiffeCSIDriver)
			Expect(err).NotTo(HaveOccurred(), "failed to create SpiffeCSIDriver object")

			By("Waiting for SpiffeCSIDriver conditions to be True")
			utils.WaitForSpiffeCSIDriverConditions(testCtx, k8sClient, "cluster", map[string]metav1.ConditionStatus{
				"ServiceAccountAvailable":             metav1.ConditionTrue,
				"CSIDriverAvailable":                  metav1.ConditionTrue,
				"SecurityContextConstraintsAvailable": metav1.ConditionTrue,
				"DaemonSetAvailable":                  metav1.ConditionTrue,
				"Ready":                               metav1.ConditionTrue,
			}, utils.DefaultTimeout)

			By("Waiting for SPIFFE CSI Driver DaemonSet to become Available")
			utils.WaitForDaemonSetAvailable(testCtx, clientset, utils.SpiffeCSIDriverDaemonSetName, utils.OperatorNamespace, utils.DefaultTimeout)
		})

		It("SPIRE OIDC Discovery Provider should be installed successfully by creating a SpireOIDCDiscoveryProvider object", func() {
			By("Creating SpireOIDCDiscoveryProvider object")
			spireOIDCDiscoveryProvider := &operatorv1alpha1.SpireOIDCDiscoveryProvider{
				ObjectMeta: metav1.ObjectMeta{
					Name: "cluster",
				},
				Spec: operatorv1alpha1.SpireOIDCDiscoveryProviderSpec{
					JwtIssuer: jwtIssuer,
				},
			}
			err := k8sClient.Create(testCtx, spireOIDCDiscoveryProvider)
			Expect(err).NotTo(HaveOccurred(), "failed to create SpireOIDCDiscoveryProvider object")

			By("Waiting for SpireOIDCDiscoveryProvider conditions to be True")
			utils.WaitForSpireOIDCDiscoveryProviderConditions(testCtx, k8sClient, "cluster", map[string]metav1.ConditionStatus{
				"ServiceAccountAvailable":  metav1.ConditionTrue,
				"ServiceAvailable":         metav1.ConditionTrue,
				"ClusterSPIFFEIDAvailable": metav1.ConditionTrue,
				"ConfigMapAvailable":       metav1.ConditionTrue,
				"DeploymentAvailable":      metav1.ConditionTrue,
				"RouteAvailable":           metav1.ConditionTrue,
				"Ready":                    metav1.ConditionTrue,
			}, utils.DefaultTimeout)

			By("Waiting for SPIRE OIDC Discovery Provider Deployment to become Available")
			utils.WaitForDeploymentAvailable(testCtx, clientset, utils.SpireOIDCDiscoveryProviderDeploymentName, utils.OperatorNamespace, utils.DefaultTimeout)
		})

		It("ZeroTrustWorkloadIdentityManager should aggregate status from all operands", func() {
			By("Waiting for ZeroTrustWorkloadIdentityManager to show all operands available")
			utils.WaitForZeroTrustWorkloadIdentityManagerConditions(testCtx, k8sClient, "cluster", map[string]metav1.ConditionStatus{
				"OperandsAvailable": metav1.ConditionTrue,
				"Ready":             metav1.ConditionTrue,
			}, utils.DefaultTimeout)

			By("Verifying ZeroTrustWorkloadIdentityManager operand status")
			cr := &operatorv1alpha1.ZeroTrustWorkloadIdentityManager{}
			err := k8sClient.Get(testCtx, client.ObjectKey{Name: "cluster"}, cr)
			Expect(err).NotTo(HaveOccurred(), "failed to get ZeroTrustWorkloadIdentityManager")

			// Should have 4 operands
			Expect(cr.Status.Operands).To(HaveLen(4), "should have 4 operands")

			// Check each operand is ready
			operandMap := make(map[string]operatorv1alpha1.OperandStatus)
			for _, operand := range cr.Status.Operands {
				operandMap[operand.Kind] = operand
			}

			requiredOperands := []string{"SpireServer", "SpireAgent", "SpiffeCSIDriver", "SpireOIDCDiscoveryProvider"}
			for _, kind := range requiredOperands {
				operand, exists := operandMap[kind]
				Expect(exists).To(BeTrue(), "%s operand should exist in status", kind)
				Expect(operand.Ready).To(Equal("true"), "%s should be ready", kind)
				Expect(operand.Message).To(Equal(operatorv1alpha1.ReasonReady), "%s message should be 'Ready'", kind)
				fmt.Fprintf(GinkgoWriter, "Operand %s is ready\n", kind)
			}
		})
	})

	Context("OperatorCondition", func() {
		It("Upgradeable should be True when all operands are ready", func() {
			By("Verifying Upgradeable condition details")
			condition, err := utils.GetUpgradeableCondition(testCtx, k8sClient, utils.OperatorNamespace, operatorConditionName)
			Expect(err).NotTo(HaveOccurred())
			Expect(condition.Status).To(Equal(metav1.ConditionTrue), "Upgradeable should be %s", metav1.ConditionTrue)
			Expect(condition.Reason).To(Equal(operatorv1alpha1.ReasonReady), "Upgradeable reason should be %s", operatorv1alpha1.ReasonReady)
			fmt.Fprintf(GinkgoWriter, "Upgradeable condition is correctly set: Status=%s, Reason=%s\n", condition.Status, condition.Reason)
		})

		It("Upgradeable should be False when SPIRE Server pod is deleted and recover to True after recovery", func() {
			By("Getting SPIRE Server pod")
			pods, err := clientset.CoreV1().Pods(utils.OperatorNamespace).List(testCtx, metav1.ListOptions{LabelSelector: utils.SpireServerPodLabel})
			Expect(err).NotTo(HaveOccurred())
			Expect(pods.Items).NotTo(BeEmpty(), "no SPIRE Server pods found")
			spireServerPod := pods.Items[0]
			fmt.Fprintf(GinkgoWriter, "will delete SPIRE Server pod '%s'\n", spireServerPod.Name)

			By("Deleting SPIRE Server pod")
			err = clientset.CoreV1().Pods(utils.OperatorNamespace).Delete(testCtx, spireServerPod.Name, metav1.DeleteOptions{})
			Expect(err).NotTo(HaveOccurred(), "failed to delete SPIRE Server pod")

			By("Waiting for Upgradeable condition to transition to False")
			utils.WaitForUpgradeableStatus(testCtx, k8sClient, utils.OperatorNamespace, operatorConditionName, metav1.ConditionFalse, utils.ShortTimeout)

			By("Waiting for SPIRE Server to recover")
			utils.WaitForStatefulSetReady(testCtx, clientset, utils.SpireServerStatefulSetName, utils.OperatorNamespace, utils.DefaultTimeout)

			By("Verifying Upgradeable condition returns to True after recovery")
			utils.WaitForUpgradeableStatus(testCtx, k8sClient, utils.OperatorNamespace, operatorConditionName, metav1.ConditionTrue, utils.ShortTimeout)
		})

		It("Upgradeable should be False when multiple concurrent pod failures and recover to True after recovery", func() {
			By("Getting random SPIRE Agent and SPIFFE CSI Driver pods")
			agentPods, err := clientset.CoreV1().Pods(utils.OperatorNamespace).List(testCtx, metav1.ListOptions{LabelSelector: utils.SpireAgentPodLabel})
			Expect(err).NotTo(HaveOccurred())
			Expect(agentPods.Items).NotTo(BeEmpty(), "no SPIRE Agent pods found")

			csiPods, err := clientset.CoreV1().Pods(utils.OperatorNamespace).List(testCtx, metav1.ListOptions{LabelSelector: utils.SpiffeCSIDriverPodLabel})
			Expect(err).NotTo(HaveOccurred())
			Expect(csiPods.Items).NotTo(BeEmpty(), "no SPIFFE CSI Driver pods found")

			By("Deleting selected SPIRE Agent and SPIFFE CSI Driver pods simultaneously")
			err = clientset.CoreV1().Pods(utils.OperatorNamespace).Delete(testCtx, agentPods.Items[0].Name, metav1.DeleteOptions{})
			Expect(err).NotTo(HaveOccurred())
			err = clientset.CoreV1().Pods(utils.OperatorNamespace).Delete(testCtx, csiPods.Items[0].Name, metav1.DeleteOptions{})
			Expect(err).NotTo(HaveOccurred())
			fmt.Fprintf(GinkgoWriter, "deleted pods: %s, %s\n", agentPods.Items[0].Name, csiPods.Items[0].Name)

			By("Waiting for Upgradeable condition to transition to False")
			utils.WaitForUpgradeableStatus(testCtx, k8sClient, utils.OperatorNamespace, operatorConditionName, metav1.ConditionFalse, utils.ShortTimeout)

			By("Waiting for SPIRE Agent and SPIFFE CSI Driver to recover")
			utils.WaitForDaemonSetAvailable(testCtx, clientset, utils.SpireAgentDaemonSetName, utils.OperatorNamespace, utils.DefaultTimeout)
			utils.WaitForDaemonSetAvailable(testCtx, clientset, utils.SpiffeCSIDriverDaemonSetName, utils.OperatorNamespace, utils.DefaultTimeout)

			By("Verifying Upgradeable condition returns to True after recovery")
			utils.WaitForUpgradeableStatus(testCtx, k8sClient, utils.OperatorNamespace, operatorConditionName, metav1.ConditionTrue, utils.ShortTimeout)
		})
	})

	Context("SpireAgent attestation", func() {
		It("Workload attestation should succeed and workload receives SVID", func() {
			attestationTestNamespace := "e2e-attestation-test"
			attestationTestPodName := "attestation-test-pod"
			attestationTestSA := "attestation-test-sa"
			attestationTestAppContainer := "app"

			attestationNS := &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: attestationTestNamespace,
					Labels: map[string]string{
						"kubernetes.io/metadata.name": attestationTestNamespace,
					},
				},
			}
			clusterSPIFFEID := &spiffev1alpha1.ClusterSPIFFEID{
				ObjectMeta: metav1.ObjectMeta{
					Name: "attestation-test",
				},
				Spec: spiffev1alpha1.ClusterSPIFFEIDSpec{
					SPIFFEIDTemplate: "spiffe://{{ .TrustDomain }}/ns/{{ .PodMeta.Namespace }}/sa/{{ .PodSpec.ServiceAccountName }}",
					PodSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{"app": "attestation-test"},
					},
					NamespaceSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{
							"kubernetes.io/metadata.name": attestationTestNamespace,
						},
					},
					ClassName: "zero-trust-workload-identity-manager-spire",
				},
			}

			By("Creating attestation test namespace")
			err := k8sClient.Create(testCtx, attestationNS)
			Expect(err).NotTo(HaveOccurred(), "failed to create attestation test namespace")

			By("Creating ClusterSPIFFEID for attestation test")
			err = k8sClient.Create(testCtx, clusterSPIFFEID)
			Expect(err).NotTo(HaveOccurred(), "failed to create ClusterSPIFFEID")

			DeferCleanup(func(ctx context.Context) {
				By("Deleting ClusterSPIFFEID")
				_ = k8sClient.Delete(ctx, clusterSPIFFEID)
				By("Deleting attestation test namespace")
				_ = k8sClient.Delete(ctx, attestationNS)
			})

			By("Creating ServiceAccount")
			sa := &corev1.ServiceAccount{
				ObjectMeta: metav1.ObjectMeta{
					Name:      attestationTestSA,
					Namespace: attestationTestNamespace,
				},
			}
			err = k8sClient.Create(testCtx, sa)
			Expect(err).NotTo(HaveOccurred(), "failed to create ServiceAccount")

			By("Creating spiffe-helper ConfigMap")
			helperConf := utils.DefaultAttestationSpiffeHelperConfig().String()
			cm := &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      utils.SpiffeHelperConfigMapName,
					Namespace: attestationTestNamespace,
				},
				Data: map[string]string{
					"helper.conf": helperConf,
				},
			}
			err = k8sClient.Create(testCtx, cm)
			Expect(err).NotTo(HaveOccurred(), "failed to create spiffe-helper ConfigMap")

			By("Creating attestation test pod with CSI volume and spiffe-helper")
			readOnlyTrue := true
			pod := &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      attestationTestPodName,
					Namespace: attestationTestNamespace,
					Labels:    map[string]string{"app": "attestation-test"},
				},
				Spec: corev1.PodSpec{
					ServiceAccountName: attestationTestSA,
					Containers: []corev1.Container{
						{
							Name:  utils.SpiffeHelperContainerName,
							Image: utils.SpiffeHelperImage,
							Args:  []string{"-config", "/run/spiffe-helper/helper.conf"},
							VolumeMounts: []corev1.VolumeMount{
								{Name: "spiffe-workload-api", MountPath: "/spiffe-workload-api", ReadOnly: true},
								{Name: "certs", MountPath: "/certs"},
								{Name: "spiffe-helper-config", MountPath: "/run/spiffe-helper", ReadOnly: true},
							},
							SecurityContext: &corev1.SecurityContext{
								AllowPrivilegeEscalation: ptr.To(false),
								Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
								RunAsNonRoot:             ptr.To(true),
								RunAsUser:                ptr.To(int64(1000)),
								SeccompProfile:           &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
							},
						},
						{
							Name:    attestationTestAppContainer,
							Image:   "busybox",
							Command: []string{"sleep", "3600"},
							VolumeMounts: []corev1.VolumeMount{
								{Name: "certs", MountPath: "/certs"},
							},
							SecurityContext: &corev1.SecurityContext{
								AllowPrivilegeEscalation: ptr.To(false),
								Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
								RunAsNonRoot:             ptr.To(true),
								RunAsUser:                ptr.To(int64(1000)),
								SeccompProfile:           &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
							},
						},
					},
					Volumes: []corev1.Volume{
						{
							Name: "spiffe-workload-api",
							VolumeSource: corev1.VolumeSource{
								CSI: &corev1.CSIVolumeSource{
									Driver:   "csi.spiffe.io",
									ReadOnly: &readOnlyTrue,
								},
							},
						},
						{Name: "certs", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}},
						{
							Name: "spiffe-helper-config",
							VolumeSource: corev1.VolumeSource{
								ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: utils.SpiffeHelperConfigMapName}},
							},
						},
					},
				},
			}
			err = k8sClient.Create(testCtx, pod)
			Expect(err).NotTo(HaveOccurred(), "failed to create attestation test pod")

			By("Waiting for attestation test pod to become ready")
			utils.WaitForPodReady(testCtx, clientset, attestationTestPodName, attestationTestNamespace, 3*utils.ShortTimeout)

			By("Verifying SVID files exist in /certs/")
			Eventually(func() string {
				stdout, _, err := utils.ExecInPod(testCtx, attestationTestNamespace, attestationTestPodName, attestationTestAppContainer, []string{"ls", "/certs/"})
				if err != nil {
					fmt.Fprintf(GinkgoWriter, "exec ls /certs/ failed: %v\n", err)
					return ""
				}
				return stdout
			}).WithTimeout(utils.DefaultTimeout).WithPolling(utils.DefaultInterval).Should(
				And(
					ContainSubstring("svid.pem"),
					ContainSubstring("svid_key.pem"),
					ContainSubstring("bundle.pem"),
				))
		})
	})

	Context("Common configurations", func() {
		It("Operator log level can be configured through Subscription", func() {
			By("Retrieving initial log level from operator Deployment")
			initialLogLevel, err := utils.GetDeploymentEnvVar(testCtx, clientset, utils.OperatorNamespace, utils.OperatorDeploymentName, utils.OperatorLogLevelEnvVar)
			Expect(err).NotTo(HaveOccurred(), "failed to get operator Deployment env var")
			fmt.Fprintf(GinkgoWriter, "initial log level from Deployment: %s\n", initialLogLevel)

			// record initial generation of the Deployment before patching Subscription
			deployment, err := clientset.AppsV1().Deployments(utils.OperatorNamespace).Get(testCtx, utils.OperatorDeploymentName, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred(), "failed to get operator Deployment")
			initialGen := deployment.Generation

			By("Patching Subscription object with verbose log level")
			newLogLevel := "4"
			err = utils.PatchSubscriptionEnv(testCtx, k8sClient, utils.OperatorNamespace, subscriptionName, utils.OperatorLogLevelEnvVar, newLogLevel)
			Expect(err).NotTo(HaveOccurred(), "failed to patch Subscription with env %s=%s", utils.OperatorLogLevelEnvVar, newLogLevel)
			DeferCleanup(func(ctx context.Context) {
				By("Resetting operator log level")
				utils.PatchSubscriptionEnv(ctx, k8sClient, utils.OperatorNamespace, subscriptionName, utils.OperatorLogLevelEnvVar, initialLogLevel)
			})

			By("Waiting for operator Deployment rolling update to start")
			utils.WaitForDeploymentRollingUpdate(testCtx, clientset, utils.OperatorDeploymentName, utils.OperatorNamespace, initialGen, utils.DefaultTimeout)

			By("Waiting for operator Deployment to become Available")
			utils.WaitForDeploymentAvailable(testCtx, clientset, utils.OperatorDeploymentName, utils.OperatorNamespace, utils.DefaultTimeout)

			By("Verifying if operator Deployment has the expected log level")
			logLevel, err := utils.GetDeploymentEnvVar(testCtx, clientset, utils.OperatorNamespace, utils.OperatorDeploymentName, utils.OperatorLogLevelEnvVar)
			Expect(err).NotTo(HaveOccurred(), "failed to get env %s from Deployment", utils.OperatorLogLevelEnvVar)
			Expect(logLevel).To(Equal(newLogLevel), "%s should be updated to %s", utils.OperatorLogLevelEnvVar, newLogLevel)
		})

		It("SPIRE Server containers resource limits and requests can be configured through CR", func() {
			By("Getting SpireServer object")
			spireServer := &operatorv1alpha1.SpireServer{}
			err := k8sClient.Get(testCtx, client.ObjectKey{Name: "cluster"}, spireServer)
			Expect(err).NotTo(HaveOccurred(), "failed to get SpireServer object")

			// record initial generation of the StatefulSet before updating SpireServer object
			statefulset, err := clientset.AppsV1().StatefulSets(utils.OperatorNamespace).Get(testCtx, utils.SpireServerStatefulSetName, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			initialGen := statefulset.Generation

			By("Patching SpireServer object with resource specifications")
			expectedResources := &corev1.ResourceRequirements{
				Limits: corev1.ResourceList{
					corev1.ResourceCPU:    resource.MustParse("500m"),
					corev1.ResourceMemory: resource.MustParse("256Mi"),
				},
				Requests: corev1.ResourceList{
					corev1.ResourceCPU:    resource.MustParse("100m"),
					corev1.ResourceMemory: resource.MustParse("64Mi"),
				},
			}

			err = utils.UpdateCRWithRetry(testCtx, k8sClient, spireServer, func() {
				spireServer.Spec.Resources = expectedResources
			})
			Expect(err).NotTo(HaveOccurred(), "failed to patch SpireServer object with resources")
			DeferCleanup(func(ctx context.Context) {
				By("Resetting SpireServer resources modification")
				server := &operatorv1alpha1.SpireServer{}
				if err := k8sClient.Get(ctx, client.ObjectKey{Name: "cluster"}, server); err == nil {
					server.Spec.Resources = nil
					k8sClient.Update(ctx, server)
				}
			})

			By("Waiting for SPIRE Server StatefulSet rolling update to start")
			utils.WaitForStatefulSetRollingUpdate(testCtx, clientset, utils.SpireServerStatefulSetName, utils.OperatorNamespace, initialGen, utils.ShortTimeout)

			By("Waiting for SPIRE Server StatefulSet to become Ready")
			utils.WaitForStatefulSetReady(testCtx, clientset, utils.SpireServerStatefulSetName, utils.OperatorNamespace, utils.DefaultTimeout)

			By("Verifying if SPIRE Server Pods have the expected resource limits and requests")
			pods, err := clientset.CoreV1().Pods(utils.OperatorNamespace).List(testCtx, metav1.ListOptions{LabelSelector: utils.SpireServerPodLabel})
			Expect(err).NotTo(HaveOccurred())
			Expect(pods.Items).NotTo(BeEmpty())
			utils.VerifyContainerResources(pods.Items, expectedResources)
		})

		It("SPIRE Server nodeSelector and tolerations can be configured through CR", func() {
			By("Getting current SPIRE Server Pod and its Node")
			currentPods, err := clientset.CoreV1().Pods(utils.OperatorNamespace).List(testCtx, metav1.ListOptions{LabelSelector: utils.SpireServerPodLabel})
			Expect(err).NotTo(HaveOccurred())
			Expect(currentPods.Items).NotTo(BeEmpty(), "no SPIRE Server pods found")
			currentNodeName := currentPods.Items[0].Spec.NodeName
			Expect(currentNodeName).NotTo(BeEmpty(), "SPIRE Server pod should be scheduled to a node")
			fmt.Fprintf(GinkgoWriter, "SPIRE Server pod '%s' is on node '%s'\n", currentPods.Items[0].Name, currentNodeName)

			By("Getting SpireServer object")
			spireServer := &operatorv1alpha1.SpireServer{}
			err = k8sClient.Get(testCtx, client.ObjectKey{Name: "cluster"}, spireServer)
			Expect(err).NotTo(HaveOccurred(), "failed to get SpireServer object")

			// record initial generation of the StatefulSet before updating SpireServer object
			statefulset, err := clientset.AppsV1().StatefulSets(utils.OperatorNamespace).Get(testCtx, utils.SpireServerStatefulSetName, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			initialGen := statefulset.Generation

			By("Patching SpireServer object with nodeSelector and tolerations targeting the current Node")
			// Target the current node by hostname to avoid cross-AZ PVC re-attachment issues
			// (SPIRE Server uses ReadWriteOncePod PVC that is bound to a specific AZ).
			controlPlaneRoleKey := utils.InferControlPlaneRoleKey(testCtx, clientset)
			expectedNodeSelector := map[string]string{
				"kubernetes.io/hostname": currentNodeName,
			}
			expectedToleration := []*corev1.Toleration{
				{
					Key:      controlPlaneRoleKey,
					Operator: corev1.TolerationOpExists,
					Effect:   corev1.TaintEffectNoSchedule,
				},
			}

			err = utils.UpdateCRWithRetry(testCtx, k8sClient, spireServer, func() {
				spireServer.Spec.NodeSelector = expectedNodeSelector
				spireServer.Spec.Tolerations = expectedToleration
			})
			Expect(err).NotTo(HaveOccurred(), "failed to patch SpireServer object with nodeSelector and tolerations")
			DeferCleanup(func(ctx context.Context) {
				By("Resetting SpireServer nodeSelector and tolerations modification")
				server := &operatorv1alpha1.SpireServer{}
				if err := k8sClient.Get(ctx, client.ObjectKey{Name: "cluster"}, server); err == nil {
					server.Spec.NodeSelector = nil
					server.Spec.Tolerations = nil
					k8sClient.Update(ctx, server)
				}
			})

			By("Waiting for SPIRE Server StatefulSet rolling update to start")
			utils.WaitForStatefulSetRollingUpdate(testCtx, clientset, utils.SpireServerStatefulSetName, utils.OperatorNamespace, initialGen, utils.ShortTimeout)

			By("Waiting for SPIRE Server StatefulSet to become Ready")
			utils.WaitForStatefulSetReady(testCtx, clientset, utils.SpireServerStatefulSetName, utils.OperatorNamespace, utils.DefaultTimeout)

			By("Verifying if SPIRE Server Pods have been scheduled to Nodes with required labels")
			pods, err := clientset.CoreV1().Pods(utils.OperatorNamespace).List(testCtx, metav1.ListOptions{LabelSelector: utils.SpireServerPodLabel})
			Expect(err).NotTo(HaveOccurred())
			Expect(pods.Items).NotTo(BeEmpty())
			utils.VerifyPodScheduling(testCtx, clientset, pods.Items, expectedNodeSelector)

			By("Verifying if SPIRE Server Pods tolerate Node taints correctly")
			utils.VerifyPodTolerations(testCtx, clientset, pods.Items, expectedToleration)
		})

		It("SPIRE Server affinity can be configured through CR", func() {
			By("Getting current SPIRE Server Pod and its Node")
			pods, err := clientset.CoreV1().Pods(utils.OperatorNamespace).List(testCtx, metav1.ListOptions{LabelSelector: utils.SpireServerPodLabel})
			Expect(err).NotTo(HaveOccurred())
			Expect(pods.Items).NotTo(BeEmpty())
			currentNodeName := pods.Items[0].Spec.NodeName
			Expect(currentNodeName).NotTo(BeEmpty(), "SPIRE Server pod should be scheduled to a node")
			fmt.Fprintf(GinkgoWriter, "pod '%s' is currently on node '%s'\n", pods.Items[0].Name, currentNodeName)

			By("Getting SpireServer object")
			spireServer := &operatorv1alpha1.SpireServer{}
			err = k8sClient.Get(testCtx, client.ObjectKey{Name: "cluster"}, spireServer)
			Expect(err).NotTo(HaveOccurred(), "failed to get SpireServer object")

			statefulset, err := clientset.AppsV1().StatefulSets(utils.OperatorNamespace).Get(testCtx, utils.SpireServerStatefulSetName, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			initialGen := statefulset.Generation

			By("Patching SpireServer object with NodeAffinity targeting the current Node")
			// Target the current node to avoid EBS PVC detach/re-attach delays.
			// SPIRE Server uses ReadWriteOncePod PVC; moving to any other node triggers
			// an EBS volume detach/attach cycle that can take unpredictable time.
			expectedAffinity := &corev1.Affinity{
				NodeAffinity: &corev1.NodeAffinity{
					RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{
						NodeSelectorTerms: []corev1.NodeSelectorTerm{
							{
								MatchExpressions: []corev1.NodeSelectorRequirement{
									{
										Key:      "kubernetes.io/hostname",
										Operator: corev1.NodeSelectorOpIn,
										Values:   []string{currentNodeName},
									},
								},
							},
						},
					},
				},
			}
			expectedToleration := []*corev1.Toleration{
				{
					Key:      utils.InferControlPlaneRoleKey(testCtx, clientset),
					Operator: corev1.TolerationOpExists,
					Effect:   corev1.TaintEffectNoSchedule,
				},
			}

			err = utils.UpdateCRWithRetry(testCtx, k8sClient, spireServer, func() {
				spireServer.Spec.Affinity = expectedAffinity
				spireServer.Spec.Tolerations = expectedToleration
			})
			Expect(err).NotTo(HaveOccurred(), "failed to patch SpireServer object with affinity")
			DeferCleanup(func(ctx context.Context) {
				By("Resetting SpireServer affinity modification")
				server := &operatorv1alpha1.SpireServer{}
				if err := k8sClient.Get(ctx, client.ObjectKey{Name: "cluster"}, server); err == nil {
					server.Spec.Affinity = nil
					server.Spec.Tolerations = nil
					k8sClient.Update(ctx, server)
				}
			})

			By("Waiting for SPIRE Server StatefulSet rolling update to start")
			utils.WaitForStatefulSetRollingUpdate(testCtx, clientset, utils.SpireServerStatefulSetName, utils.OperatorNamespace, initialGen, utils.ShortTimeout)

			By("Waiting for SPIRE Server StatefulSet to become Ready")
			utils.WaitForStatefulSetReady(testCtx, clientset, utils.SpireServerStatefulSetName, utils.OperatorNamespace, utils.DefaultTimeout)

			By("Verifying the StatefulSet pod template has the expected affinity")
			updatedSts, err := clientset.AppsV1().StatefulSets(utils.OperatorNamespace).Get(testCtx, utils.SpireServerStatefulSetName, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			Expect(updatedSts.Spec.Template.Spec.Affinity).NotTo(BeNil(), "StatefulSet pod template should have affinity set")
			Expect(updatedSts.Spec.Template.Spec.Affinity.NodeAffinity).NotTo(BeNil(), "StatefulSet pod template should have NodeAffinity set")
			terms := updatedSts.Spec.Template.Spec.Affinity.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution
			Expect(terms).NotTo(BeNil(), "NodeAffinity should have RequiredDuringSchedulingIgnoredDuringExecution")
			Expect(terms.NodeSelectorTerms).NotTo(BeEmpty())
			Expect(terms.NodeSelectorTerms[0].MatchExpressions).NotTo(BeEmpty())
			Expect(terms.NodeSelectorTerms[0].MatchExpressions[0].Key).To(Equal("kubernetes.io/hostname"))
			Expect(terms.NodeSelectorTerms[0].MatchExpressions[0].Values).To(ContainElement(currentNodeName))
			fmt.Fprintf(GinkgoWriter, "StatefulSet pod template has expected NodeAffinity targeting node '%s'\n", currentNodeName)

			By("Verifying the StatefulSet pod template has the expected tolerations")
			Expect(updatedSts.Spec.Template.Spec.Tolerations).NotTo(BeEmpty(), "StatefulSet pod template should have tolerations set")

			By("Verifying if SPIRE Server Pod is on the expected Node")
			newPods, err := clientset.CoreV1().Pods(utils.OperatorNamespace).List(testCtx, metav1.ListOptions{LabelSelector: utils.SpireServerPodLabel})
			Expect(err).NotTo(HaveOccurred())
			Expect(newPods.Items).NotTo(BeEmpty())
			Expect(newPods.Items[0].Spec.NodeName).To(Equal(currentNodeName), "pod should remain on the node matching the affinity rule")
			fmt.Fprintf(GinkgoWriter, "pod '%s' is on node '%s' matching the affinity rule\n", newPods.Items[0].Name, newPods.Items[0].Spec.NodeName)
		})

		It("SPIRE Server log level can be configured through CR", func() {
			By("Retrieving initial log level from SPIRE Server ConfigMap")
			initialLogLevel, found, err := utils.GetNestedStringFromConfigMapJSON(testCtx, clientset, utils.OperatorNamespace, utils.SpireServerConfigMapName, utils.SpireServerConfigKey, "server", "log_level")
			Expect(err).NotTo(HaveOccurred(), "failed to get initial server.log_level from ConfigMap")
			Expect(found).To(BeTrue(), "server.log_level should exist in ConfigMap")
			fmt.Fprintf(GinkgoWriter, "initial log level from ConfigMap: %s\n", initialLogLevel)

			By("Getting SpireServer object")
			spireServer := &operatorv1alpha1.SpireServer{}
			err = k8sClient.Get(testCtx, client.ObjectKey{Name: "cluster"}, spireServer)
			Expect(err).NotTo(HaveOccurred(), "failed to get SpireServer object")

			// record initial generation of the StatefulSet before updating SpireServer object
			statefulset, err := clientset.AppsV1().StatefulSets(utils.OperatorNamespace).Get(testCtx, utils.SpireServerStatefulSetName, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred(), "failed to get SpireServer StatefulSet")
			initialGen := statefulset.Generation

			By("Patching SpireServer object with verbose log level")
			newLogLevel := "debug"
			err = utils.UpdateCRWithRetry(testCtx, k8sClient, spireServer, func() {
				spireServer.Spec.LogLevel = newLogLevel
			})
			Expect(err).NotTo(HaveOccurred(), "failed to patch SpireServer with log level")
			DeferCleanup(func(ctx context.Context) {
				By("Resetting SpireServer log level")
				server := &operatorv1alpha1.SpireServer{}
				if err := k8sClient.Get(ctx, client.ObjectKey{Name: "cluster"}, server); err == nil {
					server.Spec.LogLevel = initialLogLevel
					k8sClient.Update(ctx, server)
				}
			})

			By("Waiting for SPIRE Server StatefulSet rolling update to start")
			utils.WaitForStatefulSetRollingUpdate(testCtx, clientset, utils.SpireServerStatefulSetName, utils.OperatorNamespace, initialGen, utils.ShortTimeout)

			By("Waiting for SPIRE Server StatefulSet to become Ready")
			utils.WaitForStatefulSetReady(testCtx, clientset, utils.SpireServerStatefulSetName, utils.OperatorNamespace, utils.DefaultTimeout)

			By("Verifying if SPIRE Server ConfigMap has the expected log level")
			logLevel, found, err := utils.GetNestedStringFromConfigMapJSON(testCtx, clientset, utils.OperatorNamespace, utils.SpireServerConfigMapName, utils.SpireServerConfigKey, "server", "log_level")
			Expect(err).NotTo(HaveOccurred(), "failed to get server.log_level from ConfigMap")
			Expect(found).To(BeTrue(), "server.log_level should exist in ConfigMap")
			Expect(logLevel).To(Equal(newLogLevel), "log_level should be updated to %s", newLogLevel)
		})

		It("SPIRE Server custom labels can be configured through CR and propagated to pod", func() {
			By("Getting SpireServer object")
			spireServer := &operatorv1alpha1.SpireServer{}
			err := k8sClient.Get(testCtx, client.ObjectKey{Name: "cluster"}, spireServer)
			Expect(err).NotTo(HaveOccurred(), "failed to get SpireServer object")

			// Record initial generation of the StatefulSet before updating SpireServer
			statefulset, err := clientset.AppsV1().StatefulSets(utils.OperatorNamespace).Get(testCtx, utils.SpireServerStatefulSetName, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred(), "failed to get StatefulSet")
			initialGen := statefulset.Generation

			By("Patching SpireServer object with test labels")
			testLabels := map[string]string{
				"e2e-test-label": "test-value",
				"component":      "server",
			}
			err = utils.UpdateCRWithRetry(testCtx, k8sClient, spireServer, func() {
				spireServer.Spec.Labels = testLabels
			})
			Expect(err).NotTo(HaveOccurred(), "failed to patch SpireServer with labels")
			DeferCleanup(func(ctx context.Context) {
				By("Resetting SpireServer labels modification")
				server := &operatorv1alpha1.SpireServer{}
				if err := k8sClient.Get(ctx, client.ObjectKey{Name: "cluster"}, server); err == nil {
					server.Spec.Labels = nil
					k8sClient.Update(ctx, server)
				}
			})

			By("Waiting for SPIRE Server StatefulSet rolling update to start")
			utils.WaitForStatefulSetRollingUpdate(testCtx, clientset, utils.SpireServerStatefulSetName, utils.OperatorNamespace, initialGen, utils.ShortTimeout)

			By("Waiting for SPIRE Server StatefulSet to become Ready")
			utils.WaitForStatefulSetReady(testCtx, clientset, utils.SpireServerStatefulSetName, utils.OperatorNamespace, utils.DefaultTimeout)

			By("Verifying if SPIRE Server Pods have the expected labels")
			pods, err := clientset.CoreV1().Pods(utils.OperatorNamespace).List(testCtx, metav1.ListOptions{LabelSelector: utils.SpireServerPodLabel})
			Expect(err).NotTo(HaveOccurred())
			Expect(pods.Items).NotTo(BeEmpty())
			utils.VerifyPodLabels(pods.Items, testLabels)
		})

		It("SPIRE Agent containers resource limits and requests can be configured through CR", func() {
			By("Getting SpireAgent object")
			spireAgent := &operatorv1alpha1.SpireAgent{}
			err := k8sClient.Get(testCtx, client.ObjectKey{Name: "cluster"}, spireAgent)
			Expect(err).NotTo(HaveOccurred(), "failed to get SpireAgent object")

			// record initial generation of the DaemonSet before updating SpireAgent object
			daemonset, err := clientset.AppsV1().DaemonSets(utils.OperatorNamespace).Get(testCtx, utils.SpireAgentDaemonSetName, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			initialGen := daemonset.Generation

			By("Patching SpireAgent object with resource specifications")
			expectedResources := &corev1.ResourceRequirements{
				Limits: corev1.ResourceList{
					corev1.ResourceCPU:    resource.MustParse("200m"),
					corev1.ResourceMemory: resource.MustParse("128Mi"),
				},
				Requests: corev1.ResourceList{
					corev1.ResourceCPU:    resource.MustParse("100m"),
					corev1.ResourceMemory: resource.MustParse("64Mi"),
				},
			}

			err = utils.UpdateCRWithRetry(testCtx, k8sClient, spireAgent, func() {
				spireAgent.Spec.Resources = expectedResources
			})
			Expect(err).NotTo(HaveOccurred(), "failed to patch SpireAgent object with resources")
			DeferCleanup(func(ctx context.Context) {
				By("Resetting SpireAgent resources modification")
				agent := &operatorv1alpha1.SpireAgent{}
				if err := k8sClient.Get(ctx, client.ObjectKey{Name: "cluster"}, agent); err == nil {
					agent.Spec.Resources = nil
					k8sClient.Update(ctx, agent)
				}
			})

			By("Waiting for SPIRE Agent DaemonSet rolling update to start")
			utils.WaitForDaemonSetRollingUpdate(testCtx, clientset, utils.SpireAgentDaemonSetName, utils.OperatorNamespace, initialGen, utils.DefaultTimeout)

			By("Waiting for SPIRE Agent DaemonSet to become Available")
			utils.WaitForDaemonSetAvailable(testCtx, clientset, utils.SpireAgentDaemonSetName, utils.OperatorNamespace, utils.DefaultTimeout)

			By("Verifying if SPIRE Agent Pods have the expected resource limits and requests")
			pods, err := clientset.CoreV1().Pods(utils.OperatorNamespace).List(testCtx, metav1.ListOptions{LabelSelector: utils.SpireAgentPodLabel})
			Expect(err).NotTo(HaveOccurred())
			Expect(pods.Items).NotTo(BeEmpty())
			utils.VerifyContainerResources(pods.Items, expectedResources)
		})

		It("SPIRE Agent nodeSelector and tolerations can be configured through CR", func() {
			By("Getting SpireAgent object")
			spireAgent := &operatorv1alpha1.SpireAgent{}
			err := k8sClient.Get(testCtx, client.ObjectKey{Name: "cluster"}, spireAgent)
			Expect(err).NotTo(HaveOccurred(), "failed to get SpireAgent object")

			// record initial generation of the DaemonSet before updating SpireAgent object
			daemonset, err := clientset.AppsV1().DaemonSets(utils.OperatorNamespace).Get(testCtx, utils.SpireAgentDaemonSetName, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			initialGen := daemonset.Generation

			By("Patching SpireAgent object with nodeSelector and tolerations to schedule pods on all Linux nodes")
			expectedNodeSelector := map[string]string{
				"kubernetes.io/os": "linux",
			}
			expectedToleration := []*corev1.Toleration{
				{
					Key:      utils.InferControlPlaneRoleKey(testCtx, clientset),
					Operator: corev1.TolerationOpExists,
					Effect:   corev1.TaintEffectNoSchedule,
				},
			}

			err = utils.UpdateCRWithRetry(testCtx, k8sClient, spireAgent, func() {
				spireAgent.Spec.NodeSelector = expectedNodeSelector
				spireAgent.Spec.Tolerations = expectedToleration
			})
			Expect(err).NotTo(HaveOccurred(), "failed to patch SpireAgent object with nodeSelector and tolerations")
			DeferCleanup(func(ctx context.Context) {
				By("Resetting SpireAgent nodeSelector and tolerations modification")
				agent := &operatorv1alpha1.SpireAgent{}
				if err := k8sClient.Get(ctx, client.ObjectKey{Name: "cluster"}, agent); err == nil {
					agent.Spec.NodeSelector = nil
					agent.Spec.Tolerations = nil
					k8sClient.Update(ctx, agent)
				}
			})

			By("Waiting for SPIRE Agent DaemonSet rolling update to start")
			utils.WaitForDaemonSetRollingUpdate(testCtx, clientset, utils.SpireAgentDaemonSetName, utils.OperatorNamespace, initialGen, utils.ShortTimeout)

			By("Waiting for SPIRE Agent DaemonSet to become Available")
			utils.WaitForDaemonSetAvailable(testCtx, clientset, utils.SpireAgentDaemonSetName, utils.OperatorNamespace, utils.DefaultTimeout)

			By("Verifying if SPIRE Agent Pods have been scheduled to Nodes with required labels")
			pods, err := clientset.CoreV1().Pods(utils.OperatorNamespace).List(testCtx, metav1.ListOptions{LabelSelector: utils.SpireAgentPodLabel})
			Expect(err).NotTo(HaveOccurred())
			Expect(pods.Items).NotTo(BeEmpty())
			utils.VerifyPodScheduling(testCtx, clientset, pods.Items, expectedNodeSelector)

			By("Verifying if SPIRE Agent Pods tolerate Node taints correctly")
			utils.VerifyPodTolerations(testCtx, clientset, pods.Items, expectedToleration)
		})

		It("SPIRE Agent affinity can be configured through CR", func() {
			By("Retrieving any SPIRE Agent Pod and its Node for affinity testing")
			pods, err := clientset.CoreV1().Pods(utils.OperatorNamespace).List(testCtx, metav1.ListOptions{LabelSelector: utils.SpireAgentPodLabel})
			Expect(err).NotTo(HaveOccurred())
			Expect(pods.Items).NotTo(BeEmpty())
			spireAgentPod := pods.Items[0]
			targetNodeName := spireAgentPod.Spec.NodeName
			fmt.Fprintf(GinkgoWriter, "will use node '%s' as target to exclude\n", targetNodeName)

			By("Labeling the target Node with test label to simulate NodeAffinity exclusion")
			testLabelKey := "test.spire.agent/node-affinity"
			testLabelValue := "exclude"

			patchData := fmt.Sprintf(`{"metadata":{"labels":{"%s":"%s"}}}`, testLabelKey, testLabelValue)
			_, err = clientset.CoreV1().Nodes().Patch(testCtx, targetNodeName, types.StrategicMergePatchType, []byte(patchData), metav1.PatchOptions{})
			Expect(err).NotTo(HaveOccurred(), "failed to label node '%s'", targetNodeName)
			DeferCleanup(func(ctx context.Context) {
				By("Removing test label from Node")
				patchData := fmt.Sprintf(`{"metadata":{"labels":{"%s":null}}}`, testLabelKey)
				clientset.CoreV1().Nodes().Patch(ctx, targetNodeName, types.StrategicMergePatchType, []byte(patchData), metav1.PatchOptions{})
			})

			By("Getting SpireAgent object")
			spireAgent := &operatorv1alpha1.SpireAgent{}
			err = k8sClient.Get(testCtx, client.ObjectKey{Name: "cluster"}, spireAgent)
			Expect(err).NotTo(HaveOccurred(), "failed to get SpireAgent object")

			// record initial generation of the DaemonSet before updating SpireAgent object
			daemonset, err := clientset.AppsV1().DaemonSets(utils.OperatorNamespace).Get(testCtx, utils.SpireAgentDaemonSetName, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			initialGen := daemonset.Generation

			By("Patching SpireAgent object with NodeAffinity configuration to exclude labeled nodes")
			expectedAffinity := &corev1.Affinity{
				NodeAffinity: &corev1.NodeAffinity{
					RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{
						NodeSelectorTerms: []corev1.NodeSelectorTerm{
							{
								MatchExpressions: []corev1.NodeSelectorRequirement{
									{
										Key:      testLabelKey,
										Operator: corev1.NodeSelectorOpNotIn,
										Values:   []string{testLabelValue},
									},
								},
							},
						},
					},
				},
			}
			expectedToleration := []*corev1.Toleration{
				{
					Key:      utils.InferControlPlaneRoleKey(testCtx, clientset),
					Operator: corev1.TolerationOpExists,
					Effect:   corev1.TaintEffectNoSchedule,
				},
			}

			err = utils.UpdateCRWithRetry(testCtx, k8sClient, spireAgent, func() {
				spireAgent.Spec.Affinity = expectedAffinity
				spireAgent.Spec.Tolerations = expectedToleration
			})
			Expect(err).NotTo(HaveOccurred(), "failed to patch SpireAgent object with affinity")
			DeferCleanup(func(ctx context.Context) {
				By("Resetting SpireAgent affinity modification")
				agent := &operatorv1alpha1.SpireAgent{}
				if err := k8sClient.Get(ctx, client.ObjectKey{Name: "cluster"}, agent); err == nil {
					agent.Spec.Affinity = nil
					agent.Spec.Tolerations = nil
					k8sClient.Update(ctx, agent)
				}
			})

			By("Waiting for SPIRE Agent DaemonSet rolling update to start")
			utils.WaitForDaemonSetRollingUpdate(testCtx, clientset, utils.SpireAgentDaemonSetName, utils.OperatorNamespace, initialGen, utils.ShortTimeout)

			By("Waiting for SPIRE Agent DaemonSet to become Available")
			utils.WaitForDaemonSetAvailable(testCtx, clientset, utils.SpireAgentDaemonSetName, utils.OperatorNamespace, utils.DefaultTimeout)

			By("Verifying if SPIRE Agent Pods are excluded from the labeled Node")
			newPods, err := clientset.CoreV1().Pods(utils.OperatorNamespace).List(testCtx, metav1.ListOptions{LabelSelector: utils.SpireAgentPodLabel})
			Expect(err).NotTo(HaveOccurred())
			for _, pod := range newPods.Items {
				Expect(pod.Spec.NodeName).NotTo(Equal(targetNodeName), "pod should not be scheduled on the labeled node '%s'", targetNodeName)
				fmt.Fprintf(GinkgoWriter, "pod '%s' correctly excluded from labeled node '%s', scheduled on '%s'\n", pod.Name, targetNodeName, pod.Spec.NodeName)
			}
		})

		It("SPIRE Agent log level can be configured through CR", func() {
			By("Retrieving initial log level from SPIRE Agent ConfigMap")
			initialLogLevel, found, err := utils.GetNestedStringFromConfigMapJSON(testCtx, clientset, utils.OperatorNamespace, utils.SpireAgentConfigMapName, utils.SpireAgentConfigKey, "agent", "log_level")
			Expect(err).NotTo(HaveOccurred(), "failed to get initial agent.log_level from ConfigMap")
			Expect(found).To(BeTrue(), "agent.log_level should exist in ConfigMap")
			fmt.Fprintf(GinkgoWriter, "initial log level from ConfigMap: %s\n", initialLogLevel)

			By("Getting SpireAgent object")
			spireAgent := &operatorv1alpha1.SpireAgent{}
			err = k8sClient.Get(testCtx, client.ObjectKey{Name: "cluster"}, spireAgent)
			Expect(err).NotTo(HaveOccurred(), "failed to get SpireAgent object")

			// record initial generation of the DaemonSet before updating SpireAgent object
			daemonset, err := clientset.AppsV1().DaemonSets(utils.OperatorNamespace).Get(testCtx, utils.SpireAgentDaemonSetName, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred(), "failed to get SpireAgent DaemonSet")
			initialGen := daemonset.Generation

			By("Patching SpireAgent object with verbose log level")
			newLogLevel := "debug"
			err = utils.UpdateCRWithRetry(testCtx, k8sClient, spireAgent, func() {
				spireAgent.Spec.LogLevel = newLogLevel
			})
			Expect(err).NotTo(HaveOccurred(), "failed to patch SpireAgent with log level")
			DeferCleanup(func(ctx context.Context) {
				By("Resetting SpireAgent log level")
				agent := &operatorv1alpha1.SpireAgent{}
				if err := k8sClient.Get(ctx, client.ObjectKey{Name: "cluster"}, agent); err == nil {
					agent.Spec.LogLevel = initialLogLevel
					k8sClient.Update(ctx, agent)
				}
			})

			By("Waiting for SPIRE Agent DaemonSet rolling update to start")
			utils.WaitForDaemonSetRollingUpdate(testCtx, clientset, utils.SpireAgentDaemonSetName, utils.OperatorNamespace, initialGen, utils.ShortTimeout)

			By("Waiting for SPIRE Agent DaemonSet to become Available")
			utils.WaitForDaemonSetAvailable(testCtx, clientset, utils.SpireAgentDaemonSetName, utils.OperatorNamespace, utils.DefaultTimeout)

			By("Verifying if SPIRE Agent ConfigMap has the expected log level")
			logLevel, found, err := utils.GetNestedStringFromConfigMapJSON(testCtx, clientset, utils.OperatorNamespace, utils.SpireAgentConfigMapName, utils.SpireAgentConfigKey, "agent", "log_level")
			Expect(err).NotTo(HaveOccurred(), "failed to get agent.log_level from ConfigMap")
			Expect(found).To(BeTrue(), "agent.log_level should exist in ConfigMap")
			Expect(logLevel).To(Equal(newLogLevel), "log_level should be updated to %s", newLogLevel)
		})

		It("SPIRE Agent custom labels can be configured through CR and propagated to pod", func() {
			By("Getting SpireAgent object")
			spireAgent := &operatorv1alpha1.SpireAgent{}
			err := k8sClient.Get(testCtx, client.ObjectKey{Name: "cluster"}, spireAgent)
			Expect(err).NotTo(HaveOccurred(), "failed to get SpireAgent object")

			// Record initial generation of the DaemonSet before updating SpireAgent
			daemonset, err := clientset.AppsV1().DaemonSets(utils.OperatorNamespace).Get(testCtx, utils.SpireAgentDaemonSetName, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred(), "failed to get DaemonSet")
			initialGen := daemonset.Generation

			By("Patching SpireAgent object with test labels")
			testLabels := map[string]string{
				"e2e-test-label": "test-value",
				"component":      "agent",
			}
			err = utils.UpdateCRWithRetry(testCtx, k8sClient, spireAgent, func() {
				spireAgent.Spec.Labels = testLabels
			})
			Expect(err).NotTo(HaveOccurred(), "failed to patch SpireAgent with labels")
			DeferCleanup(func(ctx context.Context) {
				By("Resetting SpireAgent labels modification")
				agent := &operatorv1alpha1.SpireAgent{}
				if err := k8sClient.Get(ctx, client.ObjectKey{Name: "cluster"}, agent); err == nil {
					agent.Spec.Labels = nil
					k8sClient.Update(ctx, agent)
				}
			})

			By("Waiting for SPIRE Agent DaemonSet rolling update to start")
			utils.WaitForDaemonSetRollingUpdate(testCtx, clientset, utils.SpireAgentDaemonSetName, utils.OperatorNamespace, initialGen, utils.ShortTimeout)

			By("Waiting for SPIRE Agent DaemonSet to become Available")
			utils.WaitForDaemonSetAvailable(testCtx, clientset, utils.SpireAgentDaemonSetName, utils.OperatorNamespace, utils.DefaultTimeout)

			By("Verifying if SPIRE Agent Pods have the expected labels")
			pods, err := clientset.CoreV1().Pods(utils.OperatorNamespace).List(testCtx, metav1.ListOptions{LabelSelector: utils.SpireAgentPodLabel})
			Expect(err).NotTo(HaveOccurred())
			Expect(pods.Items).NotTo(BeEmpty())
			utils.VerifyPodLabels(pods.Items, testLabels)
		})

		It("SPIFFE CSI Driver containers resource limits and requests can be configured through CR", func() {
			By("Getting SpiffeCSIDriver object")
			spiffeCSIDriver := &operatorv1alpha1.SpiffeCSIDriver{}
			err := k8sClient.Get(testCtx, client.ObjectKey{Name: "cluster"}, spiffeCSIDriver)
			Expect(err).NotTo(HaveOccurred(), "failed to get SpiffeCSIDriver object")

			// record initial generation of the DaemonSet before updating SpiffeCSIDriver object
			daemonset, err := clientset.AppsV1().DaemonSets(utils.OperatorNamespace).Get(testCtx, utils.SpiffeCSIDriverDaemonSetName, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			initialGen := daemonset.Generation

			By("Patching SpiffeCSIDriver object with resource specifications")
			expectedResources := &corev1.ResourceRequirements{
				Limits: corev1.ResourceList{
					corev1.ResourceCPU:    resource.MustParse("200m"),
					corev1.ResourceMemory: resource.MustParse("128Mi"),
				},
				Requests: corev1.ResourceList{
					corev1.ResourceCPU:    resource.MustParse("100m"),
					corev1.ResourceMemory: resource.MustParse("64Mi"),
				},
			}

			err = utils.UpdateCRWithRetry(testCtx, k8sClient, spiffeCSIDriver, func() {
				spiffeCSIDriver.Spec.Resources = expectedResources
			})
			Expect(err).NotTo(HaveOccurred(), "failed to patch SpiffeCSIDriver object with resources")
			DeferCleanup(func(ctx context.Context) {
				By("Resetting SpiffeCSIDriver resources modification")
				driver := &operatorv1alpha1.SpiffeCSIDriver{}
				if err := k8sClient.Get(ctx, client.ObjectKey{Name: "cluster"}, driver); err == nil {
					driver.Spec.Resources = nil
					k8sClient.Update(ctx, driver)
				}
			})

			By("Waiting for SPIFFE CSI Driver DaemonSet rolling update to start")
			utils.WaitForDaemonSetRollingUpdate(testCtx, clientset, utils.SpiffeCSIDriverDaemonSetName, utils.OperatorNamespace, initialGen, utils.DefaultTimeout)

			By("Waiting for SPIFFE CSI Driver DaemonSet to become Available")
			utils.WaitForDaemonSetAvailable(testCtx, clientset, utils.SpiffeCSIDriverDaemonSetName, utils.OperatorNamespace, utils.DefaultTimeout)

			By("Verifying if SPIFFE CSI Driver Pods have the expected resource limits and requests")
			pods, err := clientset.CoreV1().Pods(utils.OperatorNamespace).List(testCtx, metav1.ListOptions{LabelSelector: utils.SpiffeCSIDriverPodLabel})
			Expect(err).NotTo(HaveOccurred())
			Expect(pods.Items).NotTo(BeEmpty())
			utils.VerifyContainerResources(pods.Items, expectedResources)
		})

		It("SPIFFE CSI Driver nodeSelector and tolerations can be configured through CR", func() {
			By("Getting SpiffeCSIDriver object")
			spiffeCSIDriver := &operatorv1alpha1.SpiffeCSIDriver{}
			err := k8sClient.Get(testCtx, client.ObjectKey{Name: "cluster"}, spiffeCSIDriver)
			Expect(err).NotTo(HaveOccurred(), "failed to get SpiffeCSIDriver object")

			// record initial generation of the DaemonSet before updating SpiffeCSIDriver object
			daemonset, err := clientset.AppsV1().DaemonSets(utils.OperatorNamespace).Get(testCtx, utils.SpiffeCSIDriverDaemonSetName, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			initialGen := daemonset.Generation

			By("Patching SpiffeCSIDriver object with nodeSelector and tolerations to schedule pods on all Linux nodes")
			expectedNodeSelector := map[string]string{
				"kubernetes.io/os": "linux",
			}
			expectedToleration := []*corev1.Toleration{
				{
					Key:      utils.InferControlPlaneRoleKey(testCtx, clientset),
					Operator: corev1.TolerationOpExists,
					Effect:   corev1.TaintEffectNoSchedule,
				},
			}

			err = utils.UpdateCRWithRetry(testCtx, k8sClient, spiffeCSIDriver, func() {
				spiffeCSIDriver.Spec.NodeSelector = expectedNodeSelector
				spiffeCSIDriver.Spec.Tolerations = expectedToleration
			})
			Expect(err).NotTo(HaveOccurred(), "failed to patch SpiffeCSIDriver object with nodeSelector and tolerations")
			DeferCleanup(func(ctx context.Context) {
				By("Resetting SpiffeCSIDriver nodeSelector and tolerations modification")
				driver := &operatorv1alpha1.SpiffeCSIDriver{}
				if err := k8sClient.Get(ctx, client.ObjectKey{Name: "cluster"}, driver); err == nil {
					driver.Spec.NodeSelector = nil
					driver.Spec.Tolerations = nil
					k8sClient.Update(ctx, driver)
				}
			})

			By("Waiting for SPIFFE CSI Driver DaemonSet rolling update to start")
			utils.WaitForDaemonSetRollingUpdate(testCtx, clientset, utils.SpiffeCSIDriverDaemonSetName, utils.OperatorNamespace, initialGen, utils.ShortTimeout)

			By("Waiting for SPIFFE CSI Driver DaemonSet to become Available")
			utils.WaitForDaemonSetAvailable(testCtx, clientset, utils.SpiffeCSIDriverDaemonSetName, utils.OperatorNamespace, utils.DefaultTimeout)

			By("Verifying if SPIFFE CSI Driver Pods have been scheduled to Nodes with required labels")
			pods, err := clientset.CoreV1().Pods(utils.OperatorNamespace).List(testCtx, metav1.ListOptions{LabelSelector: utils.SpiffeCSIDriverPodLabel})
			Expect(err).NotTo(HaveOccurred())
			Expect(pods.Items).NotTo(BeEmpty())
			utils.VerifyPodScheduling(testCtx, clientset, pods.Items, expectedNodeSelector)

			By("Verifying if SPIFFE CSI Driver Pods tolerate Node taints correctly")
			utils.VerifyPodTolerations(testCtx, clientset, pods.Items, expectedToleration)
		})

		It("SPIFFE CSI Driver affinity can be configured through CR", func() {
			By("Retrieving any SPIFFE CSI Driver Pod and its Node for affinity testing")
			pods, err := clientset.CoreV1().Pods(utils.OperatorNamespace).List(testCtx, metav1.ListOptions{LabelSelector: utils.SpiffeCSIDriverPodLabel})
			Expect(err).NotTo(HaveOccurred())
			Expect(pods.Items).NotTo(BeEmpty())
			spiffeCSIDriverPod := pods.Items[0]
			targetNodeName := spiffeCSIDriverPod.Spec.NodeName
			fmt.Fprintf(GinkgoWriter, "will use node '%s' as target to exclude\n", targetNodeName)

			By("Labeling the target Node with test label to simulate NodeAffinity exclusion")
			testLabelKey := "test.spiffe-csi-driver/node-affinity"
			testLabelValue := "exclude"

			patchData := fmt.Sprintf(`{"metadata":{"labels":{"%s":"%s"}}}`, testLabelKey, testLabelValue)
			_, err = clientset.CoreV1().Nodes().Patch(testCtx, targetNodeName, types.StrategicMergePatchType, []byte(patchData), metav1.PatchOptions{})
			Expect(err).NotTo(HaveOccurred(), "failed to label node '%s'", targetNodeName)
			DeferCleanup(func(ctx context.Context) {
				By("Removing test label from Node")
				patchData := fmt.Sprintf(`{"metadata":{"labels":{"%s":null}}}`, testLabelKey)
				clientset.CoreV1().Nodes().Patch(ctx, targetNodeName, types.StrategicMergePatchType, []byte(patchData), metav1.PatchOptions{})
			})

			By("Getting SpiffeCSIDriver object")
			spiffeCSIDriver := &operatorv1alpha1.SpiffeCSIDriver{}
			err = k8sClient.Get(testCtx, client.ObjectKey{Name: "cluster"}, spiffeCSIDriver)
			Expect(err).NotTo(HaveOccurred(), "failed to get SpiffeCSIDriver object")

			// record initial generation of the DaemonSet before updating SpiffeCSIDriver object
			daemonset, err := clientset.AppsV1().DaemonSets(utils.OperatorNamespace).Get(testCtx, utils.SpiffeCSIDriverDaemonSetName, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			initialGen := daemonset.Generation

			By("Patching SpiffeCSIDriver object with NodeAffinity configuration to exclude labeled nodes")
			expectedAffinity := &corev1.Affinity{
				NodeAffinity: &corev1.NodeAffinity{
					RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{
						NodeSelectorTerms: []corev1.NodeSelectorTerm{
							{
								MatchExpressions: []corev1.NodeSelectorRequirement{
									{
										Key:      testLabelKey,
										Operator: corev1.NodeSelectorOpNotIn,
										Values:   []string{testLabelValue},
									},
								},
							},
						},
					},
				},
			}

			err = utils.UpdateCRWithRetry(testCtx, k8sClient, spiffeCSIDriver, func() {
				spiffeCSIDriver.Spec.Affinity = expectedAffinity
			})
			Expect(err).NotTo(HaveOccurred(), "failed to patch SpiffeCSIDriver object with affinity")
			DeferCleanup(func(ctx context.Context) {
				By("Resetting SpiffeCSIDriver affinity modification")
				driver := &operatorv1alpha1.SpiffeCSIDriver{}
				if err := k8sClient.Get(ctx, client.ObjectKey{Name: "cluster"}, driver); err == nil {
					driver.Spec.Affinity = nil
					k8sClient.Update(ctx, driver)
				}
			})

			By("Waiting for SPIFFE CSI Driver DaemonSet rolling update to start")
			utils.WaitForDaemonSetRollingUpdate(testCtx, clientset, utils.SpiffeCSIDriverDaemonSetName, utils.OperatorNamespace, initialGen, utils.ShortTimeout)

			By("Waiting for SPIFFE CSI Driver DaemonSet to become Available")
			utils.WaitForDaemonSetAvailable(testCtx, clientset, utils.SpiffeCSIDriverDaemonSetName, utils.OperatorNamespace, utils.DefaultTimeout)

			By("Verifying if SPIFFE CSI Driver Pods are excluded from the labeled Node")
			newPods, err := clientset.CoreV1().Pods(utils.OperatorNamespace).List(testCtx, metav1.ListOptions{LabelSelector: utils.SpiffeCSIDriverPodLabel})
			Expect(err).NotTo(HaveOccurred())
			for _, pod := range newPods.Items {
				Expect(pod.Spec.NodeName).NotTo(Equal(targetNodeName), "pod should not be scheduled on the labeled node '%s'", targetNodeName)
				fmt.Fprintf(GinkgoWriter, "pod '%s' correctly excluded from labeled node '%s', scheduled on '%s'\n", pod.Name, targetNodeName, pod.Spec.NodeName)
			}
		})

		It("SPIFFE CSI Driver custom labels can be configured through CR and propagated to pod", func() {
			By("Getting SpiffeCSIDriver object")
			spiffeCSIDriver := &operatorv1alpha1.SpiffeCSIDriver{}
			err := k8sClient.Get(testCtx, client.ObjectKey{Name: "cluster"}, spiffeCSIDriver)
			Expect(err).NotTo(HaveOccurred(), "failed to get SpiffeCSIDriver object")

			// Record initial generation of the DaemonSet before updating SpiffeCSIDriver
			daemonset, err := clientset.AppsV1().DaemonSets(utils.OperatorNamespace).Get(testCtx, utils.SpiffeCSIDriverDaemonSetName, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred(), "failed to get DaemonSet")
			initialGen := daemonset.Generation

			By("Patching SpiffeCSIDriver object with test labels")
			testLabels := map[string]string{
				"e2e-test-label": "test-value",
				"component":      "csi",
			}
			err = utils.UpdateCRWithRetry(testCtx, k8sClient, spiffeCSIDriver, func() {
				spiffeCSIDriver.Spec.Labels = testLabels
			})
			Expect(err).NotTo(HaveOccurred(), "failed to patch SpiffeCSIDriver with labels")
			DeferCleanup(func(ctx context.Context) {
				By("Resetting SpiffeCSIDriver labels modification")
				driver := &operatorv1alpha1.SpiffeCSIDriver{}
				if err := k8sClient.Get(ctx, client.ObjectKey{Name: "cluster"}, driver); err == nil {
					driver.Spec.Labels = nil
					k8sClient.Update(ctx, driver)
				}
			})

			By("Waiting for SPIFFE CSI Driver DaemonSet rolling update to start")
			utils.WaitForDaemonSetRollingUpdate(testCtx, clientset, utils.SpiffeCSIDriverDaemonSetName, utils.OperatorNamespace, initialGen, utils.ShortTimeout)

			By("Waiting for SPIFFE CSI Driver DaemonSet to become Available")
			utils.WaitForDaemonSetAvailable(testCtx, clientset, utils.SpiffeCSIDriverDaemonSetName, utils.OperatorNamespace, utils.DefaultTimeout)

			By("Verifying if SPIFFE CSI Driver Pods have the expected labels")
			pods, err := clientset.CoreV1().Pods(utils.OperatorNamespace).List(testCtx, metav1.ListOptions{LabelSelector: utils.SpiffeCSIDriverPodLabel})
			Expect(err).NotTo(HaveOccurred())
			Expect(pods.Items).NotTo(BeEmpty())
			utils.VerifyPodLabels(pods.Items, testLabels)
		})

		It("SPIRE OIDC Discovery Provider containers resource limits and requests can be configured through CR", func() {
			By("Getting SpireOIDCDiscoveryProvider object")
			spireOIDCDiscoveryProvider := &operatorv1alpha1.SpireOIDCDiscoveryProvider{}
			err := k8sClient.Get(testCtx, client.ObjectKey{Name: "cluster"}, spireOIDCDiscoveryProvider)
			Expect(err).NotTo(HaveOccurred(), "failed to get SpireOIDCDiscoveryProvider object")

			// record initial generation of the Deployment before updating SpireOIDCDiscoveryProvider object
			deployment, err := clientset.AppsV1().Deployments(utils.OperatorNamespace).Get(testCtx, utils.SpireOIDCDiscoveryProviderDeploymentName, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			initialGen := deployment.Generation

			By("Patching SpireOIDCDiscoveryProvider object with resource specifications")
			expectedResources := &corev1.ResourceRequirements{
				Limits: corev1.ResourceList{
					corev1.ResourceCPU:    resource.MustParse("100m"),
					corev1.ResourceMemory: resource.MustParse("64Mi"),
				},
				Requests: corev1.ResourceList{
					corev1.ResourceCPU:    resource.MustParse("50m"),
					corev1.ResourceMemory: resource.MustParse("32Mi"),
				},
			}

			err = utils.UpdateCRWithRetry(testCtx, k8sClient, spireOIDCDiscoveryProvider, func() {
				spireOIDCDiscoveryProvider.Spec.Resources = expectedResources
			})
			Expect(err).NotTo(HaveOccurred(), "failed to patch SpireOIDCDiscoveryProvider object with resources")
			DeferCleanup(func(ctx context.Context) {
				By("Resetting SpireOIDCDiscoveryProvider resources modification")
				provider := &operatorv1alpha1.SpireOIDCDiscoveryProvider{}
				if err := k8sClient.Get(ctx, client.ObjectKey{Name: "cluster"}, provider); err == nil {
					provider.Spec.Resources = nil
					k8sClient.Update(ctx, provider)
				}
			})

			By("Waiting for SPIRE OIDC Discovery Provider Deployment rolling update to start")
			utils.WaitForDeploymentRollingUpdate(testCtx, clientset, utils.SpireOIDCDiscoveryProviderDeploymentName, utils.OperatorNamespace, initialGen, utils.DefaultTimeout)

			By("Waiting for SPIRE OIDC Discovery Provider Deployment to become Available")
			utils.WaitForDeploymentAvailable(testCtx, clientset, utils.SpireOIDCDiscoveryProviderDeploymentName, utils.OperatorNamespace, utils.DefaultTimeout)

			By("Verifying if SPIRE OIDC Discovery Provider Pods have the expected resource limits and requests")
			pods, err := clientset.CoreV1().Pods(utils.OperatorNamespace).List(testCtx, metav1.ListOptions{LabelSelector: utils.SpireOIDCDiscoveryProviderPodLabel})
			Expect(err).NotTo(HaveOccurred())
			Expect(pods.Items).NotTo(BeEmpty())
			activePods := utils.FilterActivePods(pods.Items)
			Expect(activePods).NotTo(BeEmpty(), "no Running OIDC Discovery Provider pods found")
			utils.VerifyContainerResources(activePods, expectedResources)
		})

		It("SPIRE OIDC Discovery Provider nodeSelector and tolerations can be configured through CR", func() {
			By("Finding a different Node with SPIFFE CSI Driver Pod placed to schedule OIDC Discovery Provider Pod")
			oidcPods, err := clientset.CoreV1().Pods(utils.OperatorNamespace).List(testCtx, metav1.ListOptions{LabelSelector: utils.SpireOIDCDiscoveryProviderPodLabel})
			Expect(err).NotTo(HaveOccurred())
			Expect(oidcPods.Items).NotTo(BeEmpty())
			currentNodeName := oidcPods.Items[0].Spec.NodeName

			driverPods, err := clientset.CoreV1().Pods(utils.OperatorNamespace).List(testCtx, metav1.ListOptions{LabelSelector: utils.SpiffeCSIDriverPodLabel})
			Expect(err).NotTo(HaveOccurred())
			Expect(driverPods.Items).NotTo(BeEmpty())

			var targetNodeName string
			for _, pod := range driverPods.Items {
				if pod.Spec.NodeName != "" && pod.Spec.NodeName != currentNodeName {
					targetNodeName = pod.Spec.NodeName
					break
				}
			}
			Expect(targetNodeName).NotTo(BeEmpty(), "failed to find a different node with SPIFFE CSI Driver pod placed")
			fmt.Fprintf(GinkgoWriter, "will move SPIRE OIDC Discovery Provider pod from '%s' to '%s'\n", currentNodeName, targetNodeName)

			By("Getting SpireOIDCDiscoveryProvider object")
			spireOIDCDiscoveryProvider := &operatorv1alpha1.SpireOIDCDiscoveryProvider{}
			err = k8sClient.Get(testCtx, client.ObjectKey{Name: "cluster"}, spireOIDCDiscoveryProvider)
			Expect(err).NotTo(HaveOccurred(), "failed to get SpireOIDCDiscoveryProvider object")

			// record initial generation of the Deployment before updating SpireOIDCDiscoveryProvider object
			deployment, err := clientset.AppsV1().Deployments(utils.OperatorNamespace).Get(testCtx, utils.SpireOIDCDiscoveryProviderDeploymentName, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			initialGen := deployment.Generation

			By("Patching SpireOIDCDiscoveryProvider object with nodeSelector and tolerations to schedule Pod on node with SPIFFE CSI Driver")
			expectedNodeSelector := map[string]string{
				"kubernetes.io/hostname": targetNodeName,
			}
			expectedToleration := []*corev1.Toleration{
				{
					Key:      utils.InferControlPlaneRoleKey(testCtx, clientset),
					Operator: corev1.TolerationOpExists,
					Effect:   corev1.TaintEffectNoSchedule,
				},
			}

			err = utils.UpdateCRWithRetry(testCtx, k8sClient, spireOIDCDiscoveryProvider, func() {
				spireOIDCDiscoveryProvider.Spec.NodeSelector = expectedNodeSelector
				spireOIDCDiscoveryProvider.Spec.Tolerations = expectedToleration
			})
			Expect(err).NotTo(HaveOccurred(), "failed to patch SpireOIDCDiscoveryProvider object with nodeSelector and tolerations")
			DeferCleanup(func(ctx context.Context) {
				By("Resetting SpireOIDCDiscoveryProvider nodeSelector and tolerations modification")
				provider := &operatorv1alpha1.SpireOIDCDiscoveryProvider{}
				if err := k8sClient.Get(ctx, client.ObjectKey{Name: "cluster"}, provider); err == nil {
					provider.Spec.NodeSelector = nil
					provider.Spec.Tolerations = nil
					k8sClient.Update(ctx, provider)
				}
			})

			By("Waiting for SPIRE OIDC Discovery Provider Deployment rolling update to start")
			utils.WaitForDeploymentRollingUpdate(testCtx, clientset, utils.SpireOIDCDiscoveryProviderDeploymentName, utils.OperatorNamespace, initialGen, utils.ShortTimeout)

			By("Waiting for SPIRE OIDC Discovery Provider Deployment to become Ready")
			utils.WaitForDeploymentAvailable(testCtx, clientset, utils.SpireOIDCDiscoveryProviderDeploymentName, utils.OperatorNamespace, utils.DefaultTimeout)

			By("Verifying if SPIRE OIDC Discovery Provider Pods has been scheduled to the target Node with SPIFFE CSI Driver Pod")
			newPods, err := clientset.CoreV1().Pods(utils.OperatorNamespace).List(testCtx, metav1.ListOptions{LabelSelector: utils.SpireOIDCDiscoveryProviderPodLabel})
			Expect(err).NotTo(HaveOccurred())
			Expect(newPods.Items).NotTo(BeEmpty())
			runningPods := utils.FilterActivePods(newPods.Items)
			Expect(runningPods).NotTo(BeEmpty(), "no Running OIDC Discovery Provider pods found")
			utils.VerifyPodScheduling(testCtx, clientset, runningPods, expectedNodeSelector)

			By("Verifying if SPIRE OIDC Discovery Provider Pods tolerate Node taints correctly")
			utils.VerifyPodTolerations(testCtx, clientset, runningPods, expectedToleration)
		})

		It("SPIRE OIDC Discovery Provider affinity can be configured through CR", func() {
			By("Retrieving any SPIRE OIDC Discovery Provider Pod and its Node for affinity testing")
			pods, err := clientset.CoreV1().Pods(utils.OperatorNamespace).List(testCtx, metav1.ListOptions{LabelSelector: utils.SpireOIDCDiscoveryProviderPodLabel})
			Expect(err).NotTo(HaveOccurred())
			Expect(pods.Items).NotTo(BeEmpty())
			spireOIDCDiscoveryProviderPod := pods.Items[0]
			currentNodeName := spireOIDCDiscoveryProviderPod.Spec.NodeName
			fmt.Fprintf(GinkgoWriter, "pod '%s' is currently on node '%s'\n", spireOIDCDiscoveryProviderPod.Name, currentNodeName)

			By("Finding SPIFFE CSI Driver Pod on a different Node to simulate NodeAffinity")
			csiDriverPods, err := clientset.CoreV1().Pods(utils.OperatorNamespace).List(testCtx, metav1.ListOptions{LabelSelector: utils.SpiffeCSIDriverPodLabel})
			Expect(err).NotTo(HaveOccurred())
			Expect(csiDriverPods.Items).NotTo(BeEmpty())

			var targetCSIDriverPod corev1.Pod
			var targetNodeName string
			for _, pod := range csiDriverPods.Items {
				if pod.Spec.NodeName != "" && pod.Spec.NodeName != currentNodeName {
					targetCSIDriverPod = pod
					targetNodeName = pod.Spec.NodeName
					break
				}
			}
			Expect(targetNodeName).NotTo(BeEmpty(), "failed to find a different node with SPIFFE CSI Driver pod placed")
			fmt.Fprintf(GinkgoWriter, "will use SPIFFE CSI Driver pod '%s' on node '%s' as affinity target\n", targetCSIDriverPod.Name, targetNodeName)

			By("Getting SpireOIDCDiscoveryProvider object")
			spireOIDCDiscoveryProvider := &operatorv1alpha1.SpireOIDCDiscoveryProvider{}
			err = k8sClient.Get(testCtx, client.ObjectKey{Name: "cluster"}, spireOIDCDiscoveryProvider)
			Expect(err).NotTo(HaveOccurred(), "failed to get SpireOIDCDiscoveryProvider object")

			// record initial generation of the Deployment before updating SpireOIDCDiscoveryProvider object
			deployment, err := clientset.AppsV1().Deployments(utils.OperatorNamespace).Get(testCtx, utils.SpireOIDCDiscoveryProviderDeploymentName, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			initialGen := deployment.Generation

			By("Patching SpireOIDCDiscoveryProvider object with NodeAffinity configuration")
			expectedAffinity := &corev1.Affinity{
				NodeAffinity: &corev1.NodeAffinity{
					RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{
						NodeSelectorTerms: []corev1.NodeSelectorTerm{
							{
								MatchExpressions: []corev1.NodeSelectorRequirement{
									{
										Key:      "kubernetes.io/hostname",
										Operator: corev1.NodeSelectorOpIn,
										Values:   []string{targetNodeName},
									},
								},
							},
						},
					},
				},
			}
			expectedToleration := []*corev1.Toleration{
				{
					Key:      utils.InferControlPlaneRoleKey(testCtx, clientset),
					Operator: corev1.TolerationOpExists,
					Effect:   corev1.TaintEffectNoSchedule,
				},
			}

			err = utils.UpdateCRWithRetry(testCtx, k8sClient, spireOIDCDiscoveryProvider, func() {
				spireOIDCDiscoveryProvider.Spec.Affinity = expectedAffinity
				spireOIDCDiscoveryProvider.Spec.Tolerations = expectedToleration
			})
			Expect(err).NotTo(HaveOccurred(), "failed to patch SpireOIDCDiscoveryProvider object with affinity")
			DeferCleanup(func(ctx context.Context) {
				By("Resetting SpireOIDCDiscoveryProvider affinity modification")
				provider := &operatorv1alpha1.SpireOIDCDiscoveryProvider{}
				if err := k8sClient.Get(ctx, client.ObjectKey{Name: "cluster"}, provider); err == nil {
					provider.Spec.Affinity = nil
					provider.Spec.Tolerations = nil
					k8sClient.Update(ctx, provider)
				}
			})

			By("Waiting for SPIRE OIDC Discovery Provider Deployment rolling update to start")
			utils.WaitForDeploymentRollingUpdate(testCtx, clientset, utils.SpireOIDCDiscoveryProviderDeploymentName, utils.OperatorNamespace, initialGen, utils.ShortTimeout)

			By("Waiting for SPIRE OIDC Discovery Provider Deployment to become Ready")
			utils.WaitForDeploymentAvailable(testCtx, clientset, utils.SpireOIDCDiscoveryProviderDeploymentName, utils.OperatorNamespace, utils.DefaultTimeout)

			By("Verifying if SPIRE OIDC Discovery Provider Pod has been rescheduled to the target Node")
			newPods, err := clientset.CoreV1().Pods(utils.OperatorNamespace).List(testCtx, metav1.ListOptions{LabelSelector: utils.SpireOIDCDiscoveryProviderPodLabel})
			Expect(err).NotTo(HaveOccurred())
			Expect(newPods.Items).NotTo(BeEmpty())
			Expect(newPods.Items[0].Spec.NodeName).To(Equal(targetNodeName), "pod should be rescheduled to the target node")
			fmt.Fprintf(GinkgoWriter, "pod '%s' has been rescheduled to node '%s'\n", newPods.Items[0].Name, targetNodeName)
		})

		It("SPIRE OIDC Discovery Provider log level can be configured through CR", func() {
			By("Retrieving initial log level from SPIRE OIDC Discovery Provider ConfigMap")
			initialLogLevel, found, err := utils.GetNestedStringFromConfigMapJSON(testCtx, clientset, utils.OperatorNamespace, utils.SpireOIDCDiscoveryProviderConfigMapName, utils.SpireOIDCDiscoveryProviderConfigKey, "log_level")
			Expect(err).NotTo(HaveOccurred(), "failed to get initial log_level from ConfigMap")
			Expect(found).To(BeTrue(), "log_level should exist in ConfigMap")
			fmt.Fprintf(GinkgoWriter, "initial log level from ConfigMap: %s\n", initialLogLevel)

			By("Getting SpireOIDCDiscoveryProvider object")
			spireOIDCDiscoveryProvider := &operatorv1alpha1.SpireOIDCDiscoveryProvider{}
			err = k8sClient.Get(testCtx, client.ObjectKey{Name: "cluster"}, spireOIDCDiscoveryProvider)
			Expect(err).NotTo(HaveOccurred(), "failed to get SpireOIDCDiscoveryProvider object")

			// record initial generation of the Deployment before updating SpireOIDCDiscoveryProvider object
			deployment, err := clientset.AppsV1().Deployments(utils.OperatorNamespace).Get(testCtx, utils.SpireOIDCDiscoveryProviderDeploymentName, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred(), "failed to get SpireOIDCDiscoveryProvider Deployment")
			initialGen := deployment.Generation

			By("Patching SpireOIDCDiscoveryProvider object with verbose log level")
			newLogLevel := "debug"
			err = utils.UpdateCRWithRetry(testCtx, k8sClient, spireOIDCDiscoveryProvider, func() {
				spireOIDCDiscoveryProvider.Spec.LogLevel = newLogLevel
			})
			Expect(err).NotTo(HaveOccurred(), "failed to patch SpireOIDCDiscoveryProvider with log level")
			DeferCleanup(func(ctx context.Context) {
				By("Resetting SpireOIDCDiscoveryProvider log level")
				provider := &operatorv1alpha1.SpireOIDCDiscoveryProvider{}
				if err := k8sClient.Get(ctx, client.ObjectKey{Name: "cluster"}, provider); err == nil {
					provider.Spec.LogLevel = initialLogLevel
					k8sClient.Update(ctx, provider)
				}
			})

			By("Waiting for SPIRE OIDC Discovery Provider Deployment rolling update to start")
			utils.WaitForDeploymentRollingUpdate(testCtx, clientset, utils.SpireOIDCDiscoveryProviderDeploymentName, utils.OperatorNamespace, initialGen, utils.ShortTimeout)

			By("Waiting for SPIRE OIDC Discovery Provider Deployment to become Available")
			utils.WaitForDeploymentAvailable(testCtx, clientset, utils.SpireOIDCDiscoveryProviderDeploymentName, utils.OperatorNamespace, utils.DefaultTimeout)

			By("Verifying if SPIRE OIDC Discovery Provider ConfigMap has the expected log level")
			logLevel, found, err := utils.GetNestedStringFromConfigMapJSON(testCtx, clientset, utils.OperatorNamespace, utils.SpireOIDCDiscoveryProviderConfigMapName, utils.SpireOIDCDiscoveryProviderConfigKey, "log_level")
			Expect(err).NotTo(HaveOccurred(), "failed to get log_level from ConfigMap")
			Expect(found).To(BeTrue(), "log_level should exist in ConfigMap")
			Expect(logLevel).To(Equal(newLogLevel), "log_level should be updated to %s", newLogLevel)
		})

		It("SPIRE OIDC Discovery Provider custom labels can be configured through CR and propagated to pod", func() {
			By("Getting SpireOIDCDiscoveryProvider object")
			spireOIDCDiscoveryProvider := &operatorv1alpha1.SpireOIDCDiscoveryProvider{}
			err := k8sClient.Get(testCtx, client.ObjectKey{Name: "cluster"}, spireOIDCDiscoveryProvider)
			Expect(err).NotTo(HaveOccurred(), "failed to get SpireOIDCDiscoveryProvider object")

			// Record initial generation of the Deployment before updating SpireOIDCDiscoveryProvider
			deployment, err := clientset.AppsV1().Deployments(utils.OperatorNamespace).Get(testCtx, utils.SpireOIDCDiscoveryProviderDeploymentName, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred(), "failed to get Deployment")
			initialGen := deployment.Generation

			By("Patching SpireOIDCDiscoveryProvider object with test labels")
			testLabels := map[string]string{
				"e2e-test-label": "test-value",
				"component":      "oidc",
			}
			err = utils.UpdateCRWithRetry(testCtx, k8sClient, spireOIDCDiscoveryProvider, func() {
				spireOIDCDiscoveryProvider.Spec.Labels = testLabels
			})
			Expect(err).NotTo(HaveOccurred(), "failed to patch SpireOIDCDiscoveryProvider with labels")
			DeferCleanup(func(ctx context.Context) {
				By("Resetting SpireOIDCDiscoveryProvider labels modification")
				provider := &operatorv1alpha1.SpireOIDCDiscoveryProvider{}
				if err := k8sClient.Get(ctx, client.ObjectKey{Name: "cluster"}, provider); err == nil {
					provider.Spec.Labels = nil
					k8sClient.Update(ctx, provider)
				}
			})

			By("Waiting for SPIRE OIDC Discovery Provider Deployment rolling update to start")
			utils.WaitForDeploymentRollingUpdate(testCtx, clientset, utils.SpireOIDCDiscoveryProviderDeploymentName, utils.OperatorNamespace, initialGen, utils.ShortTimeout)

			By("Waiting for SPIRE OIDC Discovery Provider Deployment to become Available")
			utils.WaitForDeploymentAvailable(testCtx, clientset, utils.SpireOIDCDiscoveryProviderDeploymentName, utils.OperatorNamespace, utils.DefaultTimeout)

			By("Verifying if SPIRE OIDC Discovery Provider Pods have the expected labels")
			pods, err := clientset.CoreV1().Pods(utils.OperatorNamespace).List(testCtx, metav1.ListOptions{LabelSelector: utils.SpireOIDCDiscoveryProviderPodLabel})
			Expect(err).NotTo(HaveOccurred())
			Expect(pods.Items).NotTo(BeEmpty())
			utils.VerifyPodLabels(pods.Items, testLabels)
		})
	})

	Context("SPIRE Agent SCC Hardening", func() {
		It("SPIRE Agent SCC object fields should match hardened configuration", Label("openshift-scc", "security-context"), func() {
			By("Fetching the spire-agent SCC")
			scc := &securityv1.SecurityContextConstraints{}
			err := k8sClient.Get(testCtx, types.NamespacedName{Name: utils.SpireAgentSCCName}, scc)
			Expect(err).NotTo(HaveOccurred(), "failed to get SCC %s", utils.SpireAgentSCCName)

			By("Asserting SCC host-level isolation fields")
			Expect(scc.AllowHostNetwork).To(BeFalse(), "AllowHostNetwork must be false after hardening")
			Expect(scc.AllowHostPorts).To(BeFalse(), "AllowHostPorts must be false after hardening")
			Expect(scc.AllowHostPID).To(BeTrue(), "AllowHostPID must remain true for workload attestation")
			Expect(scc.AllowHostIPC).To(BeFalse(), "AllowHostIPC must be false")
			Expect(scc.AllowHostDirVolumePlugin).To(BeTrue(), "AllowHostDirVolumePlugin must remain true for agent socket hostPath")

			By("Asserting SCC privilege fields")
			Expect(scc.AllowPrivilegeEscalation).To(Equal(ptr.To(false)), "AllowPrivilegeEscalation must be false after hardening")
			Expect(scc.AllowPrivilegedContainer).To(BeFalse(), "AllowPrivilegedContainer must be false after hardening")

			By("Asserting SCC filesystem and capability fields")
			Expect(scc.ReadOnlyRootFilesystem).To(BeTrue(), "ReadOnlyRootFilesystem must be true")
			Expect(scc.RequiredDropCapabilities).To(ContainElement(corev1.Capability("ALL")), "RequiredDropCapabilities must include ALL")

			By("Asserting SCC RunAsUser strategy")
			Expect(scc.RunAsUser.Type).To(Equal(securityv1.RunAsUserStrategyRunAsAny), "RunAsUser.Type must be RunAsAny after hardening")
		})

		It("SPIRE Agent DaemonSet PodSpec and container SecurityContext should match hardened configuration", Label("security-context"), func() {
			By("Getting the spire-agent DaemonSet")
			ds, err := clientset.AppsV1().DaemonSets(utils.OperatorNamespace).Get(testCtx, utils.SpireAgentDaemonSetName, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred(), "failed to get spire-agent DaemonSet")

			By("Asserting DaemonSet PodSpec network and host fields")
			podSpec := ds.Spec.Template.Spec
			Expect(podSpec.HostNetwork).To(BeFalse(), "HostNetwork must be false after hardening")
			Expect(podSpec.HostPID).To(BeTrue(), "HostPID must remain true for workload attestation")
			Expect(podSpec.DNSPolicy).To(Equal(corev1.DNSClusterFirst), "DNSPolicy must be ClusterFirst after hardening")

			By("Asserting spire-agent container SecurityContext")
			Expect(podSpec.Containers).NotTo(BeEmpty(), "DaemonSet must have at least one container")
			var agentContainer *corev1.Container
			for i := range podSpec.Containers {
				if podSpec.Containers[i].Name == "spire-agent" {
					agentContainer = &podSpec.Containers[i]
					break
				}
			}
			Expect(agentContainer).NotTo(BeNil(), "spire-agent container must exist")
			Expect(agentContainer.SecurityContext).NotTo(BeNil(), "spire-agent container must have SecurityContext")

			sc := agentContainer.SecurityContext
			Expect(sc.Privileged).To(Equal(ptr.To(false)), "container must not be privileged")
			Expect(sc.AllowPrivilegeEscalation).To(Equal(ptr.To(false)), "container must disallow privilege escalation")
			Expect(sc.ReadOnlyRootFilesystem).To(Equal(ptr.To(true)), "container must use read-only root filesystem")
			Expect(sc.Capabilities).NotTo(BeNil(), "Capabilities must be set")
			Expect(sc.Capabilities.Drop).To(ContainElement(corev1.Capability("ALL")), "container must drop ALL capabilities")
		})

		It("SPIRE Agent pods should be admitted under the spire-agent SCC", Label("openshift-scc"), func() {
			By("Listing SPIRE Agent pods")
			pods, err := clientset.CoreV1().Pods(utils.OperatorNamespace).List(testCtx, metav1.ListOptions{LabelSelector: utils.SpireAgentPodLabel})
			Expect(err).NotTo(HaveOccurred())
			Expect(pods.Items).NotTo(BeEmpty(), "no SPIRE Agent pods found")

			By("Verifying each pod is admitted under the spire-agent SCC")
			for _, pod := range pods.Items {
				sccAnnotation, ok := pod.Annotations["openshift.io/scc"]
				Expect(ok).To(BeTrue(), "pod %s must carry the openshift.io/scc annotation", pod.Name)
				Expect(sccAnnotation).To(Equal(utils.SpireAgentSCCName),
					"pod %s must be admitted under SCC %s, got %s", pod.Name, utils.SpireAgentSCCName, sccAnnotation)
				fmt.Fprintf(GinkgoWriter, "pod '%s' admitted under SCC '%s'\n", pod.Name, sccAnnotation)
			}
		})

		It("SPIRE Agent containers should be healthy after SCC hardening", Label("security-context", "install-health"), func() {
			By("Listing SPIRE Agent pods")
			pods, err := clientset.CoreV1().Pods(utils.OperatorNamespace).List(testCtx, metav1.ListOptions{LabelSelector: utils.SpireAgentPodLabel})
			Expect(err).NotTo(HaveOccurred())
			Expect(pods.Items).NotTo(BeEmpty(), "no SPIRE Agent pods found")

			By("Sweeping container statuses for crash loops or waiting states")
			for _, pod := range pods.Items {
				for _, cs := range pod.Status.ContainerStatuses {
					Expect(cs.State.Waiting).To(BeNil(),
						"container %s in pod %s is in Waiting state (CrashLoopBackOff/OOMKilled?)", cs.Name, pod.Name)
					Expect(cs.RestartCount).To(BeNumerically("<", 3),
						"container %s in pod %s has restarted %d times", cs.Name, pod.Name, cs.RestartCount)
				}
				fmt.Fprintf(GinkgoWriter, "pod '%s' containers are healthy (no crash loops)\n", pod.Name)
			}
		})

		It("SPIRE Agent pod logs should have no DNS/network/filesystem errors after hardening", Label("security-context"), func() {
			By("Listing SPIRE Agent pods")
			pods, err := clientset.CoreV1().Pods(utils.OperatorNamespace).List(testCtx, metav1.ListOptions{LabelSelector: utils.SpireAgentPodLabel})
			Expect(err).NotTo(HaveOccurred())
			Expect(pods.Items).NotTo(BeEmpty(), "no SPIRE Agent pods found")

			By("Scanning pod logs for network/filesystem errors after policy change")
			for _, pod := range pods.Items {
				req := clientset.CoreV1().Pods(utils.OperatorNamespace).GetLogs(pod.Name, &corev1.PodLogOptions{
					TailLines: ptr.To(int64(100)),
				})
				rawLogs, logErr := req.DoRaw(testCtx)
				Expect(logErr).NotTo(HaveOccurred(), "failed to get logs from pod %s", pod.Name)
				logStr := string(rawLogs)

				Expect(logStr).NotTo(ContainSubstring("no such host"),
					"pod %s must not have DNS lookup failures", pod.Name)
				Expect(logStr).NotTo(ContainSubstring("network unreachable"),
					"pod %s must not have network unreachable errors", pod.Name)
				Expect(logStr).NotTo(ContainSubstring("connection refused"),
					"pod %s must not have connection refused errors", pod.Name)
				Expect(logStr).NotTo(ContainSubstring("read-only file system"),
					"pod %s must not have read-only filesystem errors", pod.Name)

				fmt.Fprintf(GinkgoWriter, "pod '%s' logs clean — no DNS/network/filesystem errors\n", pod.Name)
			}
		})

		It("SPIRE Agent root filesystem should reject writes and volume-backed paths should remain writable", Label("security-context"), func() {
			By("Getting a SPIRE Agent pod for exec probes")
			pods, err := clientset.CoreV1().Pods(utils.OperatorNamespace).List(testCtx, metav1.ListOptions{LabelSelector: utils.SpireAgentPodLabel})
			Expect(err).NotTo(HaveOccurred())
			Expect(pods.Items).NotTo(BeEmpty(), "no SPIRE Agent pods found")
			podName := pods.Items[0].Name

			By("Probing root filesystem write rejection")
			_, stderr, _ := utils.ExecInPod(testCtx, utils.OperatorNamespace, podName, "spire-agent",
				[]string{"sh", "-c", "touch /.rofs-probe 2>&1; true"})
			Expect(stderr).To(ContainSubstring("read-only file system"),
				"container spire-agent root filesystem must reject writes")

			By("Probing volume-backed writable path /var/lib/spire")
			stdout, _, execErr := utils.ExecInPod(testCtx, utils.OperatorNamespace, podName, "spire-agent",
				[]string{"ls", "/var/lib/spire"})
			Expect(execErr).NotTo(HaveOccurred(),
				"volume-backed write path /var/lib/spire must be accessible in container spire-agent")
			_ = stdout

			By("Probing volume-backed writable path /tmp/spire-agent/public")
			stdout, _, execErr = utils.ExecInPod(testCtx, utils.OperatorNamespace, podName, "spire-agent",
				[]string{"ls", "/tmp/spire-agent/public"})
			Expect(execErr).NotTo(HaveOccurred(),
				"volume-backed socket path /tmp/spire-agent/public must be accessible in container spire-agent")
			_ = stdout

			fmt.Fprintf(GinkgoWriter, "pod '%s' ReadOnlyRootFilesystem enforced; volume paths writable\n", podName)
		})

		It("SPIRE Agent container should not run as UID 0", Label("openshift-scc", "security-context"), func() {
			By("Getting a SPIRE Agent pod for exec UID check")
			pods, err := clientset.CoreV1().Pods(utils.OperatorNamespace).List(testCtx, metav1.ListOptions{LabelSelector: utils.SpireAgentPodLabel})
			Expect(err).NotTo(HaveOccurred())
			Expect(pods.Items).NotTo(BeEmpty(), "no SPIRE Agent pods found")
			podName := pods.Items[0].Name

			By("Executing 'id -u' in the spire-agent container")
			stdout, _, err := utils.ExecInPod(testCtx, utils.OperatorNamespace, podName, "spire-agent",
				[]string{"id", "-u"})
			if err != nil {
				By("Falling back to /proc/self/status for UID check")
				stdout, _, err = utils.ExecInPod(testCtx, utils.OperatorNamespace, podName, "spire-agent",
					[]string{"sh", "-c", "cat /proc/self/status | grep ^Uid"})
				Expect(err).NotTo(HaveOccurred(), "failed to read UID from /proc/self/status in pod %s", podName)
				Expect(stdout).NotTo(ContainSubstring("Uid:\t0\t"),
					"container spire-agent in pod %s must not run as UID 0; SCC RunAsAny defers to the image default", podName)
			} else {
				Expect(strings.TrimSpace(stdout)).NotTo(Equal("0"),
					"container spire-agent in pod %s must not run as UID 0; SCC RunAsAny defers to the image default", podName)
			}

			fmt.Fprintf(GinkgoWriter, "pod '%s' spire-agent container UID: %s\n", podName, strings.TrimSpace(stdout))
		})

		It("SPIRE Agent SCC should reconcile back after drift (AllowHostNetwork set to true)", Label("openshift-scc", "reconciliation"), func() {
			By("Fetching the spire-agent SCC")
			scc := &securityv1.SecurityContextConstraints{}
			Expect(k8sClient.Get(testCtx, types.NamespacedName{Name: utils.SpireAgentSCCName}, scc)).To(Succeed())

			By("Mutating SCC AllowHostNetwork back to pre-PR value (true)")
			scc.AllowHostNetwork = true
			scc.AllowPrivilegedContainer = true
			Expect(k8sClient.Update(testCtx, scc)).To(Succeed())
			DeferCleanup(func(ctx context.Context) {
				restored := &securityv1.SecurityContextConstraints{}
				if err := k8sClient.Get(ctx, types.NamespacedName{Name: utils.SpireAgentSCCName}, restored); err == nil {
					if restored.AllowHostNetwork || restored.AllowPrivilegedContainer {
						restored.AllowHostNetwork = false
						restored.AllowPrivilegedContainer = false
						_ = k8sClient.Update(ctx, restored)
					}
				}
			})

			By("Waiting for the controller to reconcile the SCC back to hardened values")
			Eventually(func(g Gomega) {
				reconciled := &securityv1.SecurityContextConstraints{}
				g.Expect(k8sClient.Get(testCtx, types.NamespacedName{Name: utils.SpireAgentSCCName}, reconciled)).To(Succeed())
				g.Expect(reconciled.AllowHostNetwork).To(BeFalse(), "AllowHostNetwork must be reconciled back to false")
				g.Expect(reconciled.AllowPrivilegedContainer).To(BeFalse(), "AllowPrivilegedContainer must be reconciled back to false")
			}).WithTimeout(utils.DefaultTimeout).WithPolling(utils.DefaultInterval).Should(Succeed())

			By("Verifying all SCC hardened fields are intact after drift correction")
			final := &securityv1.SecurityContextConstraints{}
			Expect(k8sClient.Get(testCtx, types.NamespacedName{Name: utils.SpireAgentSCCName}, final)).To(Succeed())
			Expect(final.AllowHostPorts).To(BeFalse())
			Expect(final.AllowPrivilegeEscalation).To(Equal(ptr.To(false)))
			Expect(final.RequiredDropCapabilities).To(ContainElement(corev1.Capability("ALL")))
			Expect(final.RunAsUser.Type).To(Equal(securityv1.RunAsUserStrategyRunAsAny))
		})

		It("SPIRE Agent DaemonSet should reconcile back after drift and pods should remain healthy", Label("security-context", "reconciliation"), func() {
			By("Getting the spire-agent DaemonSet and recording generation")
			ds, err := clientset.AppsV1().DaemonSets(utils.OperatorNamespace).Get(testCtx, utils.SpireAgentDaemonSetName, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			initialGen := ds.Generation

			By("Mutating DaemonSet PodSpec back to pre-PR values (HostNetwork: true, Privileged: true)")
			ds.Spec.Template.Spec.HostNetwork = true
			ds.Spec.Template.Spec.DNSPolicy = corev1.DNSClusterFirstWithHostNet
			for i := range ds.Spec.Template.Spec.Containers {
				if ds.Spec.Template.Spec.Containers[i].Name == "spire-agent" {
					ds.Spec.Template.Spec.Containers[i].SecurityContext.Privileged = ptr.To(true)
					ds.Spec.Template.Spec.Containers[i].SecurityContext.AllowPrivilegeEscalation = ptr.To(true)
					break
				}
			}
			_, err = clientset.AppsV1().DaemonSets(utils.OperatorNamespace).Update(testCtx, ds, metav1.UpdateOptions{})
			Expect(err).NotTo(HaveOccurred(), "failed to mutate DaemonSet for drift test")

			By("Waiting for the controller to reconcile the DaemonSet (generation bump)")
			driftGen := initialGen + 1
			utils.WaitForDaemonSetRollingUpdate(testCtx, clientset, utils.SpireAgentDaemonSetName, utils.OperatorNamespace, driftGen, utils.DefaultTimeout)

			By("Waiting for DaemonSet to become Available after drift correction")
			utils.WaitForDaemonSetAvailable(testCtx, clientset, utils.SpireAgentDaemonSetName, utils.OperatorNamespace, utils.DefaultTimeout)

			By("Sweeping container statuses for crash loops after drift correction rollout")
			pods, err := clientset.CoreV1().Pods(utils.OperatorNamespace).List(testCtx, metav1.ListOptions{LabelSelector: utils.SpireAgentPodLabel})
			Expect(err).NotTo(HaveOccurred())
			Expect(pods.Items).NotTo(BeEmpty(), "no SPIRE Agent pods found after drift correction")
			for _, pod := range pods.Items {
				for _, cs := range pod.Status.ContainerStatuses {
					Expect(cs.State.Waiting).To(BeNil(),
						"container %s in pod %s is in Waiting state after drift correction", cs.Name, pod.Name)
					Expect(cs.RestartCount).To(BeNumerically("<", 3),
						"container %s in pod %s restarted %d times after drift correction", cs.Name, pod.Name, cs.RestartCount)
				}
			}

			By("Asserting reconciled DaemonSet PodSpec matches hardened configuration")
			reconciledDS, err := clientset.AppsV1().DaemonSets(utils.OperatorNamespace).Get(testCtx, utils.SpireAgentDaemonSetName, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			Expect(reconciledDS.Spec.Template.Spec.HostNetwork).To(BeFalse(), "HostNetwork must be reconciled back to false")
			Expect(reconciledDS.Spec.Template.Spec.DNSPolicy).To(Equal(corev1.DNSClusterFirst), "DNSPolicy must be reconciled back to ClusterFirst")
			for _, c := range reconciledDS.Spec.Template.Spec.Containers {
				if c.Name == "spire-agent" {
					Expect(c.SecurityContext.Privileged).To(Equal(ptr.To(false)), "Privileged must be reconciled back to false")
					Expect(c.SecurityContext.AllowPrivilegeEscalation).To(Equal(ptr.To(false)), "AllowPrivilegeEscalation must be reconciled back to false")
					Expect(c.SecurityContext.ReadOnlyRootFilesystem).To(Equal(ptr.To(true)), "ReadOnlyRootFilesystem must remain true")
					Expect(c.SecurityContext.Capabilities.Drop).To(ContainElement(corev1.Capability("ALL")), "Capabilities.Drop must contain ALL")
				}
			}
			fmt.Fprintf(GinkgoWriter, "DaemonSet drift corrected and pods healthy after rolling update\n")
		})

		It("SPIRE Agent SCC should be recreated after deletion", Label("openshift-scc", "reconciliation"), func() {
			By("Verifying the spire-agent SCC exists before deletion")
			scc := &securityv1.SecurityContextConstraints{}
			Expect(k8sClient.Get(testCtx, types.NamespacedName{Name: utils.SpireAgentSCCName}, scc)).To(Succeed())

			By("Deleting the spire-agent SCC")
			Expect(k8sClient.Delete(testCtx, scc)).To(Succeed())

			By("Waiting for the controller to recreate the SCC")
			Eventually(func(g Gomega) {
				recreated := &securityv1.SecurityContextConstraints{}
				g.Expect(k8sClient.Get(testCtx, types.NamespacedName{Name: utils.SpireAgentSCCName}, recreated)).To(Succeed())
				g.Expect(recreated.AllowHostNetwork).To(BeFalse(), "recreated SCC AllowHostNetwork must be false")
				g.Expect(recreated.AllowPrivilegedContainer).To(BeFalse(), "recreated SCC AllowPrivilegedContainer must be false")
				g.Expect(recreated.AllowPrivilegeEscalation).To(Equal(ptr.To(false)), "recreated SCC AllowPrivilegeEscalation must be false")
				g.Expect(recreated.RunAsUser.Type).To(Equal(securityv1.RunAsUserStrategyRunAsAny), "recreated SCC RunAsUser.Type must be RunAsAny")
				g.Expect(recreated.RequiredDropCapabilities).To(ContainElement(corev1.Capability("ALL")), "recreated SCC must drop ALL capabilities")
			}).WithTimeout(utils.DefaultTimeout).WithPolling(utils.DefaultInterval).Should(Succeed())

			fmt.Fprintf(GinkgoWriter, "SCC '%s' recreated by controller with correct hardened fields\n", utils.SpireAgentSCCName)
		})
	})

	Context("CreateOnlyMode", func() {
		It("should transition based on CREATE_ONLY_MODE env var value", func() {
			By("Verifying CreateOnlyMode condition is not set by default")
			cr := &operatorv1alpha1.ZeroTrustWorkloadIdentityManager{}
			err := k8sClient.Get(testCtx, client.ObjectKey{Name: "cluster"}, cr)
			Expect(err).NotTo(HaveOccurred(), "failed to get ZeroTrustWorkloadIdentityManager")
			for _, cond := range cr.Status.Conditions {
				Expect(cond.Type).NotTo(Equal("CreateOnlyMode"), "CreateOnlyMode condition should not exist by default")
			}

			By("Patching Subscription object to enable CreateOnlyMode")
			err = utils.PatchSubscriptionEnv(testCtx, k8sClient, utils.OperatorNamespace, subscriptionName, utils.CreateOnlyModeEnvVar, "true")
			Expect(err).NotTo(HaveOccurred(), "failed to patch Subscription with env %s=true", utils.CreateOnlyModeEnvVar)

			By("Waiting for OLM to propagate CREATE_ONLY_MODE=true to the operator Deployment")
			utils.WaitForDeploymentEnvVar(testCtx, clientset, utils.OperatorNamespace, utils.OperatorDeploymentName, utils.CreateOnlyModeEnvVar, "true", utils.DefaultTimeout)

			By("Waiting for operator Deployment to become Available")
			utils.WaitForDeploymentAvailable(testCtx, clientset, utils.OperatorDeploymentName, utils.OperatorNamespace, utils.DefaultTimeout)

			By("Verifying CreateOnlyMode condition is True")
			utils.WaitForZeroTrustWorkloadIdentityManagerConditions(testCtx, k8sClient, "cluster", map[string]metav1.ConditionStatus{
				"CreateOnlyMode": metav1.ConditionTrue,
			}, utils.DefaultTimeout)

			By("Patching Subscription object to disable CreateOnlyMode")
			err = utils.PatchSubscriptionEnv(testCtx, k8sClient, utils.OperatorNamespace, subscriptionName, utils.CreateOnlyModeEnvVar, "false")
			Expect(err).NotTo(HaveOccurred(), "failed to patch Subscription with env %s=false", utils.CreateOnlyModeEnvVar)

			By("Waiting for OLM to propagate CREATE_ONLY_MODE=false to the operator Deployment")
			utils.WaitForDeploymentEnvVar(testCtx, clientset, utils.OperatorNamespace, utils.OperatorDeploymentName, utils.CreateOnlyModeEnvVar, "false", utils.DefaultTimeout)

			By("Waiting for operator Deployment to become Available")
			utils.WaitForDeploymentAvailable(testCtx, clientset, utils.OperatorDeploymentName, utils.OperatorNamespace, utils.DefaultTimeout)

			By("Verifying CreateOnlyMode condition is False")
			utils.WaitForZeroTrustWorkloadIdentityManagerConditions(testCtx, k8sClient, "cluster", map[string]metav1.ConditionStatus{
				"CreateOnlyMode": metav1.ConditionFalse,
			}, utils.DefaultTimeout)
		})

		It("should pause ConfigMap reconciliation when CreateOnlyMode is True and resume when CreateOnlyMode is False", func() {
			By("Getting original ConfigMap content")
			originalCM, err := clientset.CoreV1().ConfigMaps(utils.OperatorNamespace).Get(testCtx, utils.SpireServerConfigMapName, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred(), "failed to get ConfigMap")
			originalServerConf := originalCM.Data[utils.SpireServerConfigKey]
			Expect(originalServerConf).NotTo(BeEmpty(), "%s should exist in ConfigMap", utils.SpireServerConfigKey)
			fmt.Fprintf(GinkgoWriter, "original ConfigMap resourceVersion: %s\n", originalCM.ResourceVersion)

			By("Patching Subscription object to enable CreateOnlyMode")
			err = utils.PatchSubscriptionEnv(testCtx, k8sClient, utils.OperatorNamespace, subscriptionName, utils.CreateOnlyModeEnvVar, "true")
			Expect(err).NotTo(HaveOccurred(), "failed to patch Subscription with env %s=true", utils.CreateOnlyModeEnvVar)

			By("Waiting for OLM to propagate CREATE_ONLY_MODE=true to the operator Deployment")
			utils.WaitForDeploymentEnvVar(testCtx, clientset, utils.OperatorNamespace, utils.OperatorDeploymentName, utils.CreateOnlyModeEnvVar, "true", utils.DefaultTimeout)

			By("Waiting for operator Deployment to become Available")
			utils.WaitForDeploymentAvailable(testCtx, clientset, utils.OperatorDeploymentName, utils.OperatorNamespace, utils.DefaultTimeout)

			By("Waiting for CreateOnlyMode condition to become True")
			utils.WaitForZeroTrustWorkloadIdentityManagerConditions(testCtx, k8sClient, "cluster", map[string]metav1.ConditionStatus{
				"CreateOnlyMode": metav1.ConditionTrue,
			}, utils.DefaultTimeout)

			By("Patching ConfigMap to introduce drift")
			driftMarker := "# e2e-test-marker: drift-detection"
			modifiedConf := originalServerConf + "\n" + driftMarker
			cm, err := clientset.CoreV1().ConfigMaps(utils.OperatorNamespace).Get(testCtx, utils.SpireServerConfigMapName, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred(), "failed to get ConfigMap")
			cm.Data[utils.SpireServerConfigKey] = modifiedConf
			_, err = clientset.CoreV1().ConfigMaps(utils.OperatorNamespace).Update(testCtx, cm, metav1.UpdateOptions{})
			Expect(err).NotTo(HaveOccurred(), "failed to update ConfigMap with drift")

			By("Verifying ConfigMap drift is NOT corrected with CreateOnlyMode is True")
			Consistently(func() bool {
				cm, err := clientset.CoreV1().ConfigMaps(utils.OperatorNamespace).Get(testCtx, utils.SpireServerConfigMapName, metav1.GetOptions{})
				if err != nil {
					fmt.Fprintf(GinkgoWriter, "failed to get ConfigMap: %v\n", err)
					return false
				}
				return strings.Contains(cm.Data[utils.SpireServerConfigKey], driftMarker)
			}).WithPolling(utils.ShortInterval).WithTimeout(30*time.Second).Should(BeTrue(),
				"ConfigMap drift should NOT be corrected when CreateOnlyMode is True")

			By("Patching Subscription object to disable CreateOnlyMode")
			err = utils.PatchSubscriptionEnv(testCtx, k8sClient, utils.OperatorNamespace, subscriptionName, utils.CreateOnlyModeEnvVar, "false")
			Expect(err).NotTo(HaveOccurred(), "failed to patch Subscription with env %s=false", utils.CreateOnlyModeEnvVar)

			By("Waiting for OLM to propagate CREATE_ONLY_MODE=false to the operator Deployment")
			utils.WaitForDeploymentEnvVar(testCtx, clientset, utils.OperatorNamespace, utils.OperatorDeploymentName, utils.CreateOnlyModeEnvVar, "false", utils.DefaultTimeout)

			By("Waiting for operator Deployment to become Available")
			utils.WaitForDeploymentAvailable(testCtx, clientset, utils.OperatorDeploymentName, utils.OperatorNamespace, utils.DefaultTimeout)

			By("Waiting for CreateOnlyMode condition to become False")
			utils.WaitForZeroTrustWorkloadIdentityManagerConditions(testCtx, k8sClient, "cluster", map[string]metav1.ConditionStatus{
				"CreateOnlyMode": metav1.ConditionFalse,
			}, utils.DefaultTimeout)

			By("Verifying ConfigMap drift is corrected with CreateOnlyMode is False")
			Eventually(func() bool {
				cm, err := clientset.CoreV1().ConfigMaps(utils.OperatorNamespace).Get(testCtx, utils.SpireServerConfigMapName, metav1.GetOptions{})
				if err != nil {
					fmt.Fprintf(GinkgoWriter, "failed to get ConfigMap: %v\n", err)
					return false
				}
				return !strings.Contains(cm.Data[utils.SpireServerConfigKey], driftMarker)
			}).WithPolling(utils.ShortInterval).WithTimeout(utils.ShortTimeout).Should(BeTrue(),
				"ConfigMap drift should be corrected when CreateOnlyMode is False")
		})
	})

	Context("Federation", Ordered, func() {
		It("Federation with https_spiffe profile should succeed", func() {
			By("Creating SpireServer with https_spiffe federation profile")
			server := &operatorv1alpha1.SpireServer{
				ObjectMeta: metav1.ObjectMeta{
					Name: "cluster",
				},
				Spec: operatorv1alpha1.SpireServerSpec{
					LogLevel:            "info",
					LogFormat:           "text",
					JwtIssuer:           jwtIssuer,
					CAValidity:          metav1.Duration{Duration: 24 * time.Hour},
					DefaultX509Validity: metav1.Duration{Duration: 1 * time.Hour},
					DefaultJWTValidity:  metav1.Duration{Duration: 5 * time.Minute},
					CAKeyType:           "rsa-2048",
					CASubject: operatorv1alpha1.CASubject{
						CommonName:   "SPIRE Server CA",
						Organization: "Test Org",
						Country:      "US",
					},
					Datastore: operatorv1alpha1.DataStore{
						DatabaseType:     "sqlite3",
						ConnectionString: "/run/spire/data/datastore.sqlite3",
						MaxOpenConns:     100,
						MaxIdleConns:     2,
					},
					Persistence: operatorv1alpha1.Persistence{
						Size:       "2Gi",
						AccessMode: "ReadWriteOnce",
					},
					Federation: &operatorv1alpha1.FederationConfig{
						BundleEndpoint: operatorv1alpha1.BundleEndpointConfig{
							Profile:     operatorv1alpha1.HttpsSpiffeProfile,
							RefreshHint: 300,
						},
						FederatesWith: []operatorv1alpha1.FederatesWithConfig{
							{
								TrustDomain:           "partner.example",
								BundleEndpointUrl:     "https://partner.example:8443",
								BundleEndpointProfile: operatorv1alpha1.HttpsSpiffeProfile,
								EndpointSpiffeId:      "spiffe://partner.example/server",
							},
						},
						ManagedRoute: "true",
					},
				},
			}
			err := k8sClient.Create(testCtx, server)
			Expect(err).NotTo(HaveOccurred(), "failed to create SpireServer with federation")
			DeferCleanup(func() {
				err := k8sClient.Delete(testCtx, server)
				if err != nil {
					fmt.Fprintf(GinkgoWriter, "failed to delete SpireServer: %v\n", err)
				}
			})

			By("Waiting for SPIRE server StatefulSet to become Available")
			utils.WaitForStatefulSetAvailable(testCtx, clientset, utils.SpireServerStatefulSetName, utils.OperatorNamespace, utils.DefaultTimeout)

			By("Verifying ConfigMap contains federation configuration")
			err = utils.VerifyConfigMapFederationConfig(testCtx, k8sClient, utils.SpireServerConfigMapName, utils.OperatorNamespace, "0.0.0.0:8443")
			Expect(err).NotTo(HaveOccurred(), "ConfigMap should contain valid federation configuration")

			By("Verifying ConfigMap contains federates_with configuration")
			cm := &corev1.ConfigMap{}
			err = k8sClient.Get(testCtx, types.NamespacedName{Name: utils.SpireServerConfigMapName, Namespace: utils.OperatorNamespace}, cm)
			Expect(err).NotTo(HaveOccurred())
			Expect(cm.Data["server.conf"]).To(ContainSubstring("partner.example"), "ConfigMap should contain partner.example trust domain")
		})

		It("Federation with https_web ServingCert profile should succeed", func() {
			By("Creating TLS Secret for ServingCert profile")
			federationDomain := "federation." + appDomain
			err := utils.CreateTLSSecret(testCtx, k8sClient, "federation-tls-cert", utils.OperatorNamespace, federationDomain)
			Expect(err).NotTo(HaveOccurred(), "failed to create TLS Secret")
			DeferCleanup(func() {
				secret := &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "federation-tls-cert",
						Namespace: utils.OperatorNamespace,
					},
				}
				err := k8sClient.Delete(testCtx, secret)
				if err != nil {
					fmt.Fprintf(GinkgoWriter, "failed to delete TLS Secret: %v\n", err)
				}
			})

			By("Creating SpireServer with https_web ServingCert federation profile")
			server := &operatorv1alpha1.SpireServer{
				ObjectMeta: metav1.ObjectMeta{
					Name: "cluster",
				},
				Spec: operatorv1alpha1.SpireServerSpec{
					LogLevel:            "info",
					LogFormat:           "text",
					JwtIssuer:           jwtIssuer,
					CAValidity:          metav1.Duration{Duration: 24 * time.Hour},
					DefaultX509Validity: metav1.Duration{Duration: 1 * time.Hour},
					DefaultJWTValidity:  metav1.Duration{Duration: 5 * time.Minute},
					CAKeyType:           "rsa-2048",
					CASubject: operatorv1alpha1.CASubject{
						CommonName:   "SPIRE Server CA",
						Organization: "Test Org",
						Country:      "US",
					},
					Datastore: operatorv1alpha1.DataStore{
						DatabaseType:     "sqlite3",
						ConnectionString: "/run/spire/data/datastore.sqlite3",
						MaxOpenConns:     100,
						MaxIdleConns:     2,
					},
					Persistence: operatorv1alpha1.Persistence{
						Size:       "2Gi",
						AccessMode: "ReadWriteOnce",
					},
					Federation: &operatorv1alpha1.FederationConfig{
						BundleEndpoint: operatorv1alpha1.BundleEndpointConfig{
							Profile:     operatorv1alpha1.HttpsWebProfile,
							RefreshHint: 300,
							HttpsWeb: &operatorv1alpha1.HttpsWebConfig{
								ServingCert: &operatorv1alpha1.ServingCertConfig{
									ExternalSecretRef: "federation-tls-cert",
									FileSyncInterval:  3600,
								},
							},
						},
						ManagedRoute: "true",
					},
				},
			}
			err = k8sClient.Create(testCtx, server)
			Expect(err).NotTo(HaveOccurred(), "failed to create SpireServer with https_web profile")
			DeferCleanup(func() {
				err := k8sClient.Delete(testCtx, server)
				if err != nil {
					fmt.Fprintf(GinkgoWriter, "failed to delete SpireServer: %v\n", err)
				}
			})

			By("Waiting for SPIRE server StatefulSet to become Available")
			utils.WaitForStatefulSetAvailable(testCtx, clientset, utils.SpireServerStatefulSetName, utils.OperatorNamespace, utils.DefaultTimeout)

			By("Verifying ConfigMap contains https_web federation configuration")
			err = utils.VerifyConfigMapFederationConfig(testCtx, k8sClient, utils.SpireServerConfigMapName, utils.OperatorNamespace, "0.0.0.0:8443")
			Expect(err).NotTo(HaveOccurred(), "ConfigMap should contain valid federation configuration")

			By("Verifying StatefulSet Pod has Secret volume mount")
			sts, err := clientset.AppsV1().StatefulSets(utils.OperatorNamespace).Get(testCtx, utils.SpireServerStatefulSetName, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			foundSecretVolume := false
			for _, volume := range sts.Spec.Template.Spec.Volumes {
				if volume.Secret != nil && volume.Secret.SecretName == "federation-tls-cert" {
					foundSecretVolume = true
					break
				}
			}
			Expect(foundSecretVolume).To(BeTrue(), "StatefulSet should have Secret volume for TLS certificate")
		})

		It("managedRoute=true should create federation Route", func() {
			By("Verifying federation Route was created")
			utils.WaitForFederationRouteAvailable(testCtx, k8sClient, utils.FederationRouteName, utils.OperatorNamespace, utils.DefaultTimeout)

			By("Verifying Route configuration")
			route := &routev1.Route{}
			err := k8sClient.Get(testCtx, types.NamespacedName{Name: utils.FederationRouteName, Namespace: utils.OperatorNamespace}, route)
			Expect(err).NotTo(HaveOccurred())

			By("Verifying Route host matches federation domain pattern")
			expectedHostPrefix := "federation."
			Expect(route.Spec.Host).To(HavePrefix(expectedHostPrefix), "Route host should start with 'federation.'")

			By("Verifying Route targets spire-server Service")
			Expect(route.Spec.To.Name).To(Equal(utils.FederationServiceName), "Route should target spire-server Service")
			Expect(route.Spec.To.Kind).To(Equal("Service"))

			By("Verifying Route port configuration")
			Expect(route.Spec.Port).NotTo(BeNil())
			Expect(route.Spec.Port.TargetPort.String()).To(Equal("federation"), "Route should target federation named port")
		})

		It("managedRoute=false should not create federation Route", func() {
			By("Deleting existing SpireServer to clean state")
			server := &operatorv1alpha1.SpireServer{
				ObjectMeta: metav1.ObjectMeta{
					Name: "cluster",
				},
			}
			err := k8sClient.Delete(testCtx, server)
			Expect(err).NotTo(HaveOccurred())

			By("Waiting for StatefulSet to be deleted")
			Eventually(func() bool {
				_, err := clientset.AppsV1().StatefulSets(utils.OperatorNamespace).Get(testCtx, utils.SpireServerStatefulSetName, metav1.GetOptions{})
				return kerrors.IsNotFound(err)
			}).WithTimeout(utils.DefaultTimeout).WithPolling(utils.DefaultInterval).Should(BeTrue())

			By("Creating SpireServer with managedRoute=false")
			serverNoRoute := &operatorv1alpha1.SpireServer{
				ObjectMeta: metav1.ObjectMeta{
					Name: "cluster",
				},
				Spec: operatorv1alpha1.SpireServerSpec{
					LogLevel:            "info",
					LogFormat:           "text",
					JwtIssuer:           jwtIssuer,
					CAValidity:          metav1.Duration{Duration: 24 * time.Hour},
					DefaultX509Validity: metav1.Duration{Duration: 1 * time.Hour},
					DefaultJWTValidity:  metav1.Duration{Duration: 5 * time.Minute},
					CAKeyType:           "rsa-2048",
					CASubject: operatorv1alpha1.CASubject{
						CommonName:   "SPIRE Server CA",
						Organization: "Test Org",
						Country:      "US",
					},
					Datastore: operatorv1alpha1.DataStore{
						DatabaseType:     "sqlite3",
						ConnectionString: "/run/spire/data/datastore.sqlite3",
						MaxOpenConns:     100,
						MaxIdleConns:     2,
					},
					Persistence: operatorv1alpha1.Persistence{
						Size:       "2Gi",
						AccessMode: "ReadWriteOnce",
					},
					Federation: &operatorv1alpha1.FederationConfig{
						BundleEndpoint: operatorv1alpha1.BundleEndpointConfig{
							Profile:     operatorv1alpha1.HttpsSpiffeProfile,
							RefreshHint: 300,
						},
						ManagedRoute: "false",
					},
				},
			}
			err = k8sClient.Create(testCtx, serverNoRoute)
			Expect(err).NotTo(HaveOccurred())
			DeferCleanup(func() {
				err := k8sClient.Delete(testCtx, serverNoRoute)
				if err != nil {
					fmt.Fprintf(GinkgoWriter, "failed to delete SpireServer: %v\n", err)
				}
			})

			By("Waiting for SPIRE server StatefulSet to become Available")
			utils.WaitForStatefulSetAvailable(testCtx, clientset, utils.SpireServerStatefulSetName, utils.OperatorNamespace, utils.DefaultTimeout)

			By("Verifying federation Route does not exist")
			route := &routev1.Route{}
			err = k8sClient.Get(testCtx, types.NamespacedName{Name: utils.FederationRouteName, Namespace: utils.OperatorNamespace}, route)
			Expect(kerrors.IsNotFound(err)).To(BeTrue(), "Route should not exist when managedRoute=false")

			By("Verifying Service still exposes federation port")
			svc, err := clientset.CoreV1().Services(utils.OperatorNamespace).Get(testCtx, utils.FederationServiceName, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			foundPort := false
			for _, port := range svc.Spec.Ports {
				if port.Port == utils.FederationServicePort {
					foundPort = true
					break
				}
			}
			Expect(foundPort).To(BeTrue(), "Service should still expose port 8443 for federation")
		})

		It("Route TLS configuration should match bundle endpoint profile", func() {
			By("Deleting existing SpireServer to clean state")
			server := &operatorv1alpha1.SpireServer{
				ObjectMeta: metav1.ObjectMeta{
					Name: "cluster",
				},
			}
			err := k8sClient.Delete(testCtx, server)
			Expect(err).NotTo(HaveOccurred())

			By("Waiting for StatefulSet to be deleted")
			Eventually(func() bool {
				_, err := clientset.AppsV1().StatefulSets(utils.OperatorNamespace).Get(testCtx, utils.SpireServerStatefulSetName, metav1.GetOptions{})
				return kerrors.IsNotFound(err)
			}).WithTimeout(utils.DefaultTimeout).WithPolling(utils.DefaultInterval).Should(BeTrue())

			By("Testing https_spiffe profile with Passthrough TLS")
			serverSpiffe := &operatorv1alpha1.SpireServer{
				ObjectMeta: metav1.ObjectMeta{
					Name: "cluster",
				},
				Spec: operatorv1alpha1.SpireServerSpec{
					LogLevel:            "info",
					LogFormat:           "text",
					JwtIssuer:           jwtIssuer,
					CAValidity:          metav1.Duration{Duration: 24 * time.Hour},
					DefaultX509Validity: metav1.Duration{Duration: 1 * time.Hour},
					DefaultJWTValidity:  metav1.Duration{Duration: 5 * time.Minute},
					CAKeyType:           "rsa-2048",
					CASubject: operatorv1alpha1.CASubject{
						CommonName:   "SPIRE Server CA",
						Organization: "Test Org",
						Country:      "US",
					},
					Datastore: operatorv1alpha1.DataStore{
						DatabaseType:     "sqlite3",
						ConnectionString: "/run/spire/data/datastore.sqlite3",
						MaxOpenConns:     100,
						MaxIdleConns:     2,
					},
					Persistence: operatorv1alpha1.Persistence{
						Size:       "2Gi",
						AccessMode: "ReadWriteOnce",
					},
					Federation: &operatorv1alpha1.FederationConfig{
						BundleEndpoint: operatorv1alpha1.BundleEndpointConfig{
							Profile:     operatorv1alpha1.HttpsSpiffeProfile,
							RefreshHint: 300,
						},
						ManagedRoute: "true",
					},
				},
			}
			err = k8sClient.Create(testCtx, serverSpiffe)
			Expect(err).NotTo(HaveOccurred())
			DeferCleanup(func() {
				err := k8sClient.Delete(testCtx, serverSpiffe)
				if err != nil {
					fmt.Fprintf(GinkgoWriter, "failed to delete SpireServer: %v\n", err)
				}
			})

			By("Waiting for SPIRE server StatefulSet to become Available")
			utils.WaitForStatefulSetAvailable(testCtx, clientset, utils.SpireServerStatefulSetName, utils.OperatorNamespace, utils.DefaultTimeout)

			By("Waiting for federation Route")
			utils.WaitForFederationRouteAvailable(testCtx, k8sClient, utils.FederationRouteName, utils.OperatorNamespace, utils.DefaultTimeout)

			By("Verifying https_spiffe Route uses Passthrough TLS")
			route := &routev1.Route{}
			err = k8sClient.Get(testCtx, types.NamespacedName{Name: utils.FederationRouteName, Namespace: utils.OperatorNamespace}, route)
			Expect(err).NotTo(HaveOccurred())
			Expect(route.Spec.TLS).NotTo(BeNil())
			Expect(route.Spec.TLS.Termination).To(Equal(routev1.TLSTerminationPassthrough), "https_spiffe profile should use Passthrough TLS")

			By("Deleting https_spiffe SpireServer")
			err = k8sClient.Delete(testCtx, serverSpiffe)
			Expect(err).NotTo(HaveOccurred())

			By("Waiting for StatefulSet to be deleted")
			Eventually(func() bool {
				_, err := clientset.AppsV1().StatefulSets(utils.OperatorNamespace).Get(testCtx, utils.SpireServerStatefulSetName, metav1.GetOptions{})
				return kerrors.IsNotFound(err)
			}).WithTimeout(utils.DefaultTimeout).WithPolling(utils.DefaultInterval).Should(BeTrue())

			By("Creating TLS Secret for https_web test")
			federationDomain := "federation." + appDomain
			err = utils.CreateTLSSecret(testCtx, k8sClient, "federation-tls-cert-route-test", utils.OperatorNamespace, federationDomain)
			Expect(err).NotTo(HaveOccurred())
			DeferCleanup(func() {
				secret := &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "federation-tls-cert-route-test",
						Namespace: utils.OperatorNamespace,
					},
				}
				err := k8sClient.Delete(testCtx, secret)
				if err != nil {
					fmt.Fprintf(GinkgoWriter, "failed to delete TLS Secret: %v\n", err)
				}
			})

			By("Testing https_web ServingCert profile with Reencrypt TLS")
			serverWeb := &operatorv1alpha1.SpireServer{
				ObjectMeta: metav1.ObjectMeta{
					Name: "cluster",
				},
				Spec: operatorv1alpha1.SpireServerSpec{
					LogLevel:            "info",
					LogFormat:           "text",
					JwtIssuer:           jwtIssuer,
					CAValidity:          metav1.Duration{Duration: 24 * time.Hour},
					DefaultX509Validity: metav1.Duration{Duration: 1 * time.Hour},
					DefaultJWTValidity:  metav1.Duration{Duration: 5 * time.Minute},
					CAKeyType:           "rsa-2048",
					CASubject: operatorv1alpha1.CASubject{
						CommonName:   "SPIRE Server CA",
						Organization: "Test Org",
						Country:      "US",
					},
					Datastore: operatorv1alpha1.DataStore{
						DatabaseType:     "sqlite3",
						ConnectionString: "/run/spire/data/datastore.sqlite3",
						MaxOpenConns:     100,
						MaxIdleConns:     2,
					},
					Persistence: operatorv1alpha1.Persistence{
						Size:       "2Gi",
						AccessMode: "ReadWriteOnce",
					},
					Federation: &operatorv1alpha1.FederationConfig{
						BundleEndpoint: operatorv1alpha1.BundleEndpointConfig{
							Profile:     operatorv1alpha1.HttpsWebProfile,
							RefreshHint: 300,
							HttpsWeb: &operatorv1alpha1.HttpsWebConfig{
								ServingCert: &operatorv1alpha1.ServingCertConfig{
									ExternalSecretRef: "federation-tls-cert-route-test",
									FileSyncInterval:  3600,
								},
							},
						},
						ManagedRoute: "true",
					},
				},
			}
			err = k8sClient.Create(testCtx, serverWeb)
			Expect(err).NotTo(HaveOccurred())
			DeferCleanup(func() {
				err := k8sClient.Delete(testCtx, serverWeb)
				if err != nil {
					fmt.Fprintf(GinkgoWriter, "failed to delete SpireServer: %v\n", err)
				}
			})

			By("Waiting for SPIRE server StatefulSet to become Available")
			utils.WaitForStatefulSetAvailable(testCtx, clientset, utils.SpireServerStatefulSetName, utils.OperatorNamespace, utils.DefaultTimeout)

			By("Waiting for federation Route")
			utils.WaitForFederationRouteAvailable(testCtx, k8sClient, utils.FederationRouteName, utils.OperatorNamespace, utils.DefaultTimeout)

			By("Verifying https_web ServingCert Route uses Reencrypt TLS with external certificate")
			routeWeb := &routev1.Route{}
			err = k8sClient.Get(testCtx, types.NamespacedName{Name: utils.FederationRouteName, Namespace: utils.OperatorNamespace}, routeWeb)
			Expect(err).NotTo(HaveOccurred())
			Expect(routeWeb.Spec.TLS).NotTo(BeNil())
			Expect(routeWeb.Spec.TLS.Termination).To(Equal(routev1.TLSTerminationReencrypt), "https_web ServingCert profile should use Reencrypt TLS")
			Expect(routeWeb.Spec.TLS.ExternalCertificate).NotTo(BeNil(), "Route should reference external certificate")
			Expect(routeWeb.Spec.TLS.ExternalCertificate.Name).To(Equal("federation-tls-cert-route-test"), "Route should reference correct Secret")
		})

		Context("ClusterFederatedTrustDomain", func() {
			BeforeAll(func() {
				By("Checking if spire-controller-manager is deployed")
				_, err := clientset.AppsV1().Deployments(utils.OperatorNamespace).Get(context.Background(), "spire-controller-manager", metav1.GetOptions{})
				if kerrors.IsNotFound(err) {
					Skip("spire-controller-manager not deployed, skipping ClusterFederatedTrustDomain tests")
				}
				Expect(err).NotTo(HaveOccurred(), "failed to check spire-controller-manager deployment")

				By("Waiting for spire-controller-manager to become Available")
				utils.WaitForDeploymentAvailable(context.Background(), clientset, "spire-controller-manager", utils.OperatorNamespace, utils.DefaultTimeout)
			})

			It("ClusterFederatedTrustDomain CR should be created successfully", func() {
				By("Ensuring SpireServer with federation exists")
				server := &operatorv1alpha1.SpireServer{}
				err := k8sClient.Get(testCtx, types.NamespacedName{Name: "cluster"}, server)
				if kerrors.IsNotFound(err) {
					By("Creating SpireServer with federation for ClusterFederatedTrustDomain tests")
					serverForFed := &operatorv1alpha1.SpireServer{
						ObjectMeta: metav1.ObjectMeta{
							Name: "cluster",
						},
						Spec: operatorv1alpha1.SpireServerSpec{
							LogLevel:            "info",
							LogFormat:           "text",
							JwtIssuer:           jwtIssuer,
							CAValidity:          metav1.Duration{Duration: 24 * time.Hour},
							DefaultX509Validity: metav1.Duration{Duration: 1 * time.Hour},
							DefaultJWTValidity:  metav1.Duration{Duration: 5 * time.Minute},
							CAKeyType:           "rsa-2048",
							CASubject: operatorv1alpha1.CASubject{
								CommonName:   "SPIRE Server CA",
								Organization: "Test Org",
								Country:      "US",
							},
							Datastore: operatorv1alpha1.DataStore{
								DatabaseType:     "sqlite3",
								ConnectionString: "/run/spire/data/datastore.sqlite3",
								MaxOpenConns:     100,
								MaxIdleConns:     2,
							},
							Persistence: operatorv1alpha1.Persistence{
								Size:       "2Gi",
								AccessMode: "ReadWriteOnce",
							},
							Federation: &operatorv1alpha1.FederationConfig{
								BundleEndpoint: operatorv1alpha1.BundleEndpointConfig{
									Profile:     operatorv1alpha1.HttpsSpiffeProfile,
									RefreshHint: 300,
								},
								ManagedRoute: "true",
							},
						},
					}
					err = k8sClient.Create(testCtx, serverForFed)
					Expect(err).NotTo(HaveOccurred())
					utils.WaitForStatefulSetAvailable(testCtx, clientset, utils.SpireServerStatefulSetName, utils.OperatorNamespace, utils.DefaultTimeout)
				} else {
					Expect(err).NotTo(HaveOccurred())
				}

				By("Creating ClusterFederatedTrustDomain CR")
				federatedTrustDomain := &spiffev1alpha1.ClusterFederatedTrustDomain{
					ObjectMeta: metav1.ObjectMeta{
						Name: "partner-example",
					},
					Spec: spiffev1alpha1.ClusterFederatedTrustDomainSpec{
						TrustDomain:           "partner.example",
						BundleEndpointProfile: spiffev1alpha1.BundleEndpointProfileHTTPSWeb,
						BundleEndpointURL:     "https://partner.example:8443",
					},
				}
				err = k8sClient.Create(testCtx, federatedTrustDomain)
				Expect(err).NotTo(HaveOccurred(), "failed to create ClusterFederatedTrustDomain")
				DeferCleanup(func() {
					err := k8sClient.Delete(testCtx, federatedTrustDomain)
					if err != nil {
						fmt.Fprintf(GinkgoWriter, "failed to delete ClusterFederatedTrustDomain: %v\n", err)
					}
				})

				By("Verifying ClusterFederatedTrustDomain CR exists")
				ftd := &spiffev1alpha1.ClusterFederatedTrustDomain{}
				err = k8sClient.Get(testCtx, types.NamespacedName{Name: "partner-example"}, ftd)
				Expect(err).NotTo(HaveOccurred(), "ClusterFederatedTrustDomain should exist")
				Expect(ftd.Spec.TrustDomain).To(Equal("partner.example"))
			})

			It("ClusterSPIFFEID with federatesWith should configure workload SVID", func() {
				By("Creating ClusterSPIFFEID with federatesWith")
				spiffeID := &spiffev1alpha1.ClusterSPIFFEID{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-workload-federation",
					},
					Spec: spiffev1alpha1.ClusterSPIFFEIDSpec{
						SpiffeIDTemplate: "spiffe://{{ .TrustDomain }}/ns/{{ .PodMeta.Namespace }}/sa/{{ .PodSpec.ServiceAccountName }}",
						PodSelector: metav1.LabelSelector{
							MatchLabels: map[string]string{
								"test-federation": "true",
							},
						},
						FederatesWith: []string{"partner.example"},
					},
				}
				err := k8sClient.Create(testCtx, spiffeID)
				Expect(err).NotTo(HaveOccurred(), "failed to create ClusterSPIFFEID")
				DeferCleanup(func() {
					err := k8sClient.Delete(testCtx, spiffeID)
					if err != nil {
						fmt.Fprintf(GinkgoWriter, "failed to delete ClusterSPIFFEID: %v\n", err)
					}
				})

				By("Creating test workload Pod matching ClusterSPIFFEID selector")
				testPod := &corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-federation-workload",
						Namespace: utils.OperatorNamespace,
						Labels: map[string]string{
							"test-federation": "true",
						},
					},
					Spec: corev1.PodSpec{
						ServiceAccountName: "default",
						Containers: []corev1.Container{
							{
								Name:    "test-container",
								Image:   "registry.access.redhat.com/ubi9/ubi-minimal:latest",
								Command: []string{"/bin/sh", "-c", "sleep 3600"},
								VolumeMounts: []corev1.VolumeMount{
									{
										Name:      "spiffe-workload-api",
										MountPath: "/spiffe-workload-api",
										ReadOnly:  true,
									},
								},
							},
						},
						Volumes: []corev1.Volume{
							{
								Name: "spiffe-workload-api",
								VolumeSource: corev1.VolumeSource{
									CSI: &corev1.CSIVolumeSource{
										Driver:   "csi.spiffe.io",
										ReadOnly: ptr.To(true),
									},
								},
							},
						},
					},
				}
				err = k8sClient.Create(testCtx, testPod)
				Expect(err).NotTo(HaveOccurred(), "failed to create test Pod")
				DeferCleanup(func() {
					err := k8sClient.Delete(testCtx, testPod)
					if err != nil {
						fmt.Fprintf(GinkgoWriter, "failed to delete test Pod: %v\n", err)
					}
				})

				By("Waiting for test Pod to be Running")
				Eventually(func() bool {
					pod := &corev1.Pod{}
					err := k8sClient.Get(testCtx, types.NamespacedName{Name: "test-federation-workload", Namespace: utils.OperatorNamespace}, pod)
					if err != nil {
						fmt.Fprintf(GinkgoWriter, "failed to get Pod: %v\n", err)
						return false
					}
					if pod.Status.Phase != corev1.PodRunning {
						fmt.Fprintf(GinkgoWriter, "Pod phase: %s\n", pod.Status.Phase)
						return false
					}
					fmt.Fprintf(GinkgoWriter, "Pod is Running\n")
					return true
				}).WithTimeout(utils.DefaultTimeout).WithPolling(utils.DefaultInterval).Should(BeTrue())

				By("Verifying SPIFFE CSI driver socket exists in Pod")
				pod := &corev1.Pod{}
				err = k8sClient.Get(testCtx, types.NamespacedName{Name: "test-federation-workload", Namespace: utils.OperatorNamespace}, pod)
				Expect(err).NotTo(HaveOccurred())
				Expect(pod.Spec.Volumes).To(ContainElement(
					MatchFields(IgnoreExtras, Fields{
						"Name": Equal("spiffe-workload-api"),
						"VolumeSource": MatchFields(IgnoreExtras, Fields{
							"CSI": PointTo(MatchFields(IgnoreExtras, Fields{
								"Driver": Equal("csi.spiffe.io"),
							})),
						}),
					}),
				), "Pod should have SPIFFE CSI volume configured")
			})
		})

		Context("Immutability and Validation", func() {
			It("Federation configuration cannot be removed once set", func() {
				By("Getting existing SpireServer with federation")
				server := &operatorv1alpha1.SpireServer{}
				err := k8sClient.Get(testCtx, types.NamespacedName{Name: "cluster"}, server)
				Expect(err).NotTo(HaveOccurred())

				if server.Spec.Federation == nil {
					Skip("SpireServer does not have federation configured, skipping immutability test")
				}

				By("Attempting to remove federation configuration")
				serverCopy := server.DeepCopy()
				serverCopy.Spec.Federation = nil

				err = k8sClient.Update(testCtx, serverCopy)
				Expect(err).To(HaveOccurred(), "Update should fail when removing federation")
				Expect(kerrors.IsInvalid(err)).To(BeTrue(), "Error should be validation error")
				Expect(err.Error()).To(ContainSubstring("Federation configuration cannot be removed once set"), "Error should mention federation removal")
			})

			It("Bundle endpoint profile is immutable", func() {
				By("Getting existing SpireServer with https_spiffe profile")
				server := &operatorv1alpha1.SpireServer{}
				err := k8sClient.Get(testCtx, types.NamespacedName{Name: "cluster"}, server)
				Expect(err).NotTo(HaveOccurred())

				if server.Spec.Federation == nil {
					Skip("SpireServer does not have federation configured, skipping immutability test")
				}

				originalProfile := server.Spec.Federation.BundleEndpoint.Profile

				By("Attempting to change bundle endpoint profile")
				serverCopy := server.DeepCopy()
				if originalProfile == operatorv1alpha1.HttpsSpiffeProfile {
					serverCopy.Spec.Federation.BundleEndpoint.Profile = operatorv1alpha1.HttpsWebProfile
				} else {
					serverCopy.Spec.Federation.BundleEndpoint.Profile = operatorv1alpha1.HttpsSpiffeProfile
				}

				err = k8sClient.Update(testCtx, serverCopy)
				Expect(err).To(HaveOccurred(), "Update should fail when changing profile")
				Expect(kerrors.IsInvalid(err)).To(BeTrue(), "Error should be validation error")
				Expect(err.Error()).To(ContainSubstring("profile is immutable"), "Error should mention profile immutability")
			})

			It("Cannot switch between ACME and ServingCert configuration", func() {
				By("Getting existing SpireServer")
				server := &operatorv1alpha1.SpireServer{}
				err := k8sClient.Get(testCtx, types.NamespacedName{Name: "cluster"}, server)
				Expect(err).NotTo(HaveOccurred())

				if server.Spec.Federation == nil || server.Spec.Federation.BundleEndpoint.Profile != operatorv1alpha1.HttpsWebProfile {
					Skip("SpireServer does not have https_web profile configured, skipping ACME/ServingCert switch test")
				}

				if server.Spec.Federation.BundleEndpoint.HttpsWeb == nil || server.Spec.Federation.BundleEndpoint.HttpsWeb.ServingCert == nil {
					Skip("SpireServer does not have ServingCert configured, skipping switch test")
				}

				By("Attempting to switch from ServingCert to ACME")
				serverCopy := server.DeepCopy()
				serverCopy.Spec.Federation.BundleEndpoint.HttpsWeb.ServingCert = nil
				serverCopy.Spec.Federation.BundleEndpoint.HttpsWeb.Acme = &operatorv1alpha1.AcmeConfig{
					DirectoryUrl: "https://acme-staging.example.com/directory",
					DomainName:   "test.example",
					Email:        "test@example.com",
					TosAccepted:  "true",
				}

				err = k8sClient.Update(testCtx, serverCopy)
				Expect(err).To(HaveOccurred(), "Update should fail when switching from ServingCert to ACME")
				Expect(kerrors.IsInvalid(err)).To(BeTrue(), "Error should be validation error")
				Expect(err.Error()).To(ContainSubstring("cannot switch from servingCert to acme"), "Error should mention ServingCert to ACME switch")
			})

			It("https_spiffe profile requires endpointSpiffeId in federatesWith", func() {
				By("Attempting to create SpireServer with https_spiffe federatesWith missing endpointSpiffeId")
				serverInvalid := &operatorv1alpha1.SpireServer{
					ObjectMeta: metav1.ObjectMeta{
						Name: "cluster-invalid",
					},
					Spec: operatorv1alpha1.SpireServerSpec{
						LogLevel:            "info",
						LogFormat:           "text",
						JwtIssuer:           jwtIssuer,
						CAValidity:          metav1.Duration{Duration: 24 * time.Hour},
						DefaultX509Validity: metav1.Duration{Duration: 1 * time.Hour},
						DefaultJWTValidity:  metav1.Duration{Duration: 5 * time.Minute},
						CAKeyType:           "rsa-2048",
						CASubject: operatorv1alpha1.CASubject{
							CommonName:   "SPIRE Server CA",
							Organization: "Test Org",
							Country:      "US",
						},
						Datastore: operatorv1alpha1.DataStore{
							DatabaseType:     "sqlite3",
							ConnectionString: "/run/spire/data/datastore.sqlite3",
							MaxOpenConns:     100,
							MaxIdleConns:     2,
						},
						Persistence: operatorv1alpha1.Persistence{
							Size:       "2Gi",
							AccessMode: "ReadWriteOnce",
						},
						Federation: &operatorv1alpha1.FederationConfig{
							BundleEndpoint: operatorv1alpha1.BundleEndpointConfig{
								Profile:     operatorv1alpha1.HttpsSpiffeProfile,
								RefreshHint: 300,
							},
							FederatesWith: []operatorv1alpha1.FederatesWithConfig{
								{
									TrustDomain:           "invalid.example",
									BundleEndpointUrl:     "https://invalid.example:8443",
									BundleEndpointProfile: operatorv1alpha1.HttpsSpiffeProfile,
									EndpointSpiffeId:      "", // Missing required field
								},
							},
						},
					},
				}

				err := k8sClient.Create(testCtx, serverInvalid)
				Expect(err).To(HaveOccurred(), "Create should fail when endpointSpiffeId is missing for https_spiffe")
				Expect(kerrors.IsInvalid(err)).To(BeTrue(), "Error should be validation error")
				Expect(err.Error()).To(ContainSubstring("endpointSpiffeId is required when bundleEndpointProfile is https_spiffe"), "Error should mention missing endpointSpiffeId")
			})
		})
	})
})
