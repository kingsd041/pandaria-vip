package gpu

import (
	"github.com/rancher/rancher/pkg/gpu"
	"github.com/rancher/rancher/pkg/systemaccount"
	appsv1 "github.com/rancher/types/apis/apps/v1"
	corev1 "github.com/rancher/types/apis/core/v1"
	mgmtv3 "github.com/rancher/types/apis/management.cattle.io/v3"
	projectv3 "github.com/rancher/types/apis/project.cattle.io/v3"
)

type appHandler struct {
	cattleAppClient             projectv3.AppInterface
	cattleSecretClient          corev1.SecretInterface
	cattleTemplateVersionClient mgmtv3.CatalogTemplateVersionInterface
	cattleProjectClient         mgmtv3.ProjectInterface
	cattleClusterGraphClient    mgmtv3.ClusterMonitorGraphInterface
	cattleProjectGraphClient    mgmtv3.ProjectMonitorGraphInterface
	cattleMonitorMetricClient   mgmtv3.MonitorMetricInterface
	agentDeploymentClient       appsv1.DeploymentInterface
	agentStatefulSetClient      appsv1.StatefulSetInterface
	agentDaemonSetClient        appsv1.DaemonSetInterface
	agentServiceAccountClient   corev1.ServiceAccountInterface
	agentSecretClient           corev1.SecretInterface
	agentNodeClient             corev1.NodeInterface
	agentNamespaceClient        corev1.NamespaceInterface
	systemAccountManager        *systemaccount.Manager
	projectLister               mgmtv3.ProjectLister
	catalogTemplateLister       mgmtv3.CatalogTemplateLister
}

func (ah *appHandler) withdrawApp(clusterID, appName, appTargetNamespace string) error {
	return gpu.WithdrawApp(ah.cattleAppClient, gpu.OwnedAppListOptions(clusterID, appName, appTargetNamespace))
}
