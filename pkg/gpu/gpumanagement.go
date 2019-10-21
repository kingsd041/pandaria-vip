package gpu

import (
	"fmt"

	"github.com/rancher/rancher/pkg/ref"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type AppLevel string

const (
	SystemLevel  AppLevel = "system"
	ClusterLevel AppLevel = "cluster"
	ProjectLevel AppLevel = "project"
)

const (
	cattleNamespaceName = "cattle-gpumanagement"
)

const (
	//CattleMonitoringLabelKey The label info of Namespace
	cattleMonitoringLabelKey = "gpumanagement.cattle.io"

	// The label info of App, RoleBinding
	appNameLabelKey            = cattleMonitoringLabelKey + "/appName"
	appTargetNamespaceLabelKey = cattleMonitoringLabelKey + "/appTargetNamespace"
	appProjectIDLabelKey       = cattleMonitoringLabelKey + "/projectID"
	appClusterIDLabelKey       = cattleMonitoringLabelKey + "/clusterID"

	// The names of App
	clusterLevelAppName = "cluster-gpu-management"
)

func ClusterGPUManagementInfo() (appName, appTargetNamespace string) {
	return clusterLevelAppName, cattleNamespaceName
}

func OwnedAppListOptions(clusterID, appName, appTargetNamespace string) metav1.ListOptions {
	return metav1.ListOptions{
		LabelSelector: fmt.Sprintf("%s=%s, %s=%s, %s=%s", appClusterIDLabelKey, clusterID, appNameLabelKey, appName, appTargetNamespaceLabelKey, appTargetNamespace),
	}
}

func OwnedLabels(appName, appTargetNamespace, appProjectName string) map[string]string {
	clusterID, projectID := ref.Parse(appProjectName)

	return map[string]string{
		appNameLabelKey:            appName,
		appTargetNamespaceLabelKey: appTargetNamespace,
		appProjectIDLabelKey:       projectID,
		appClusterIDLabelKey:       clusterID,
	}
}
