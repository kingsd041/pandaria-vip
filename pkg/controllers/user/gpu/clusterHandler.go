package gpu

import (
	"fmt"
	"reflect"

	"github.com/pkg/errors"
	"github.com/rancher/rancher/pkg/app/utils"
	"github.com/rancher/rancher/pkg/gpu"
	"github.com/rancher/rancher/pkg/ref"
	"github.com/rancher/rancher/pkg/settings"
	mgmtv3 "github.com/rancher/types/apis/management.cattle.io/v3"
	v3 "github.com/rancher/types/apis/project.cattle.io/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

const (
	creatorIDAnno              = "field.cattle.io/creatorId"
	appSchedulerExtenderAnswer = "schedulerextender.ports.nodeport"
)

type clusterHandler struct {
	clusterName          string
	cattleClustersClient mgmtv3.ClusterInterface
	app                  *appHandler
}

func (ch *clusterHandler) sync(key string, cluster *mgmtv3.Cluster) (runtime.Object, error) {
	if cluster == nil || cluster.DeletionTimestamp != nil || cluster.Name != ch.clusterName {
		return cluster, nil
	}

	if !mgmtv3.ClusterConditionAgentDeployed.IsTrue(cluster) {
		return cluster, nil
	}

	clusterTag := getClusterTag(cluster)
	src := cluster
	cpy := src.DeepCopy()

	err := ch.doSync(cpy)
	if !reflect.DeepEqual(cpy, src) {
		updated, updateErr := ch.cattleClustersClient.Update(cpy)
		if updateErr != nil {
			return updated, errors.Wrapf(updateErr, "failed to update Cluster %s", clusterTag)
		}

		cpy = updated
	}

	return cpy, err
}

func (ch *clusterHandler) doSync(cluster *mgmtv3.Cluster) error {
	appName, appTargetNamespace := gpu.ClusterGPUManagementInfo()

	if cluster.Spec.EnableGPUManagement {
		appProjectName, err := ch.ensureAppProjectName(cluster.Name, appTargetNamespace)
		if err != nil {
			mgmtv3.ClusterConditionGPUManagementEnabled.Unknown(cluster)
			mgmtv3.ClusterConditionGPUManagementEnabled.Message(cluster, err.Error())
			return errors.Wrap(err, "failed to ensure gpumanagement project name")
		}

		err = ch.deployApp(appName, appTargetNamespace, appProjectName, cluster)
		if err != nil {
			mgmtv3.ClusterConditionGPUManagementEnabled.Unknown(cluster)
			mgmtv3.ClusterConditionGPUManagementEnabled.Message(cluster, err.Error())
			return errors.Wrap(err, "failed to deploy gpumanagement")
		}

		mgmtv3.ClusterConditionGPUManagementEnabled.True(cluster)
		mgmtv3.ClusterConditionGPUManagementEnabled.Message(cluster, "")
	} else if enabledStatus := mgmtv3.ClusterConditionGPUManagementEnabled.GetStatus(cluster); enabledStatus != "" && enabledStatus != "False" {
		if err := ch.app.withdrawApp(cluster.Name, appName, appTargetNamespace); err != nil {
			mgmtv3.ClusterConditionGPUManagementEnabled.Unknown(cluster)
			mgmtv3.ClusterConditionGPUManagementEnabled.Message(cluster, err.Error())
			return errors.Wrap(err, "failed to withdraw gpumanagement")
		}

		mgmtv3.ClusterConditionGPUManagementEnabled.False(cluster)
		mgmtv3.ClusterConditionGPUManagementEnabled.Message(cluster, "")
	}

	return nil
}

func (ch *clusterHandler) ensureAppProjectName(clusterID, appTargetNamespace string) (string, error) {
	appDeployProjectID, err := utils.GetSystemProjectID(clusterID, ch.app.projectLister)
	if err != nil {
		return "", err
	}

	appProjectName, err := utils.EnsureAppProjectName(ch.app.agentNamespaceClient, appDeployProjectID, clusterID, appTargetNamespace)
	if err != nil {
		return "", err
	}

	return appProjectName, nil
}

func (ch *clusterHandler) deployApp(appName, appTargetNamespace string, appProjectName string, cluster *mgmtv3.Cluster) error {
	_, appDeployProjectID := ref.Parse(appProjectName)

	creator, err := ch.app.systemAccountManager.GetSystemUser(ch.clusterName)
	if err != nil {
		return err
	}

	schdNodePort := cluster.Spec.GPUSchedulerNodePort

	appAnswers := map[string]string{
		appSchedulerExtenderAnswer: schdNodePort,
	}

	appCatalogID := settings.SystemGPUManagementCatalogID.Get()
	app := &v3.App{
		ObjectMeta: metav1.ObjectMeta{
			Annotations: map[string]string{creatorIDAnno: creator.Name},
			Labels:      gpu.OwnedLabels(appName, appTargetNamespace, appProjectName),
			Name:        appName,
			Namespace:   appDeployProjectID,
		},
		Spec: v3.AppSpec{
			Answers:         appAnswers,
			Description:     "Rancher Cluster GPU Management",
			ExternalID:      appCatalogID,
			ProjectName:     appProjectName,
			TargetNamespace: appTargetNamespace,
		},
	}

	_, err = utils.DeployApp(ch.app.cattleAppClient, appDeployProjectID, app, false)
	if err != nil {
		return err
	}

	return nil
}

func getClusterTag(cluster *mgmtv3.Cluster) string {
	return fmt.Sprintf("%s(%s)", cluster.Name, cluster.Spec.DisplayName)
}
