package auth

import (
	"fmt"

	"github.com/rancher/rancher/pkg/clustermanager"
	v3 "github.com/rancher/types/apis/management.cattle.io/v3"
	"github.com/rancher/types/config"
	"github.com/sirupsen/logrus"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	k8dynamic "k8s.io/client-go/dynamic"
)

const mgmtProjectMacvlansubnetCleaner = "mgmt-project-macvlansubnet-cleaner"

func newProjectMacvlansubnetCleaner(management *config.ManagementContext, clusterManager *clustermanager.Manager) *projectMacvlansubnetCleaner {
	p := &projectMacvlansubnetCleaner{
		mgmt:           management,
		clusterManager: clusterManager,
	}
	return p
}

type projectMacvlansubnetCleaner struct {
	mgmt           *config.ManagementContext
	clusterManager *clustermanager.Manager
}

func (l *projectMacvlansubnetCleaner) Create(obj *v3.Project) (runtime.Object, error) {
	return obj, nil
}

func (l *projectMacvlansubnetCleaner) Updated(obj *v3.Project) (runtime.Object, error) {
	return obj, nil
}

func (l *projectMacvlansubnetCleaner) Remove(obj *v3.Project) (runtime.Object, error) {
	l.removeMacvlanSubnetByProject(obj)
	return obj, nil
}

// removeMacvlanSubnetByProject delete macvlansubnets by specific project label
func (l *projectMacvlansubnetCleaner) removeMacvlanSubnetByProject(obj *v3.Project) {
	logrus.Infof("Pandaria: removeMacvlanSubnetByProject deleting macvlan subnet for project %v %v", obj.Spec.ClusterName, obj.Name)
	macvlanSubnetDef := schema.GroupVersionResource{
		Group:    "macvlan.cluster.cattle.io",
		Version:  "v1",
		Resource: "macvlansubnets",
	}

	labelSelector := fmt.Sprintf("project=%s-%s", obj.Spec.ClusterName, obj.Name)

	userCtx, err := l.clusterManager.UserContext(obj.Spec.ClusterName)
	if err != nil {
		logrus.Errorf("Pandaria: removeMacvlanSubnetByProject get user ctx error: %v", err)
		return
	}

	dynamicClient, err := k8dynamic.NewForConfig(&userCtx.RESTConfig)
	if err != nil {
		logrus.Errorf("Pandaria: removeMacvlanSubnetByProject get dynamic client error: %v", err)
		return
	}

	err = dynamicClient.
		Resource(macvlanSubnetDef).
		Namespace("kube-system").
		DeleteCollection(&v1.DeleteOptions{}, v1.ListOptions{LabelSelector: labelSelector})
	if err != nil {
		logrus.Errorf("Pandaria: removeMacvlanSubnetByProject delete macvlan subnet for project %v error: %v", obj.Name, err)
	}
}
