package pod

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"

	"github.com/rancher/rancher/pkg/kubectl"

	"github.com/mitchellh/mapstructure"
	"github.com/rancher/norman/api/access"
	"github.com/rancher/norman/api/handler"
	"github.com/rancher/norman/httperror"
	"github.com/rancher/norman/types"
	"github.com/rancher/rancher/pkg/clustermanager"
	"github.com/rancher/types/apis/project.cattle.io/v3/schema"
	projectschema "github.com/rancher/types/apis/project.cattle.io/v3/schema"
	projectclient "github.com/rancher/types/client/project/v3"
	"github.com/rancher/types/config"
	"github.com/rancher/types/user"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

type ActionWrapper struct {
	ClusterManager *clustermanager.Manager
	UserManager    user.Manager
}

func (a ActionWrapper) ActionHandler(actionName string, action *types.Action, apiContext *types.APIContext) error {
	var pod projectclient.Pod
	accessError := access.ByID(apiContext, &projectschema.Version, "pod", apiContext.ID, &pod)
	if accessError != nil {
		return httperror.NewAPIError(httperror.InvalidReference, "Error accessing pod")
	}
	namespace, name := splitID(pod.ID)
	switch actionName {
	case "download":
		clusterName := a.ClusterManager.ClusterName(apiContext)
		if clusterName == "" {
			return httperror.NewAPIError(httperror.ServerError, fmt.Sprintf("Cluster name empty %s", pod.ID))
		}
		clusterContext, err := a.ClusterManager.UserContext(clusterName)
		if err != nil {
			return httperror.NewAPIError(httperror.ServerError, fmt.Sprintf("Error getting cluster context %s", pod.ID))
		}
		return a.downloadPodFile(apiContext, clusterContext, actionName, pod, namespace, name)
	}
	return nil
}

func Formatter(apiContext *types.APIContext, resource *types.RawResource) {
	podID := resource.ID
	podSchema := apiContext.Schemas.Schema(&schema.Version, "pod")
	resource.Actions["download"] = apiContext.URLBuilder.ActionLinkByID(podSchema, podID, "download")
}

func splitID(id string) (string, string) {
	namespace := ""
	parts := strings.SplitN(id, ":", 2)
	if len(parts) == 2 {
		namespace = parts[0]
		id = parts[1]
	}

	return namespace, id
}

func (a ActionWrapper) getToken(apiContext *types.APIContext) (string, error) {
	userName := a.UserManager.GetUser(apiContext)
	return a.UserManager.EnsureToken("kubeconfig-"+userName, "Kubeconfig token", "kubeconfig", userName)
}

func (a ActionWrapper) getKubeConfig(apiContext *types.APIContext, clusterContext *config.UserContext) (*clientcmdapi.Config, error) {
	token, err := a.getToken(apiContext)
	if err != nil {
		return nil, err
	}

	cfg := a.ClusterManager.KubeConfig(clusterContext.ClusterName, token)
	return cfg, nil
}

func (a ActionWrapper) downloadPodFile(apiContext *types.APIContext, clusterContext *config.UserContext,
	actionName string, pod projectclient.Pod, namespace string, name string) error {
	input, err := handler.ParseAndValidateActionBody(apiContext, apiContext.Schemas.Schema(&projectschema.Version,
		projectclient.PodFileDownloadInputType))
	if err != nil {
		return httperror.NewAPIError(httperror.InvalidBodyContent,
			fmt.Sprintf("Failed to parse action body: %v", err))
	}
	podFileDownloadInput := &projectclient.PodFileDownloadInput{}
	if err := mapstructure.Decode(input, podFileDownloadInput); err != nil {
		return httperror.NewAPIError(httperror.InvalidBodyContent,
			fmt.Sprintf("Failed to parse body: %v", err))
	}

	cfg, err := a.getKubeConfig(apiContext, clusterContext)
	if err != nil {
		return httperror.NewAPIError(httperror.InvalidState,
			fmt.Sprintf("Failed to get kubeconfig: %v", err))
	}
	if podFileDownloadInput.ContainerName == "" &&
		len(pod.Containers) > 0 {
		podFileDownloadInput.ContainerName = pod.Containers[0].Name
	}
	b, err := kubectl.Copy(namespace, name, podFileDownloadInput.ContainerName, podFileDownloadInput.FilePath, cfg)
	if err != nil {
		return httperror.NewAPIError(httperror.ServerError,
			fmt.Sprintf("Failed to copy %s/%s:%s - %v", namespace, name, podFileDownloadInput.FilePath, err))
	}

	data := map[string]interface{}{
		"type": "podFileDownloadOutput",
		projectclient.PodFileDownloadOutputFieldFileContent: base64.StdEncoding.EncodeToString(b),
	}
	apiContext.WriteResponse(http.StatusOK, data)
	return nil
}
