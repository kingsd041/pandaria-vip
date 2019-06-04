package harbor

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/rancher/rancher/pkg/settings"
	"github.com/rancher/types/apis/core/v1"
	"github.com/rancher/types/apis/management.cattle.io/v3"
	"github.com/rancher/types/config"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/kubernetes/pkg/credentialprovider"
)

var (
	harborRegistryAuthLabel   = "rancher.cn/registry-harbor-auth"
	harborUserAnnotationAuth  = "authz.management.cattle.io.cn/harborauth"
	harborUserAnnotationEmail = "authz.management.cattle.io.cn/harboremail"
)

type Controller struct {
	settings          v3.SettingInterface
	users             v3.UserInterface
	managementSecrets v1.SecretInterface
	clusterName       string
}

func Register(ctx context.Context, cluster *config.UserContext) {
	s := &Controller{
		settings:          cluster.Management.Management.Settings(""),
		users:             cluster.Management.Management.Users(""),
		managementSecrets: cluster.Management.Core.Secrets(""),
		clusterName:       cluster.ClusterName,
	}

	cluster.Management.Management.Settings("").AddHandler(ctx, "harborSecretsController", s.syncSettings)
	cluster.Management.Management.Users("").AddHandler(ctx, "harborSecretsController", s.syncUser)
}

func (c *Controller) syncSettings(key string, obj *v3.Setting) (runtime.Object, error) {
	// sync harbor registry secret when HarborServerURL and HarborAdminAuth changed
	if settings.HarborAdminAuth.Name == obj.Name {
		return c.syncSecret(obj.Value, "", false)
	} else if settings.HarborServerURL.Name == obj.Name {
		// update all harbor registry secret
		return c.syncSecret("", "", true)
	}

	return nil, nil
}

func (c *Controller) syncUser(key string, obj *v3.User) (runtime.Object, error) {
	if obj == nil || obj.DeletionTimestamp != nil {
		return nil, nil
	}
	annotations := obj.Annotations
	if annotations != nil && annotations[harborUserAnnotationAuth] != "" && annotations[harborUserAnnotationEmail] != "" {
		return c.syncSecret(annotations[harborUserAnnotationAuth], annotations[harborUserAnnotationEmail], false)
	}

	return nil, nil
}

func (c *Controller) syncSecret(auth, email string, isUpdateServer bool) (runtime.Object, error) {
	// get all harbor registry secrets
	secretList, err := c.managementSecrets.List(metav1.ListOptions{
		FieldSelector: "type=kubernetes.io/dockerconfigjson",
		LabelSelector: fmt.Sprintf("%s=true", harborRegistryAuthLabel),
	})
	if err != nil {
		return nil, err
	}

	if len(secretList.Items) == 0 {
		return nil, nil
	}
	// get harbor server
	harborServerStr := settings.HarborServerURL.Get()
	harborServerArray := strings.Split(harborServerStr, "://")
	harborServer := ""
	if len(harborServerArray) != 2 {
		harborServer = harborServerArray[0]
	} else {
		harborServer = harborServerArray[1]
	}

	// format value <username>:<password>
	decodeAuth, err := base64.StdEncoding.DecodeString(auth)
	if err != nil {
		return nil, err
	}
	harborAuth := strings.Split(string(decodeAuth), ":")
	if len(harborAuth) != 2 && !isUpdateServer {
		return nil, fmt.Errorf("invalid user auth of harbor: %v", string(decodeAuth))
	}

	for _, s := range secretList.Items {
		secret := s.DeepCopy()
		dockerConfigContent := secret.Data[corev1.DockerConfigJsonKey]
		dockerConfig := &credentialprovider.DockerConfigJson{}
		err = json.Unmarshal(dockerConfigContent, dockerConfig)
		if err != nil {
			return nil, err
		}
		dockerConfigAuth := dockerConfig.Auths
		newConfigAuth := map[string]credentialprovider.DockerConfigEntry{}
		for _, auth := range dockerConfigAuth {
			if isUpdateServer {
				newConfigAuth[harborServer] = auth
			} else {
				if auth.Username == harborAuth[0] {
					dockercfgAuth := credentialprovider.DockerConfigEntry{
						Username: harborAuth[0],
						Password: harborAuth[1],
					}
					if email != "" {
						dockercfgAuth.Email = email
					}
					newConfigAuth[harborServer] = dockercfgAuth
				}
			}
		}
		if len(newConfigAuth) > 0 {
			dockerConfig.Auths = newConfigAuth
			configJSON, err := json.Marshal(dockerConfig)
			if err != nil {
				return nil, err
			}
			secret.Data[corev1.DockerConfigJsonKey] = configJSON
			_, err = c.managementSecrets.Update(secret)
			if err != nil {
				return nil, err
			}
		}
	}

	return nil, nil
}
