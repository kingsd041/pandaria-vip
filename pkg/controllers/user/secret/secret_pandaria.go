package secret

import (
	"context"
	"strings"

	"k8s.io/apimachinery/pkg/runtime"

	"fmt"

	"github.com/rancher/norman/controller"
	v1 "github.com/rancher/types/apis/core/v1"
	v3 "github.com/rancher/types/apis/management.cattle.io/v3"
	"github.com/rancher/types/config"
	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
)

// SecretController listens for secret CUD in management API
// and propagates the changes to all corresponding namespaces in cluster API

// NamespaceController listens to cluster namespace events,
// reads secrets from the management namespace of corresponding project,
// and creates the secrets in the cluster namespace

type ControllerPandaria struct {
	secrets                   v1.SecretInterface
	clusterNamespaceLister    v1.NamespaceLister
	managementNamespaceLister v1.NamespaceLister
	projectLister             v3.ProjectLister
	clusterName               string
}

func RegisterPandaria(ctx context.Context, cluster *config.UserContext) {
	clusterSecretsClient := cluster.Core.Secrets("")
	s := &ControllerPandaria{
		secrets:                   clusterSecretsClient,
		clusterNamespaceLister:    cluster.Core.Namespaces("").Controller().Lister(),
		managementNamespaceLister: cluster.Management.Core.Namespaces("").Controller().Lister(),
		projectLister:             cluster.Management.Management.Projects("").Controller().Lister(),
		clusterName:               cluster.ClusterName,
	}

	n := &PandariaNamespaceController{
		clusterSecretsClient: clusterSecretsClient,
		managementSecrets:    cluster.Management.Core.Secrets("").Controller().Lister(),
	}
	cluster.Core.Namespaces("").AddHandler(ctx, "secretsController", n.sync)

	sync := v1.NewSecretLifecycleAdapter(fmt.Sprintf("secretsController_%s", cluster.ClusterName), true,
		cluster.Management.Core.Secrets(""), s)

	cluster.Management.Core.Secrets("").AddHandler(ctx, "secretsController", func(key string, obj *corev1.Secret) (runtime.Object, error) {
		if obj == nil {
			return sync(key, nil)
		}
		if !controller.ObjectInCluster(cluster.ClusterName, obj) {
			return nil, nil
		}

		if obj.Labels != nil {
			if obj.Labels["cattle.io/creator"] == "norman" {
				return sync(key, obj)
			}
		}

		return nil, nil
	})
}

type PandariaNamespaceController struct {
	clusterSecretsClient v1.SecretInterface
	managementSecrets    v1.SecretLister
}

func (n *PandariaNamespaceController) sync(key string, obj *corev1.Namespace) (runtime.Object, error) {
	if obj == nil || obj.DeletionTimestamp != nil {
		return nil, nil
	}
	// field.cattle.io/projectId value is <cluster name>:<project name>
	if obj.Annotations[projectIDLabel] != "" {
		parts := strings.Split(obj.Annotations[projectIDLabel], ":")
		if len(parts) == 2 {
			// on the management side, secret's namespace name equals to project name
			secrets, err := n.managementSecrets.List(parts[1], labels.NewSelector())
			if err != nil {
				return nil, err
			}
			for _, secret := range secrets {
				// for pandaria
				if val, ok := secret.Annotations["kubernetes.io/service-account.name"]; ok {
					if val == "default" {
						continue
					}
				}
				namespacedSecret := getNamespacedSecret(secret, obj.Name)
				// for pandaria
				_, err := n.clusterSecretsClient.GetNamespaced(obj.Name, namespacedSecret.Name, metav1.GetOptions{})
				if err != nil {
					if errors.IsNotFound(err) {
						_, err = n.clusterSecretsClient.Create(namespacedSecret)
						if err != nil && !errors.IsAlreadyExists(err) {
							return nil, err
						}
					}
					continue
				}
			}
		}
	}
	return nil, nil
}

func (s *ControllerPandaria) Create(obj *corev1.Secret) (runtime.Object, error) {
	return nil, s.createOrUpdate(obj, create)
}

func (s *ControllerPandaria) Updated(obj *corev1.Secret) (runtime.Object, error) {
	return nil, s.createOrUpdate(obj, update)
}

func (s *ControllerPandaria) Remove(obj *corev1.Secret) (runtime.Object, error) {
	clusterNamespaces, err := s.getClusterNamespaces(obj)
	if err != nil {
		return nil, err
	}

	for _, namespace := range clusterNamespaces {
		logrus.Infof("Deleting secret [%s] in namespace [%s]", obj.Name, namespace.Name)
		if err := s.secrets.DeleteNamespaced(namespace.Name, obj.Name, &metav1.DeleteOptions{}); err != nil && !errors.IsNotFound(err) {
			return nil, err
		}
	}
	return nil, nil
}

func (s *ControllerPandaria) getClusterNamespaces(obj *corev1.Secret) ([]*corev1.Namespace, error) {
	var toReturn []*corev1.Namespace
	projectNamespace, err := s.managementNamespaceLister.Get("", obj.Namespace)
	if err != nil {
		if errors.IsNotFound(err) {
			logrus.Warnf("Project namespace [%s] can't be found", obj.Namespace)
			return toReturn, nil
		}
		return toReturn, err
	}
	if projectNamespace.Annotations == nil {
		return toReturn, nil
	}
	if val, ok := projectNamespace.Annotations[projectNamespaceAnnotation]; !(ok && val == "true") {
		return toReturn, nil
	}

	// Ignore projects from other clusters. Project namespace name = project name, so use it to locate the project
	_, err = s.projectLister.Get(s.clusterName, projectNamespace.Name)
	if err != nil {
		if errors.IsNotFound(err) {
			return toReturn, nil
		}
		return toReturn, err
	}

	namespaces, err := s.clusterNamespaceLister.List("", labels.NewSelector())
	if err != nil {
		return toReturn, err
	}
	// system project namespace name == project.Name
	projectID := obj.Namespace

	for _, namespace := range namespaces {
		parts := strings.Split(namespace.Annotations[projectIDLabel], ":")
		if len(parts) == 2 && parts[1] == projectID {
			toReturn = append(toReturn, namespace)
		}
	}
	return toReturn, nil
}

func (s *ControllerPandaria) createOrUpdate(obj *corev1.Secret, action string) error {
	if obj.Annotations[projectIDLabel] != "" {
		parts := strings.Split(obj.Annotations[projectIDLabel], ":")
		if len(parts) == 2 {
			if parts[0] != s.clusterName {
				return nil
			}
		}
	}
	clusterNamespaces, err := s.getClusterNamespaces(obj)
	if err != nil {
		return err
	}
	for _, namespace := range clusterNamespaces {
		// copy the secret into namespace
		namespacedSecret := getNamespacedSecret(obj, namespace.Name)
		switch action {
		case create:
			// for pandaria
			_, err := s.secrets.GetNamespaced(namespace.Name, namespacedSecret.Name, metav1.GetOptions{})
			if err != nil {
				if errors.IsNotFound(err) {
					logrus.Infof("Copying secret [%s] into namespace [%s]", namespacedSecret.Name, namespace.Name)
					_, err := s.secrets.Create(namespacedSecret)
					if err != nil && !errors.IsAlreadyExists(err) {
						return err
					}
				}
				continue
			}
		case update:
			_, err := s.secrets.Update(namespacedSecret)
			if err != nil && !errors.IsNotFound(err) {
				return err
			} else if errors.IsNotFound(err) {
				_, err := s.secrets.Create(namespacedSecret)
				if err != nil {
					return err
				}
			}
		}
	}

	return nil
}
