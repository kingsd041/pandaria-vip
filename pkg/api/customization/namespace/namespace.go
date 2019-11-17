package namespace

import (
	"encoding/json"
	"time"

	"github.com/pkg/errors"
	"github.com/rancher/norman/api/access"
	"github.com/rancher/norman/httperror"
	"github.com/rancher/norman/parse"
	"github.com/rancher/norman/types"
	"github.com/rancher/norman/types/convert"
	"github.com/rancher/rancher/pkg/clustermanager"
	"github.com/rancher/rancher/pkg/controllers/user/helm"
	"github.com/rancher/rancher/pkg/ref"
	"github.com/rancher/types/apis/cluster.cattle.io/v3/schema"
	v3 "github.com/rancher/types/apis/management.cattle.io/v3"
	client "github.com/rancher/types/client/cluster/v3"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/cache"
)

var (
	projectIDFieldLabel     = "field.cattle.io/projectId"
	namespaceOwnerMap       = cache.NewLRUExpireCache(1000)
	resourceQuotaAnnotation = "field.cattle.io/resourceQuota"
	limitRangeAnnotation    = "field.cattle.io/containerDefaultResourceLimit"
	TenantNamespaceLabel    = "tenant.saic.pandaria.io/tenantId"
)

func updateNamespaceOwnerMap(apiContext *types.APIContext) error {
	var namespaces []client.Namespace
	if err := access.List(apiContext, &schema.Version, client.NamespaceType, &types.QueryOptions{}, &namespaces); err != nil {
		return err
	}

	for _, namespace := range namespaces {
		namespaceOwnerMap.Add(namespace.Name, namespace.ProjectID, time.Hour)
	}

	return nil
}

func ProjectMap(apiContext *types.APIContext, refresh bool) (map[string]string, error) {
	if refresh {
		err := updateNamespaceOwnerMap(apiContext)
		if err != nil {
			return nil, err
		}
	}

	data := map[string]string{}
	for _, key := range namespaceOwnerMap.Keys() {
		if val, ok := namespaceOwnerMap.Get(key); ok {
			data[key.(string)] = val.(string)
		}
	}

	return data, nil
}

type ActionWrapper struct {
	ClusterManager *clustermanager.Manager
}

func (w ActionWrapper) ActionHandler(actionName string, action *types.Action, apiContext *types.APIContext) error {
	actionInput, err := parse.ReadBody(apiContext.Request)
	if err != nil {
		return err
	}
	switch actionName {
	case "move":
		clusterID := w.ClusterManager.ClusterName(apiContext)
		_, projectID := ref.Parse(convert.ToString(actionInput["projectId"]))
		userContext, err := w.ClusterManager.UserContext(clusterID)
		if err != nil {
			if !kerrors.IsNotFound(err) {
				return err
			}
			return httperror.NewAPIError(httperror.NotFound, err.Error())
		}

		nsClient := userContext.Core.Namespaces("")
		ns, err := nsClient.Get(apiContext.ID, metav1.GetOptions{})
		if err != nil {
			if !kerrors.IsNotFound(err) {
				return err
			}
			return httperror.NewAPIError(httperror.NotFound, err.Error())
		}
		updateNS := ns.DeepCopy()
		// for pandaria
		delete(updateNS.Annotations, resourceQuotaAnnotation)
		delete(updateNS.Annotations, limitRangeAnnotation)
		// SAIC: Add tenantID for namespace
		var tenantID string
		nsQuota := &v3.NamespaceResourceQuota{}
		if projectID != "" {
			project, err := userContext.Management.Management.Projects(clusterID).Get(projectID, metav1.GetOptions{})
			if err != nil {
				return err
			}
			if project.Spec.ResourceQuota != nil {
				// SAIC: Add project resource quota to ns
				projectQuotaLimit := project.Spec.ResourceQuota.Limit
				nsQuotaLimit := &v3.ResourceQuotaLimit{}
				projectQuotaLimitMap, err := convert.EncodeToMap(projectQuotaLimit)
				if err != nil {
					return err
				}
				nsQuotaLimitMap := map[string]string{}
				for quotaKey := range projectQuotaLimitMap {
					nsQuotaLimitMap[quotaKey] = "0"
				}
				err = convert.ToObj(nsQuotaLimitMap, nsQuotaLimit)
				if err != nil {
					return err
				}
				nsQuota.Limit = *nsQuotaLimit
				bytes, err := json.Marshal(nsQuota)
				if err != nil {
					return err
				}
				quotaToUpdate := string(bytes)
				updateNS.Annotations[resourceQuotaAnnotation] = quotaToUpdate
			}
			tenantID = project.Labels["tenant-id"]
		}

		if updateNS.Annotations[helm.AppIDsLabel] != "" {
			return errors.New("namespace is currently being used")
		}
		if projectID == "" {
			delete(updateNS.Annotations, projectIDFieldLabel)
		} else {
			updateNS.Annotations[projectIDFieldLabel] = convert.ToString(actionInput["projectId"])
			// SAIC: Add tenantID for namespace
			if tenantID != "" {
				updateNS.Labels[TenantNamespaceLabel] = tenantID
			}
		}
		if _, err := nsClient.Update(updateNS); err != nil {
			return err
		}
	default:
		return errors.New("invalid action")
	}
	return nil
}

func NewFormatter(next types.Formatter) types.Formatter {
	return func(request *types.APIContext, resource *types.RawResource) {
		if next != nil {
			next(request, resource)
		}
		annotations := convert.ToMapInterface(resource.Values["annotations"])
		if convert.ToString(annotations[helm.AppIDsLabel]) == "" {
			resource.AddAction(request, "move")
		}
	}
}
