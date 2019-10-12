package project

import (
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"

	"github.com/mitchellh/mapstructure"
	"github.com/rancher/norman/api/access"
	"github.com/rancher/norman/httperror"
	"github.com/rancher/norman/types"
	"github.com/rancher/norman/types/convert"
	"github.com/rancher/norman/types/values"
	"github.com/rancher/rancher/pkg/clustermanager"
	"github.com/rancher/rancher/pkg/resourcequota"
	validate "github.com/rancher/rancher/pkg/resourcequota"
	v3 "github.com/rancher/types/apis/management.cattle.io/v3"
	mgmtschema "github.com/rancher/types/apis/management.cattle.io/v3/schema"
	mgmtclient "github.com/rancher/types/client/management/v3"
	"github.com/rancher/types/config"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	api "k8s.io/kubernetes/pkg/apis/core"
	"k8s.io/kubernetes/pkg/quota"
)

const clusterIDField = "clusterId"
const clusterAllocatableField = "clusterAllocatable"
const clusterQuotaCPUExceedLabel = "request-cpu"
const clusterQuotaMemoryExceedLabel = "request-memory"

type projectSAICStore struct {
	types.Store
	projectLister      v3.ProjectLister
	roleTemplateLister v3.RoleTemplateLister
	scaledContext      *config.ScaledContext
	clusterLister      v3.ClusterLister
}

func SetSAICProjectStore(schema *types.Schema, mgmt *config.ScaledContext) {
	store := &projectSAICStore{
		Store:              schema.Store,
		projectLister:      mgmt.Management.Projects("").Controller().Lister(),
		roleTemplateLister: mgmt.Management.RoleTemplates("").Controller().Lister(),
		scaledContext:      mgmt,
		clusterLister:      mgmt.Management.Clusters("").Controller().Lister(),
	}
	schema.Store = store
}

func (s *projectSAICStore) Create(apiContext *types.APIContext, schema *types.Schema, data map[string]interface{}) (map[string]interface{}, error) {
	annotation, err := s.createProjectAnnotation()
	if err != nil {
		return nil, err
	}

	if err := s.validateResourceQuota(apiContext, data, ""); err != nil {
		return nil, err
	}

	values.PutValue(data, annotation, "annotations", roleTemplatesRequired)

	return s.Store.Create(apiContext, schema, data)
}

func (s *projectSAICStore) Update(apiContext *types.APIContext, schema *types.Schema, data map[string]interface{}, id string) (map[string]interface{}, error) {
	if err := s.validateResourceQuota(apiContext, data, id); err != nil {
		return nil, err
	}

	return s.Store.Update(apiContext, schema, data, id)
}

func (s *projectSAICStore) Delete(apiContext *types.APIContext, schema *types.Schema, id string) (map[string]interface{}, error) {
	parts := strings.Split(id, ":")

	proj, err := s.projectLister.Get(parts[0], parts[len(parts)-1])
	if err != nil {
		return nil, err
	}
	if proj.Labels["authz.management.cattle.io/system-project"] == "true" {
		return nil, httperror.NewAPIError(httperror.MethodNotAllowed, "System Project cannot be deleted")
	}
	return s.Store.Delete(apiContext, schema, id)
}

func (s *projectSAICStore) createProjectAnnotation() (string, error) {
	rt, err := s.roleTemplateLister.List("", labels.NewSelector())
	if err != nil {
		return "", err
	}

	annoMap := make(map[string][]string)

	for _, role := range rt {
		if role.ProjectCreatorDefault && !role.Locked {
			annoMap["required"] = append(annoMap["required"], role.Name)
		}
	}

	d, err := json.Marshal(annoMap)
	if err != nil {
		return "", err
	}

	return string(d), nil
}

func (s *projectSAICStore) validateResourceQuota(apiContext *types.APIContext, data map[string]interface{}, id string) error {
	quotaO, quotaOk := data[quotaField]
	if quotaO == nil {
		quotaOk = false
	}
	nsQuotaO, namespaceQuotaOk := data[namespaceQuotaField]
	if nsQuotaO == nil {
		namespaceQuotaOk = false
	}
	if quotaOk != namespaceQuotaOk {
		if quotaOk {
			return httperror.NewFieldAPIError(httperror.MissingRequired, namespaceQuotaField, "")
		}
		return httperror.NewFieldAPIError(httperror.MissingRequired, quotaField, "")
	} else if !quotaOk {
		return nil
	}

	var nsQuota mgmtclient.NamespaceResourceQuota
	if err := convert.ToObj(nsQuotaO, &nsQuota); err != nil {
		return err
	}
	var projectQuota mgmtclient.ProjectResourceQuota
	if err := convert.ToObj(quotaO, &projectQuota); err != nil {
		return err
	}

	projectQuotaLimit, err := limitToLimit(projectQuota.Limit)
	if err != nil {
		return err
	}
	nsQuotaLimit, err := limitToLimit(nsQuota.Limit)
	if err != nil {
		return err
	}

	// limits in namespace default quota should include all limits defined in the project quota
	projectQuotaLimitMap, err := convert.EncodeToMap(projectQuotaLimit)
	if err != nil {
		return err
	}

	nsQuotaLimitMap, err := convert.EncodeToMap(nsQuotaLimit)
	if err != nil {
		return err
	}
	if len(nsQuotaLimitMap) != len(projectQuotaLimitMap) {
		return httperror.NewFieldAPIError(httperror.MissingRequired, namespaceQuotaField, fmt.Sprintf("does not have all fields defined on a %s", quotaField))
	}

	for k := range projectQuotaLimitMap {
		if _, ok := nsQuotaLimitMap[k]; !ok {
			return httperror.NewFieldAPIError(httperror.MissingRequired, namespaceQuotaField, fmt.Sprintf("misses %s defined on a %s", k, quotaField))
		}
	}
	var clusterID string
	cID, cIDOK := data[clusterIDField]
	if cIDOK && cID != nil {
		clusterID = cID.(string)
	}
	return s.isQuotaFit(apiContext, nsQuotaLimit, projectQuotaLimit, id, clusterID)
}

func (s *projectSAICStore) isQuotaFit(apiContext *types.APIContext, nsQuotaLimit *v3.ResourceQuotaLimit,
	projectQuotaLimit *v3.ResourceQuotaLimit, id, clusterID string) error {
	// check that namespace default quota is within project quota
	isFit, msg, err := resourcequota.IsQuotaFit(nsQuotaLimit, []*v3.ResourceQuotaLimit{}, projectQuotaLimit)
	if err != nil {
		return err
	}
	if !isFit {
		return httperror.NewFieldAPIError(httperror.MaxLimitExceeded, namespaceQuotaField, fmt.Sprintf("exceeds %s on fields: %s",
			quotaField, msg))
	}

	if clusterID == "" && id == "" {
		return nil
	}

	var project mgmtclient.Project
	if id != "" {
		if err := access.ByID(apiContext, &mgmtschema.Version, mgmtclient.ProjectType, id, &project); err != nil {
			return err
		}
		// check if fields were added or removed
		// and update project's namespaces accordingly
		defaultQuotaLimitMap, err := convert.EncodeToMap(nsQuotaLimit)
		if err != nil {
			return err
		}

		usedQuotaLimitMap := map[string]interface{}{}
		if project.ResourceQuota != nil && project.ResourceQuota.UsedLimit != nil {
			usedQuotaLimitMap, err = convert.EncodeToMap(project.ResourceQuota.UsedLimit)
			if err != nil {
				return err
			}
		}

		limitToAdd := map[string]interface{}{}
		limitToRemove := map[string]interface{}{}
		for key, value := range defaultQuotaLimitMap {
			if _, ok := usedQuotaLimitMap[key]; !ok {
				limitToAdd[key] = value
			}
		}

		for key, value := range usedQuotaLimitMap {
			if _, ok := defaultQuotaLimitMap[key]; !ok {
				limitToRemove[key] = value
			}
		}

		// check that used quota is not bigger than the project quota
		for key := range limitToRemove {
			delete(usedQuotaLimitMap, key)
		}

		var usedLimitToCheck mgmtclient.ResourceQuotaLimit
		err = convert.ToObj(usedQuotaLimitMap, &usedLimitToCheck)
		if err != nil {
			return err
		}

		usedQuotaLimit, err := limitToLimit(&usedLimitToCheck)
		if err != nil {
			return err
		}
		isFit, msg, err = resourcequota.IsQuotaFit(usedQuotaLimit, []*v3.ResourceQuotaLimit{}, projectQuotaLimit)
		if err != nil {
			return err
		}
		if !isFit {
			return httperror.NewFieldAPIError(httperror.MaxLimitExceeded, quotaField, fmt.Sprintf("is below the used limit on fields: %s",
				msg))
		}

		if len(limitToAdd) == 0 && len(limitToRemove) == 0 {
			return nil
		}

		// check if default quota is enough to set on namespaces
		toAppend := &mgmtclient.ResourceQuotaLimit{}
		if err := mapstructure.Decode(limitToAdd, toAppend); err != nil {
			return err
		}

		converted, err := limitToLimit(toAppend)
		if err != nil {
			return err
		}
		mu := resourcequota.GetProjectLock(id)
		mu.Lock()
		defer mu.Unlock()

		namespacesCount, err := s.getNamespacesCount(apiContext, project)
		if err != nil {
			return err
		}
		var nsLimits []*v3.ResourceQuotaLimit
		for i := 0; i < namespacesCount; i++ {
			nsLimits = append(nsLimits, converted)
		}

		isFit, msg, err = resourcequota.IsQuotaFit(&v3.ResourceQuotaLimit{}, nsLimits, projectQuotaLimit)
		if err != nil {
			return err
		}
		if !isFit {
			return httperror.NewFieldAPIError(httperror.MaxLimitExceeded, namespaceQuotaField,
				fmt.Sprintf("exceeds project limit on fields %s when applied to all namespaces in a project",
					msg))
		}
	}

	// check that project quota is within cluster quota
	if clusterID == "" && project.ClusterID != "" {
		clusterID = project.ClusterID
	}
	cluster, err := s.clusterLister.Get("", clusterID)
	if err != nil {
		return err
	}

	clusterAllocatable := cluster.Status.Allocatable.DeepCopy()
	allocatableConverted, err := convert.EncodeToMap(clusterAllocatable)
	if err != nil {
		return err
	}

	allocatableConvertedMap := map[string]string{}
	for key, value := range allocatableConverted {
		var resourceName string
		if val, ok := resourceQuotaConversion[key]; ok {
			resourceName = val
		} else {
			resourceName = key
		}
		allocatableConvertedMap[resourceName] = convert.ToString(value)
	}

	clusterLimit := &v3.ResourceQuotaLimit{}
	if err := convert.ToObj(allocatableConvertedMap, clusterLimit); err != nil {
		return err
	}

	// aggregate project's quota limit which below to the cluster
	projects, err := s.projectLister.List(cluster.Name, labels.Everything())
	if err != nil {
		return err
	}

	var cpuExceed float64
	var memoryExceed float64
	if val, ok := cluster.Labels[clusterQuotaCPUExceedLabel]; ok {
		val64, err := strconv.ParseFloat(val, 64)
		if err != nil {
			return err
		}
		cpuExceed = val64
	}
	if val, ok := cluster.Labels[clusterQuotaMemoryExceedLabel]; ok {
		val64, err := strconv.ParseFloat(val, 64)
		if err != nil {
			return err
		}
		memoryExceed = val64
	}

	psResourceList := api.ResourceList{}
	for _, p := range projects {
		if p.Spec.ResourceQuota != nil {
			if id == fmt.Sprintf("%s:%s", p.Namespace, p.Name) {
				continue
			}
			deepCopy := p.Spec.ResourceQuota.Limit.DeepCopy()
			if deepCopy != nil {
				pConverted, err := convert.EncodeToMap(deepCopy)
				if err != nil {
					return err
				}
				pConvertedMap := map[string]string{}
				for key, value := range pConverted {
					pConvertedMap[key] = convert.ToString(value)
				}
				pLimit := &v3.ResourceQuotaLimit{}
				if err := convert.ToObj(pConvertedMap, pLimit); err != nil {
					return err
				}
				pLimitList, err := validate.ConvertLimitToResourceList(pLimit)
				if err != nil {
					return err
				}
				psResourceList = quota.Add(psResourceList, pLimitList)
			}
		}
	}

	currentProjectResourceList, err := validate.ConvertLimitToResourceList(projectQuotaLimit)
	if err != nil {
		return err
	}

	psResourceList = quota.Add(psResourceList, currentProjectResourceList)

	aggregatePLimit, err := convertResourceListToLimit(psResourceList)
	if err != nil {
		return err
	}

	aggregatePList, err := convertLimitToResourceList(aggregatePLimit, cpuExceed, memoryExceed)
	if err != nil {
		return err
	}

	aggregatePLimit, err = convertResourceListToLimit(aggregatePList)
	if err != nil {
		return err
	}

	isFit, msg, err = resourcequota.IsProjectQuotaFitCluster(aggregatePLimit, clusterLimit)
	if err != nil {
		return err
	}
	if !isFit {
		return httperror.NewFieldAPIError(httperror.MaxLimitExceeded, quotaField, fmt.Sprintf("exceeds %s on fields: %s",
			clusterAllocatableField, msg))
	}

	return nil
}

func (s *projectSAICStore) getNamespacesCount(apiContext *types.APIContext, project mgmtclient.Project) (int, error) {
	cluster, err := s.clusterLister.Get("", project.ClusterID)
	if err != nil {
		return 0, err
	}

	kubeConfig, err := clustermanager.ToRESTConfig(cluster, s.scaledContext)
	if kubeConfig == nil || err != nil {
		return 0, err
	}

	clusterContext, err := config.NewUserContext(s.scaledContext, *kubeConfig, cluster.Name)
	if err != nil {
		return 0, err
	}
	namespaces, err := clusterContext.Core.Namespaces("").List(metav1.ListOptions{})
	if err != nil {
		return 0, err
	}
	count := 0
	for _, n := range namespaces.Items {
		if n.Annotations == nil {
			continue
		}
		if n.Annotations["field.cattle.io/projectId"] == project.ID {
			count++
		}
	}

	return count, nil
}

func convertResourceListToLimit(rList api.ResourceList) (*v3.ResourceQuotaLimit, error) {
	converted, err := convert.EncodeToMap(rList)
	if err != nil {
		return nil, err
	}

	convertedMap := map[string]string{}
	for key, value := range converted {
		convertedMap[key] = convert.ToString(value)
	}

	toReturn := &v3.ResourceQuotaLimit{}
	err = convert.ToObj(convertedMap, toReturn)

	return toReturn, err
}

var resourceQuotaConversion = map[string]string{
	"replicationcontrollers":  "replicationControllers",
	"configmaps":              "configMaps",
	"persistentvolumeclaims":  "persistentVolumeClaims",
	"services.nodeports":      "servicesNodePorts",
	"services.loadbalancers":  "servicesLoadBalancers",
	"services.allocatedports": "servicesAllocatedPorts",
	"storage":                 "requestsStorage",
	"cpu":                     "limitsCpu",
	"memory":                  "limitsMemory",
}

func convertMemoryQuota(memoryValue string) (float64, string, error) {
	unitList := []string{"K", "M", "G", "T", "P", "E"}
	iUnitList := []string{"Ki", "Mi", "Gi", "Ti", "Pi", "Ei"}

	reg := "([^0-9])([a-zA-Z]+)?"
	quotaReg := regexp.MustCompile(reg)
	units := quotaReg.FindAllString(memoryValue, -1)
	if len(units) == 0 {
		return 0, "", nil
	}

	for index, unit := range unitList {
		if units[0] == unit {
			return math.Pow(1000, float64(index+1)), units[0], nil
		}
	}

	for index, iUnit := range iUnitList {
		if units[0] == iUnit {
			return math.Pow(1024, float64(index+1)), units[0], nil
		}
	}

	return 0, "", fmt.Errorf("Got unexpected memory quota %v", memoryValue)
}

func convertLimitToResourceList(limit *v3.ResourceQuotaLimit, cpuExceed, memoryExceed float64) (api.ResourceList, error) {
	toReturn := api.ResourceList{}
	converted, err := convert.EncodeToMap(limit)
	if err != nil {
		return nil, err
	}
	for key, value := range converted {
		q, err := resource.ParseQuantity(convert.ToString(value))
		if err != nil {
			return nil, err
		}
		if key == "limitsCpu" && cpuExceed > 0 {
			val64 := cpuExceed * float64(q.MilliValue())
			q, err = resource.ParseQuantity(fmt.Sprintf("%vm", val64))
			if err != nil {
				return nil, err
			}
		}
		if key == "limitsMemory" && memoryExceed > 0 {
			baseValue, unit, err := convertMemoryQuota(q.String())
			if err != nil {
				return nil, err
			}
			val64 := memoryExceed * float64(q.Value())
			if baseValue != 0 {
				val64 = val64 / baseValue
			}
			q, err = resource.ParseQuantity(fmt.Sprintf("%v%s", val64, unit))
			if err != nil {
				return nil, err
			}
		}
		toReturn[api.ResourceName(key)] = q
	}
	return toReturn, nil
}
