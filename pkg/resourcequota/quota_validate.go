package resourcequota

import (
	"fmt"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rancher/norman/types/convert"
	v3 "github.com/rancher/types/apis/management.cattle.io/v3"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/util/cache"
	api "k8s.io/kubernetes/pkg/apis/core"
	"k8s.io/kubernetes/pkg/quota"
)

const clusterQuotaCPUExceedLabel = "request-cpu"
const clusterQuotaMemoryExceedLabel = "request-memory"

var (
	projectLockCache = cache.NewLRUExpireCache(1000)
)

func GetProjectLock(projectID string) *sync.Mutex {
	val, ok := projectLockCache.Get(projectID)
	if !ok {
		projectLockCache.Add(projectID, &sync.Mutex{}, time.Hour)
		val, _ = projectLockCache.Get(projectID)
	}
	mu := val.(*sync.Mutex)
	return mu
}

func IsQuotaFit(nsLimit *v3.ResourceQuotaLimit, nsLimits []*v3.ResourceQuotaLimit, projectLimit *v3.ResourceQuotaLimit) (bool, string, error) {
	nssResourceList := api.ResourceList{}
	nsResourceList, err := ConvertLimitToResourceList(nsLimit)
	if err != nil {
		return false, "", err
	}
	nssResourceList = quota.Add(nssResourceList, nsResourceList)

	for _, nsLimit := range nsLimits {
		nsResourceList, err := ConvertLimitToResourceList(nsLimit)
		if err != nil {
			return false, "", err
		}
		nssResourceList = quota.Add(nssResourceList, nsResourceList)
	}

	projectResourceList, err := ConvertLimitToResourceList(projectLimit)
	if err != nil {
		return false, "", err
	}

	allowed, exceeded := quota.LessThanOrEqual(nssResourceList, projectResourceList)
	if allowed {
		return true, "", nil
	}
	failedHard := quota.Mask(nssResourceList, exceeded)
	return false, prettyPrint(failedHard), nil
}

func ConvertLimitToResourceList(limit *v3.ResourceQuotaLimit) (api.ResourceList, error) {
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
		toReturn[api.ResourceName(key)] = q
	}
	return toReturn, nil
}

func prettyPrint(item api.ResourceList) string {
	parts := []string{}
	keys := []string{}
	for key := range item {
		keys = append(keys, string(key))
	}
	sort.Strings(keys)
	for _, key := range keys {
		value := item[api.ResourceName(key)]
		constraint := key + "=" + value.String()
		parts = append(parts, constraint)
	}
	return strings.Join(parts, ",")
}

func IsProjectQuotaFitCluster(projects []*v3.Project, cluster *v3.Cluster, id string, projectQuotaLimit *v3.ResourceQuotaLimit) (bool, string, error) {
	var cpuExceed float64
	var memoryExceed float64
	if val, ok := cluster.Labels[clusterQuotaCPUExceedLabel]; ok {
		val64, err := strconv.ParseFloat(val, 64)
		if err != nil {
			return false, "", err
		}
		cpuExceed = val64
	}
	if val, ok := cluster.Labels[clusterQuotaMemoryExceedLabel]; ok {
		val64, err := strconv.ParseFloat(val, 64)
		if err != nil {
			return false, "", err
		}
		memoryExceed = val64
	}

	clusterAllocatable := cluster.Status.Allocatable.DeepCopy()
	allocatableConverted, err := convert.EncodeToMap(clusterAllocatable)
	if err != nil {
		return false, "", err
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
		return false, "", err
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
					return false, "", err
				}
				pConvertedMap := map[string]string{}
				for key, value := range pConverted {
					pConvertedMap[key] = convert.ToString(value)
				}
				pLimit := &v3.ResourceQuotaLimit{}
				if err := convert.ToObj(pConvertedMap, pLimit); err != nil {
					return false, "", err
				}
				pLimitList, err := ConvertLimitToResourceList(pLimit)
				if err != nil {
					return false, "", err
				}
				psResourceList = quota.Add(psResourceList, pLimitList)
			}
		}
	}

	currentProjectResourceList, err := ConvertLimitToResourceList(projectQuotaLimit)
	if err != nil {
		return false, "", err
	}

	psResourceList = quota.Add(psResourceList, currentProjectResourceList)

	aggregatePLimit, err := convertResourceListToLimit(psResourceList)
	if err != nil {
		return false, "", err
	}

	aggregatePList, err := convertLimitToResourceList(aggregatePLimit, cpuExceed, memoryExceed)
	if err != nil {
		return false, "", err
	}

	aggregateResourceList := api.ResourceList{}
	aggregateResourceList = quota.Add(aggregateResourceList, aggregatePList)

	clusterResourceList, err := ConvertLimitToResourceList(clusterLimit)
	if err != nil {
		return false, "", err
	}

	allowed, exceeded := QuotaLessThanOrEqual(aggregateResourceList, clusterResourceList)
	if allowed {
		return true, "", nil
	}
	failedHard := quota.Mask(aggregateResourceList, exceeded)
	return false, prettyPrint(failedHard), nil
}

// QuotaLessThanOrEqual returns true if a < b for each key in b
// If false, it returns the keys in a that exceeded b
func QuotaLessThanOrEqual(a api.ResourceList, b api.ResourceList) (bool, []api.ResourceName) {
	result := true
	resourceNames := []api.ResourceName{}
	for key, value := range b {
		if value.IsZero() {
			continue
		}
		if other, found := a[key]; found {
			if other.Cmp(value) > 0 {
				result = false
				resourceNames = append(resourceNames, key)
			}
		}
	}
	return result, resourceNames
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
