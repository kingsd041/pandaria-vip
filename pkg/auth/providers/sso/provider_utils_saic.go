package sso

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/pkg/errors"
	"github.com/rancher/norman/types/slice"
	"github.com/rancher/rancher/pkg/resourcequota"
	"github.com/rancher/rancher/pkg/settings"
	v3 "github.com/rancher/types/apis/management.cattle.io/v3"
	"github.com/sirupsen/logrus"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
)

var (
	InsufficientQuotaStatus = 1
	OtherFailedStatus       = 2
)

type ResourceQuotaExceedError struct {
	Message string
}

func (e *ResourceQuotaExceedError) Error() string {
	return e.Message
}

type TenantLoginFailedCluster struct {
	ID                   string `json:"id"`
	Name                 string `json:"name"`
	RegionClusterKeyName string `json:"regionClusterKeyName"`
	Status               int    `json:"status"`
	Message              string `json:"message"`
}

func (sp *ssoProvider) GetUserClustersAndProjects(tenantActions *TenantActions, user DUser) ([]*v3.Cluster, error) {
	regionClusters := []string{}
	clusterActions := map[string][]string{}
	// find cluster list in rancher with regionClusterKeyName label
	for _, c := range tenantActions.Data.ServiceRegionResp {
		if len(c.Actions) > 0 {
			regionClusters = append(regionClusters, c.RegionClusterKeyName)
			clusterActions[c.RegionClusterKeyName] = c.Actions
		}
	}

	if len(regionClusters) == 0 {
		return nil, nil
	}

	labelSelector := &metav1.LabelSelector{
		MatchExpressions: []metav1.LabelSelectorRequirement{
			{
				Key:      "regionClusterKeyName",
				Operator: metav1.LabelSelectorOpIn,
				Values:   regionClusters,
			},
		},
	}
	selector, err := metav1.LabelSelectorAsSelector(labelSelector)
	clusterList, err := sp.clusterLister.List("", selector)
	if err != nil {
		return nil, err
	}
	failedClusters := []TenantLoginFailedCluster{}
	for _, cluster := range clusterList {
		clusterKeyName := cluster.Labels[RegionClusterKeyNameLabel]
		if clusterAction, ok := clusterActions[clusterKeyName]; ok {
			logrus.Debugf("login for cluster %v with actions %v for tenant %s, user %s", clusterKeyName, clusterAction, user.TenantShortName, user.Username)
			project, err := sp.checkProjectWithClusterAndUser(cluster, user)
			if err != nil {
				failedCluster := TenantLoginFailedCluster{
					ID:                   cluster.Name,
					Name:                 cluster.Name,
					RegionClusterKeyName: clusterKeyName,
					Message:              err.Error(),
				}
				// check is quota exceed error
				_, isQuotaExceedErr := err.(*ResourceQuotaExceedError)
				if isQuotaExceedErr {
					failedCluster.Status = InsufficientQuotaStatus
				} else {
					failedCluster.Status = OtherFailedStatus
				}
				failedClusters = append(failedClusters, failedCluster)
				continue
			}
			// don't need return error if project logging failed
			if err := sp.ensureProjectLogging(cluster, project, user); err != nil {
				logrus.Errorf("failed to ensure project logging, error: %s", err.Error())
			}
			// don't need return error if project role binding fails
			if err := sp.ensureProjectRoleBinding(clusterAction, project, user, cluster); err != nil {
				logrus.Errorf("failed to ensure project role binding of project %s for user %+v, error: %s", project.Name, user, err.Error())
			}

			if err := sp.ensureClusterRoleBinding(clusterAction, user, cluster); err != nil {
				logrus.Errorf("failed to ensure cluster role binding of cluster %s for user %+v, error: %s", cluster.Name, user, err.Error())
			}
		}
	}

	if len(failedClusters) > 0 {
		result, e := json.Marshal(failedClusters)
		if e != nil {
			logrus.Errorf("convert failed cluster list %v error: %v", failedClusters, e)
			return nil, e
		}
		return clusterList, &SAICLoginError{TenantLoginFailedClusters: string(result), Code: "00000", Message: ""}
	}

	return clusterList, nil
}

func (sp *ssoProvider) checkProjectWithClusterAndUser(cluster *v3.Cluster, user DUser) (*v3.Project, error) {
	tenantIDLabels := labels.Set(map[string]string{"tenant-id": user.TenantID})
	rules := map[string][]string{
		"required": nil,
	}
	data, err := json.Marshal(rules)
	if err != nil {
		return nil, err
	}
	annotation := string(data)
	return sp.isAvailableProject(&v3.Project{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "pro-",
			Labels:       tenantIDLabels,
			Namespace:    cluster.Name,
			ClusterName:  cluster.Name,
			Annotations: map[string]string{
				"authz.management.cattle.io/creator-role-bindings": annotation,
			},
		},
		Spec: v3.ProjectSpec{
			DisplayName: user.TenantShortName,
		},
	}, cluster)
}

func (sp *ssoProvider) isAvailableProject(project *v3.Project, cluster *v3.Cluster) (*v3.Project, error) {
	projectList, err := sp.projectLister.List(project.Namespace, labels.Set(project.Labels).AsSelector())
	if err != nil {
		return nil, err
	}
	found := false
	for _, p := range projectList {
		if project.Spec.DisplayName == p.Spec.DisplayName {
			project = p
			found = true
			break
		}
	}

	if !found {
		logrus.Debugf("Need to create new project for tenant %v on cluster %s", project.Labels, project.Namespace)
		// get all projects on same cluster to validate quota limit
		allProjects, err := sp.projectLister.List(project.Namespace, labels.Everything())
		if err != nil {
			return nil, err
		}
		logrus.Debugf("Get all projects %d on cluster %s", len(allProjects), project.Namespace)
		// get saic tenant default quota
		project.Spec.ResourceQuota = &v3.ProjectResourceQuota{
			Limit: sp.defaultProjectQuota(),
		}
		project.Spec.NamespaceDefaultResourceQuota = &v3.NamespaceResourceQuota{
			Limit: sp.defaultProjectQuota(),
		}
		logrus.Debugf("Before check project: %+v", *project)
		// check quota
		err = isQuotaFit(allProjects, cluster, project)
		if err != nil {
			logrus.Errorf("Failed to create project: %v", err)
			return nil, err
		}
		// create project
		p, err := sp.projectInterface.Create(project)
		if err == nil || apierrors.IsAlreadyExists(err) {
			project = p
		} else {
			logrus.Errorf("create project err: %s", err.Error())
			return nil, err
		}

	}

	if err := runFirstTicker(sp.ctx, 500*time.Millisecond, 5*time.Second, func() error {
		origin := project
		project, err = sp.projectLister.Get(project.Namespace, project.Name)
		if err != nil {
			project = origin
			return errors.Wrapf(err, "failed to get project %s/%s from lister", origin.Namespace, origin.Name)
		}
		if v3.NamespaceBackedResource.IsTrue(project) {
			return nil
		}
		return fmt.Errorf("project %s is not ready", project.Name)
	}); err != nil {
		return project, err
	}

	if !v3.NamespaceBackedResource.IsTrue(project) {
		logrus.Errorf("timeout waiting for project %s has condition %s", project.Name, v3.NamespaceBackedResource)
	}

	// add tenant namespace to project with label 'tenant.saic.pandaria.io/tenantId'
	err = sp.ensureNamespace(project)
	if err != nil {
		logrus.Errorf("add tenant namespace to project failed: %v", err)
	}

	return project, nil
}

func (sp *ssoProvider) ensureNamespace(project *v3.Project) error {
	logrus.Debugf("find namespace for tenant %s", project.Labels["tenant-id"])
	// check whether need ensure namespace
	usercontext, err := sp.clusterManager.UserContext(project.Namespace)
	if err != nil {
		return errors.Wrap(err, "failed to get usercontext")
	}
	namespaceList, err := usercontext.Core.Namespaces("").List(metav1.ListOptions{LabelSelector: fmt.Sprintf("%s=%s", TenantNamespaceLabel, project.Labels["tenant-id"])})
	if err != nil {
		return errors.Wrap(err, "failed to get namespace list")
	}
	if namespaceList != nil && len(namespaceList.Items) > 0 {
		for _, ns := range namespaceList.Items {
			newNs := ns.DeepCopy()
			newNs.Annotations[projectIDAnno] = project.Namespace + ":" + project.Name
			_, err = usercontext.Core.Namespaces("").Update(newNs)
			if err != nil && !apierrors.IsConflict(err) {
				return err
			}
		}
	}

	return nil
}

func (sp *ssoProvider) defaultProjectQuota() v3.ResourceQuotaLimit {
	limit := v3.ResourceQuotaLimit{}
	limit.RequestsCPU = settings.SaicCPUQuota.Get()
	limit.LimitsCPU = settings.SaicCPUQuota.Get()
	limit.RequestsMemory = settings.SaicMemoryQuota.Get()
	limit.LimitsMemory = settings.SaicMemoryQuota.Get()
	limit.Services = settings.SaicServiceQuota.Get()
	limit.ConfigMaps = settings.SaicConfigMapQuota.Get()
	limit.ServicesAllocatedPorts = settings.SaicAllocatedPortQuota.Get()
	limit.PersistentVolumeClaims = settings.SaicPersistentVolumeClaimQuota.Get()
	limit.ReplicationControllers = settings.SaicReplicationControllerQuota.Get()
	limit.Secrets = settings.SaicSecretQuota.Get()
	limit.ServicesLoadBalancers = settings.SaicLoadBalancerQuota.Get()
	limit.ServicesNodePorts = settings.SaicNodePortQuota.Get()
	limit.RequestsStorage = settings.SaicStorageQuota.Get()

	return limit
}

func isQuotaFit(projects []*v3.Project, cluster *v3.Cluster, p *v3.Project) error {
	projectQuotaLimit := p.Spec.ResourceQuota.Limit
	logrus.Debugf("check quota before create project with quota: %+v", projectQuotaLimit)
	// check project quota fit cluster
	isFit, msg, err := resourcequota.IsProjectQuotaFitCluster(projects, cluster, "", &projectQuotaLimit)
	if err != nil {
		return err
	}
	if !isFit {
		return &ResourceQuotaExceedError{Message: msg}
	}

	return nil
}

func (sp *ssoProvider) ensureProjectRoleBinding(actions []string, project *v3.Project, user DUser, cluster *v3.Cluster) error {
	projectRoleList := []string{}
	for _, action := range actions {
		if role, ok := roleMap[action]; ok {
			if isProject, ok := roleScope[role]; isProject && ok {
				projectRoleList = append(projectRoleList, role)
			}
		}
	}

	logrus.Debugf("ensure project role %v for user %s", projectRoleList, user.Username)

	set := labels.Set(map[string]string{AuthRoleBindingLabel: user.IamOpenID})
	prtbList, err := sp.prtbLister.List(project.Name, set.AsSelector())
	if err != nil && !apierrors.IsNotFound(err) {
		return err
	}

	deleteRoleList := []*v3.ProjectRoleTemplateBinding{}
	newRoleList := []string{}

	for _, prtb := range prtbList {
		logrus.Debugf("get exist project role binding %s, with role %s", prtb.Name, prtb.RoleTemplateName)
		if !slice.ContainsString(projectRoleList, prtb.RoleTemplateName) {
			deleteRoleList = append(deleteRoleList, prtb)
		}
	}

	for _, role := range projectRoleList {
		found := false
		for _, prtb := range prtbList {
			if prtb.RoleTemplateName == role {
				found = true
				break
			}
		}
		if !found {
			newRoleList = append(newRoleList, role)
		}
	}

	for _, prtb := range deleteRoleList { // delete case
		logrus.Debugf("user %s is no longer project %s role %s, delete it", user.IamOpenID, project.Name, actions)
		err = sp.prtbClient.DeleteNamespaced(project.Name, prtb.Name, &metav1.DeleteOptions{})
		if err != nil {
			return err
		}
	}

	// create case
	displayName := user.Username
	if displayName == "" {
		displayName = user.IamOpenID
	}
	for _, projectRole := range newRoleList {
		logrus.Debugf("create new project role binding for %s, user %s", projectRole, displayName)
		_, err = sp.prtbClient.Create(&v3.ProjectRoleTemplateBinding{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: fmt.Sprintf("%s-", user.IamOpenID),
				Namespace:    project.Name,
				ClusterName:  project.ClusterName,
				Annotations:  map[string]string{"auth.cattle.io/principal-display-name": displayName},
				Labels:       map[string]string{AuthRoleBindingLabel: user.IamOpenID},
			},
			ProjectName:       project.Namespace + ":" + project.Name,
			RoleTemplateName:  projectRole,
			UserPrincipalName: Name + "_user://" + user.IamOpenID,
		})
		if err != nil && !apierrors.IsAlreadyExists(err) {
			return err
		}
	}

	return nil
}

func (sp *ssoProvider) ensureClusterRoleBinding(actions []string, user DUser, cluster *v3.Cluster) error {
	toDelete := true
	var role string
	if slice.ContainsString(actions, "cluster_admin") {
		role = roleMap["cluster_admin"]
		toDelete = false
	}

	crtb, err := sp.crtbLister.Get(cluster.Name, user.IamOpenID)
	if err != nil && !apierrors.IsNotFound(err) {
		return err
	}

	if apierrors.IsNotFound(err) && !toDelete { //create case
		displayName := user.Username
		if displayName == "" {
			displayName = user.IamOpenID
		}
		crtb, err = sp.crtbClient.Create(&v3.ClusterRoleTemplateBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:        user.IamOpenID,
				Namespace:   cluster.Name,
				Annotations: map[string]string{"auth.cattle.io/principal-display-name": displayName},
			},
			UserPrincipalName: Name + "_user://" + user.IamOpenID,
			RoleTemplateName:  role,
		})
		if err != nil && !apierrors.IsAlreadyExists(err) {
			return err
		}
	} else if err == nil && toDelete { //delete case
		logrus.Debugf("user %s is no longer cluster %s owner, delete crtb", user.IamOpenID, cluster.Name)
		return sp.crtbClient.DeleteNamespaced(cluster.Name, crtb.Name, &metav1.DeleteOptions{})
	}

	return nil
}
