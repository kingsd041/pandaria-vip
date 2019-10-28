package sso

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/rancher/rancher/pkg/settings"
	"github.com/rancher/rancher/pkg/ticker"
	v3 "github.com/rancher/types/apis/management.cattle.io/v3"
	"github.com/rancher/types/config"
	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
)

const (
	creatorIDAnno             = "field.cattle.io/creatorId"
	projectIDAnno             = "field.cattle.io/projectId"
	RegionClusterKeyNameLabel = "regionClusterKeyName"
	AuthRoleBindingLabel      = "pandaria.authz.saic.io/IamOpenID"
	TenantNamespaceLabel      = "tenant.saic.pandaria.io/tenantId"
)

var (
	roleScope = map[string]bool{
		"project-owner":          true,
		"project-member":         true,
		"quota-manager":          true,
		"network-policy-manager": true,
		"cluster-owner":          false,
	}
	globalRole = []string{"quota-manager", "network-policy-manager"}
)

func (sp *ssoProvider) getClusterWithlabels(set labels.Set) (*v3.Cluster, error) {
	clusterList, err := sp.clusterLister.List("", set.AsSelector())
	if err != nil {
		logrus.Errorf("failed to get clusterList error: %s", err.Error())
		return nil, err
	}
	if len(clusterList) != 0 {
		return clusterList[0], nil
	}
	return nil, fmt.Errorf("cluster not found with labels %+v", set)
}

func (sp *ssoProvider) getProjectWithClusterAndUser(cluster *v3.Cluster, user DUser) (*v3.Project, *corev1.Namespace, error) {
	tenantIDLabels := labels.Set(map[string]string{"tenant-id": user.TenantID})
	rules := map[string][]string{
		"required": nil,
	}
	data, err := json.Marshal(rules)
	if err != nil {
		return nil, nil, err
	}
	annotation := string(data)
	return sp.ensureSAICProject(&v3.Project{
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
	})
}

func (sp *ssoProvider) GetUserClusterAndProject(user DUser, clusterKey string) (*v3.Cluster, *v3.Project, error) {
	var cluster *v3.Cluster
	var project *v3.Project
	var err error
	serviceIDLabels := labels.Set(map[string]string{"service-id": user.ServiceID})
	clusterKeyLabels := labels.Set(map[string]string{"regionClusterKeyName": clusterKey})
	if isUsingClusterKey(user) {
		cluster, err = sp.getClusterWithlabels(clusterKeyLabels)
	} else {
		cluster, err = sp.getClusterWithlabels(serviceIDLabels)
	}
	if err != nil {
		return nil, nil, err
	}

	project, _, err = sp.getProjectWithClusterAndUser(cluster, user)
	if err != nil {
		return nil, nil, err
	}

	return cluster, project, nil
}

func isUsingClusterKey(user DUser) bool {
	return user.ServiceID == ""
}

func (sp *ssoProvider) reconcileProjectRoleBinding(project *v3.Project, amClient *amClient, user DUser, clusterKeyName string) error {
	projectRole, err := GetRoleFromUser(user, amClient, clusterKeyName)
	if err != nil {
		return err
	}

	toDelete := false
	if isProject, ok := roleScope[projectRole]; !ok || !isProject {
		toDelete = true
	}

	prtb, err := sp.prtbLister.Get(project.Name, user.IamOpenID)
	if err != nil && !apierrors.IsNotFound(err) {
		return err
	}

	if apierrors.IsNotFound(err) && !toDelete { //create case
		displayName := user.Username
		if displayName == "" {
			displayName = user.IamOpenID
		}
		prtb, err = sp.prtbClient.Create(&v3.ProjectRoleTemplateBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:        user.IamOpenID,
				Namespace:   project.Name,
				ClusterName: project.ClusterName,
				Annotations: map[string]string{"auth.cattle.io/principal-display-name": displayName},
			},
			ProjectName:       project.Namespace + ":" + project.Name,
			RoleTemplateName:  projectRole,
			UserPrincipalName: Name + "_user://" + user.IamOpenID,
		})
		if err != nil && !apierrors.IsAlreadyExists(err) {
			return err
		}
		return nil
	} else if err == nil && toDelete { // delete case
		logrus.Infof("user %s is no longer project %s role %s, delete it", user.IamOpenID, project.Name, projectRole)
		return sp.prtbClient.DeleteNamespaced(project.Name, prtb.Name, &metav1.DeleteOptions{})
	} else if err == nil { // update case
		// update prtb if role is changed
		if prtb.RoleTemplateName != projectRole {
			newObj := prtb.DeepCopy()
			newObj.RoleTemplateName = projectRole
			_, err := sp.prtbClient.Update(newObj)
			return err
		}
	}

	return nil
}

func (sp *ssoProvider) ensureProjectLogging(cluster *v3.Cluster, project *v3.Project, user DUser) error {
	datacenter := cluster.Labels["datacenter"]
	kafkaip := cluster.Labels["kafka-server"]
	securekafka := cluster.Labels["secure-kafka"]
	tenantLabels := labels.Set(map[string]string{"tenant-id": project.Labels["tenant-id"]})

	kfks := strings.Split(strings.Replace(kafkaip, "-", ":", -1), "_")
	if kafkaip != "" {
		if sf, _ := strconv.ParseBool(securekafka); sf {
			for k := range kfks {
				kfks[k] = "https://" + kfks[k]
			}
		} else {
			for k := range kfks {
				kfks[k] = "http://" + kfks[k]
			}
		}
	}

	var projectLogging *v3.ProjectLogging
	projectLoggingList, err := sp.projectLoggingLister.List(project.Name, tenantLabels.AsSelector())
	if err != nil {
		return errors.Wrapf(err, "failed to list project logging with labels %+v", tenantLabels)
	}

	if len(projectLoggingList) == 0 {
		projectLogging, err = sp.projectLoggingInterface.Create(&v3.ProjectLogging{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "pl-",
				Labels:       tenantLabels,
				Namespace:    project.Name,
				ClusterName:  project.ClusterName,
				Annotations: map[string]string{
					creatorIDAnno: user.TenantShortName,
				},
			},
			Spec: v3.ProjectLoggingSpec{
				LoggingTargets: v3.LoggingTargets{
					KafkaConfig: &v3.KafkaConfig{
						Topic:           user.TenantShortName + "-" + datacenter,
						BrokerEndpoints: kfks,
					},
				},
				LoggingCommonField: v3.LoggingCommonField{
					OutputFlushInterval: 3,
				},
				ProjectName: project.Namespace + ":" + project.Name,
			},
		})
		if err != nil && !apierrors.IsAlreadyExists(err) {
			return errors.Wrapf(err, "failed to create project logging for project %s", project.Name)
		}
	} else {
		//update ProjectLogging
		logrus.Debugln("update ProjectLogging")
		projectLogging = projectLoggingList[0]
		newObj := projectLogging.DeepCopy()
		newObj.Spec = v3.ProjectLoggingSpec{
			LoggingTargets: v3.LoggingTargets{
				KafkaConfig: &v3.KafkaConfig{
					Topic:           user.TenantShortName + "-" + datacenter,
					BrokerEndpoints: kfks,
				},
			},
			LoggingCommonField: v3.LoggingCommonField{
				OutputFlushInterval: 3,
			},
			ProjectName: project.Namespace + ":" + project.Name,
		}

		if !reflect.DeepEqual(projectLogging, newObj) {
			if _, err = sp.projectLoggingInterface.Update(newObj); err != nil {
				return errors.Wrapf(err, "failed to update project logging %s for project %s", projectLogging.Name, project.Name)
			}
		}
	}
	return nil
}

func (sp *ssoProvider) ensureResourceQuota(project *v3.Project, user DUser, tenantInfo *TenantInfo) error {
	usercontext, err := sp.clusterManager.UserContext(project.Namespace)
	if err != nil {
		return errors.Wrap(err, "failed to get usercontext")
	}
	namespace, err := sp.getSAICTenantNamespace(usercontext, project)
	if err != nil {
		return err
	}

	hard := map[corev1.ResourceName]resource.Quantity{}
	if tenantInfo == nil {
		cpuQuantity, err := resource.ParseQuantity(settings.SaicCPUQuota.Get())
		if err != nil {
			return errors.Wrap(err, "failed to ParseQuantity quota cpu")
		}
		hard[corev1.ResourceCPU] = cpuQuantity
		hard[corev1.ResourceLimitsCPU] = cpuQuantity
		memQuantity, err := resource.ParseQuantity(settings.SaicMemoryQuota.Get())
		if err != nil {
			return errors.Wrap(err, "failed to ParseQuantity quota memory")
		}
		hard[corev1.ResourceMemory] = memQuantity
		hard[corev1.ResourceLimitsMemory] = memQuantity
	} else {
		for _, usage := range tenantInfo.QuotaUsages {
			switch usage.Name {
			case "CPU":
				cpuQuantity, err := resource.ParseQuantity(strconv.FormatInt(usage.Limit, 10))
				if err != nil {
					return errors.Wrap(err, "failed to ParseQuantity quota cpu")
				}
				hard[corev1.ResourceCPU] = cpuQuantity
				hard[corev1.ResourceLimitsCPU] = cpuQuantity
			case "内存":
				memQuantity, err := resource.ParseQuantity(strconv.FormatInt(usage.Limit, 10) + "Gi")
				if err != nil {
					return errors.Wrap(err, "failed to ParseQuantity quota memory")
				}
				hard[corev1.ResourceMemory] = memQuantity
				hard[corev1.ResourceLimitsMemory] = memQuantity
			}
		}
	}

	current, err := usercontext.Core.ResourceQuotas(namespace.Name).Get(user.TenantID, metav1.GetOptions{})
	if err != nil && !apierrors.IsNotFound(err) {
		return err
	}

	if current == nil || apierrors.IsNotFound(err) {
		quota := corev1.ResourceQuota{}
		quota.Name = user.TenantID
		quota.Namespace = namespace.Name
		quota.Spec.Hard = hard
		_, err = usercontext.Core.ResourceQuotas(namespace.Name).Create(&quota)
	}

	if err != nil && !apierrors.IsAlreadyExists(err) {
		return errors.Wrap(err, "failed to create namespace quota")
	}
	return nil
}

func (sp *ssoProvider) getSAICTenantNamespace(usercontext *config.UserContext, project *v3.Project) (*corev1.Namespace, error) {
	return usercontext.Core.Namespaces("").Get(project.Spec.DisplayName, metav1.GetOptions{})
}

func (sp *ssoProvider) ensureSAICProject(project *v3.Project) (*v3.Project, *corev1.Namespace, error) {
	projectList, err := sp.projectLister.List(project.Namespace, labels.Set(project.Labels).AsSelector())
	if err != nil {
		return nil, nil, err
	}
	found := false
	for _, p := range projectList {
		if project.Spec.DisplayName == p.Spec.DisplayName {
			project = p
			found = true
		}
	}
	if !found {
		//create Project
		p, err := sp.projectInterface.Create(project)
		if err == nil || apierrors.IsAlreadyExists(err) {
			project = p
		} else {
			logrus.Errorf("create project err: %s", err.Error())
			return nil, nil, err
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
		return project, nil, err
	}

	if !v3.NamespaceBackedResource.IsTrue(project) {
		logrus.Errorf("timeout waiting for project %s has condition %s", project.Name, v3.NamespaceBackedResource)
	}

	//ensure namespace
	usercontext, err := sp.clusterManager.UserContext(project.Namespace)
	if err != nil {
		return project, nil, errors.Wrap(err, "failed to get usercontext")
	}

	// create NameSpace
	_, err = usercontext.Core.Namespaces("").Create(&corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: project.Spec.DisplayName,
			Annotations: map[string]string{
				projectIDAnno: project.Namespace + ":" + project.Name,
			},
		},
	})
	if err != nil && !apierrors.IsAlreadyExists(err) {
		return nil, nil, err
	}

	namespace, err := sp.ensureNSInProject(usercontext, project)
	if err != nil {
		return nil, nil, err
	}

	return project, namespace, nil
}

func (sp *ssoProvider) reconcileClusterRoleBinding(cluster *v3.Cluster, amClient *amClient, user DUser, clusterKeyName string) error {
	role, err := GetRoleFromUser(user, amClient, clusterKeyName)
	if err != nil {
		return err
	}
	toDelete := false
	if isProject, ok := roleScope[role]; !ok || isProject {
		toDelete = true
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
		logrus.Infof("user %s is no longer cluster %s owner, delete crtb", user.IamOpenID, cluster.Name)
		return sp.crtbClient.DeleteNamespaced(cluster.Name, crtb.Name, &metav1.DeleteOptions{})
	}

	return nil
}

func (sp *ssoProvider) ensureNSInProject(usercontext *config.UserContext, project *v3.Project) (*corev1.Namespace, error) {
	var updated bool
	var namespace *corev1.Namespace
	if err := runFirstTicker(sp.ctx, 500*time.Millisecond, 10*time.Second, func() error {
		var err error
		namespace, err = sp.getSAICTenantNamespace(usercontext, project)
		if err == nil && !updated {
			value, ok := namespace.Annotations[projectIDAnno]
			if ok && value == project.Namespace+":"+project.Name {
				updated = true
			} else {
				newObj := namespace.DeepCopy()
				newObj.Annotations[projectIDAnno] = project.Namespace + ":" + project.Name
				namespace, err = usercontext.Core.Namespaces("").Update(newObj)
				if err != nil {
					err = errors.Wrapf(err, "failed to update namespace with project id, error: %s", err.Error())
				} else {
					updated = true
				}
			}
		}
		if err == nil && updated {
			if value, ok := namespace.Labels[projectIDAnno]; ok && value == project.Name {
				return nil
			}
		}
		return fmt.Errorf("namespace %s is not ready", namespace.Name)
	}); err != nil {
		return nil, err
	}

	return namespace, nil
}

func runFirstTicker(ctx context.Context, d, timeout time.Duration, runner func() error) error {
	timeoutContext, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	timer := ticker.Context(timeoutContext, d)
	var err error
	for {
		err = runner()
		if err == nil {
			return nil
		}
		_, ok := <-timer
		if !ok {
			break
		}
	}
	return errors.Wrap(err, "timeout running function")
}
