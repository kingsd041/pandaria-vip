package sso

import (
	"fmt"

	"github.com/rancher/norman/types/slice"
	v3 "github.com/rancher/types/apis/management.cattle.io/v3"
	"github.com/rancher/types/config"
	"github.com/sirupsen/logrus"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
)

type SaicAuthManager struct {
	grLister   v3.GlobalRoleBindingLister
	grClient   v3.GlobalRoleBindingInterface
	crtbLister v3.ClusterRoleTemplateBindingLister
	crtbClient v3.ClusterRoleTemplateBindingInterface
}

func newSaicAuthManager(mgmt *config.ScaledContext) *SaicAuthManager {
	return &SaicAuthManager{
		grLister:   mgmt.Management.GlobalRoleBindings("").Controller().Lister(),
		grClient:   mgmt.Management.GlobalRoleBindings(""),
		crtbLister: mgmt.Management.ClusterRoleTemplateBindings("").Controller().Lister(),
		crtbClient: mgmt.Management.ClusterRoleTemplateBindings(""),
	}
}

func (sam *SaicAuthManager) ensureGlobalRoleBinding(clusterList []*v3.Cluster, clusterActions map[string][]string, dUser DUser, rUser *v3.User) {
	logrus.Infof("ensure global role for user %s, tenant %s", dUser.Username, dUser.TenantShortName)
	for _, cluster := range clusterList {
		clusterKeyName := cluster.Labels[RegionClusterKeyNameLabel]
		if clusterAction, ok := clusterActions[clusterKeyName]; ok {
			logrus.Infof("ensure global role %s for cluster %s", clusterAction, clusterKeyName)
			if err := sam.reconcileGlobalRoleBinding(clusterAction, dUser, cluster, rUser); err != nil {
				logrus.Errorf("fail to ensure global role binding of user %+v, rancher user %+v, error: %s", dUser, rUser, err.Error())
			}
		}
	}
}

func (sam *SaicAuthManager) reconcileGlobalRoleBinding(actions []string, user DUser, cluster *v3.Cluster, rUser *v3.User) error {
	roleList := []string{}
	for _, action := range actions {
		if role, ok := roleMap[action]; ok {
			if slice.ContainsString(globalRole, role) {
				roleList = append(roleList, role)
			}
		}
	}
	logrus.Infof("login for global role %v on cluster %s", roleList, cluster.Name)
	set := labels.Set(map[string]string{
		AuthRoleBindingLabel: user.IamOpenID,
		TenantShortNameLabel: user.TenantShortName,
	})
	grList, err := sam.grLister.List("", set.AsSelector())
	if err != nil {
		return err
	}

	deleteRoleBinding := []*v3.GlobalRoleBinding{}
	newRoleBinding := []string{}

	for _, gr := range grList {
		if !slice.ContainsString(roleList, gr.GlobalRoleName) {
			deleteRoleBinding = append(deleteRoleBinding, gr)
		}
	}

	for _, r := range roleList {
		found := false
		for _, gr := range grList {
			if r == gr.GlobalRoleName {
				found = true
				break
			}
		}
		if !found {
			newRoleBinding = append(newRoleBinding, r)
		}
	}

	for _, gr := range deleteRoleBinding {
		err = sam.grClient.Delete(gr.Name, &metav1.DeleteOptions{})
		if err != nil {
			return err
		}
	}

	for _, role := range newRoleBinding {
		// create globalrolebinding
		_, err = sam.grClient.Create(&v3.GlobalRoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "globalrolebinding-",
				Labels: map[string]string{
					AuthRoleBindingLabel: user.IamOpenID,
					TenantShortNameLabel: user.TenantShortName,
				},
			},
			GlobalRoleName: role,
			UserName:       rUser.Name,
		})
		if err != nil {
			return err
		}
	}

	return sam.ensureClusterGlobalRoleBinding(roleList, cluster, user)
}

func (sam *SaicAuthManager) ensureClusterGlobalRoleBinding(actions []string, cluster *v3.Cluster, user DUser) error {
	logrus.Infof("ensure cluster global role for %v, user %s, cluster %s", actions, user.Username, cluster.Name)
	set := labels.Set(map[string]string{
		AuthRoleBindingLabel:       user.IamOpenID,
		TenantShortNameLabel:       user.TenantShortName,
		AuthGlobalRoleBindingLabel: "true",
	})
	crtbList, err := sam.crtbLister.List(cluster.Name, set.AsSelector())
	if err != nil {
		return err
	}

	deleteRolebinding := []*v3.ClusterRoleTemplateBinding{}
	for _, crtb := range crtbList {
		logrus.Infof("get exist cluster role template binding %s for role %s, cluster %s", crtb.Name, crtb.RoleTemplateName, cluster.Name)
		if !slice.ContainsString(actions, crtb.RoleTemplateName) {
			deleteRolebinding = append(deleteRolebinding, crtb)
		}
	}

	newRoleList := []string{}
	for _, action := range actions {
		found := false
		for _, crtb := range crtbList {
			if crtb.RoleTemplateName == action {
				found = true
				break
			}
		}
		if !found {
			newRoleList = append(newRoleList, action)
		}
	}

	for _, crtb := range deleteRolebinding {
		logrus.Infof("user %s is no longer has global role %s, delete crtb of cluster %s", user.Username, crtb.RoleTemplateName, cluster.Name)
		err = sam.crtbClient.DeleteNamespaced(cluster.Name, crtb.Name, &metav1.DeleteOptions{})
		if err != nil {
			return err
		}
	}

	for _, role := range newRoleList {
		displayName := user.Username
		if displayName == "" {
			displayName = user.IamOpenID
		}
		logrus.Infof("create new cluster template role %s for cluster %s", role, cluster.Labels["regionClusterKeyName"])
		_, err = sam.crtbClient.Create(&v3.ClusterRoleTemplateBinding{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: fmt.Sprintf("%s-", role),
				Namespace:    cluster.Name,
				Annotations:  map[string]string{"auth.cattle.io/principal-display-name": displayName},
				Labels: map[string]string{
					AuthRoleBindingLabel:       user.IamOpenID,
					TenantShortNameLabel:       user.TenantShortName,
					AuthGlobalRoleBindingLabel: "true",
				},
			},
			UserPrincipalName: Name + "_user://" + user.IamOpenID,
			RoleTemplateName:  role,
			ClusterName:       cluster.Name,
		})
		if err != nil && !apierrors.IsAlreadyExists(err) {
			return err
		}
	}
	return nil
}

func (sam *SaicAuthManager) EnsureGlobalRolebinding(clusterList []*v3.Cluster, tenantActions *TenantActions, dUser DUser, user *v3.User, userPrincipal v3.Principal) {
	if clusterList == nil {
		return
	}
	clusterActions := map[string][]string{}
	// find cluster list in rancher with regionClusterKeyName label
	for _, c := range tenantActions.Data.ServiceRegionResp {
		if len(c.Actions) > 0 {
			clusterActions[c.RegionClusterKeyName] = c.Actions
		}
	}
	sam.ensureGlobalRoleBinding(clusterList, clusterActions, dUser, user)
}
