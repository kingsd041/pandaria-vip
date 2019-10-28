package publicapi

import (
	"encoding/json"

	"github.com/rancher/rancher/pkg/auth/providers/sso"
	v3 "github.com/rancher/types/apis/management.cattle.io/v3"
	"github.com/rancher/types/config"
	"github.com/sirupsen/logrus"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
)

type SaicAuthManager struct {
	grLister v3.GlobalRoleBindingLister
	grClient v3.GlobalRoleBindingInterface
}

func newSaicAuthManager(mgmt *config.ScaledContext) *SaicAuthManager {
	return &SaicAuthManager{
		grLister: mgmt.Management.GlobalRoleBindings("").Controller().Lister(),
		grClient: mgmt.Management.GlobalRoleBindings(""),
	}
}

func (sam *SaicAuthManager) EnsureGlobalRolebinding(user *v3.User, userPrincipal v3.Principal) {
	// update global role binding for saic sso
	userInfo, ok := userPrincipal.ExtraInfo["userInfo"]
	if ok {
		saicUser := &sso.DUser{}
		err := json.Unmarshal([]byte(userInfo), saicUser)
		// don't return error if convert error
		if err != nil {
			logrus.Errorf("Fail to convert userInfo %s from principal %v, error is %v", userInfo, userPrincipal, err)
			return
		}
		set := labels.Set(map[string]string{sso.AuthRoleBindingLabel: saicUser.IamOpenID})
		grbList, err := sam.grLister.List("", set.AsSelector())
		if err != nil {
			logrus.Errorf("Fail to get globalrolebinding for user %v, error is %v", saicUser.Username, err)
			return
		}
		for _, grb := range grbList {
			if grb.UserName == "" || grb.UserName != user.Name {
				newGrb := grb.DeepCopy()
				newGrb.UserName = user.Name
				_, err = sam.grClient.Update(newGrb)
				if err != nil && !apierrors.IsConflict(err) {
					logrus.Errorf("Fail to update globalrolebinding %s with username %s, error is %v", grb.Name, user.Name, err)
				}
			}
		}
	}
}
