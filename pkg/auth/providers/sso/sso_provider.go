package sso

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"time"

	"github.com/mitchellh/mapstructure"
	"github.com/pkg/errors"
	"github.com/rancher/norman/types"
	"github.com/rancher/rancher/pkg/auth/providers/common"
	"github.com/rancher/rancher/pkg/auth/tokens"
	"github.com/rancher/rancher/pkg/clustermanager"
	"github.com/rancher/types/apis/management.cattle.io/v3"
	"github.com/rancher/types/apis/management.cattle.io/v3public"
	"github.com/rancher/types/client/management/v3"
	publicclient "github.com/rancher/types/client/management/v3public"
	"github.com/rancher/types/config"
	"github.com/rancher/types/user"
	"github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

const (
	// Name of the provider
	Name = "sso"
)

var (
	_ common.AuthProvider = &ssoProvider{}

	roleMap = map[string]string{
		"tenant_admin":  "project-owner",
		"tenant_member": "project-member",
	}
)

type ssoProvider struct {
	ctx         context.Context
	ssoClient   *ssoClient
	authConfigs v3.AuthConfigInterface
	userMGR     user.Manager
	tokenMGR    *tokens.Manager

	prtbLister              v3.ProjectRoleTemplateBindingLister
	prtbClient              v3.ProjectRoleTemplateBindingInterface
	crtbLister              v3.ClusterRoleTemplateBindingLister
	crtbClient              v3.ClusterRoleTemplateBindingInterface
	clusterLister           v3.ClusterLister
	projectLister           v3.ProjectLister
	projectInterface        v3.ProjectInterface
	roleTemplateLister      v3.RoleTemplateLister
	projectLoggingLister    v3.ProjectLoggingLister
	projectLoggingInterface v3.ProjectLoggingInterface
	clusterManager          *clustermanager.Manager
}

func Configure(
	ctx context.Context,
	mgmtCtx *config.ScaledContext,
	userMGR user.Manager,
	tokenMGR *tokens.Manager,
) common.AuthProvider {
	defaultHTTPClient := &http.Client{
		Transport: &JSONRoundTripper{},
	}

	return &ssoProvider{
		ctx:         ctx,
		ssoClient:   &ssoClient{httpClient: defaultHTTPClient},
		authConfigs: mgmtCtx.Management.AuthConfigs(""),
		userMGR:     userMGR,
		tokenMGR:    tokenMGR,

		prtbLister:              mgmtCtx.Management.ProjectRoleTemplateBindings("").Controller().Lister(),
		prtbClient:              mgmtCtx.Management.ProjectRoleTemplateBindings(""),
		crtbLister:              mgmtCtx.Management.ClusterRoleTemplateBindings("").Controller().Lister(),
		crtbClient:              mgmtCtx.Management.ClusterRoleTemplateBindings(""),
		clusterLister:           mgmtCtx.Management.Clusters("").Controller().Lister(),
		projectLister:           mgmtCtx.Management.Projects("").Controller().Lister(),
		projectInterface:        mgmtCtx.Management.Projects(""),
		projectLoggingLister:    mgmtCtx.Management.ProjectLoggings("").Controller().Lister(),
		projectLoggingInterface: mgmtCtx.Management.ProjectLoggings(""),
		roleTemplateLister:      mgmtCtx.Management.RoleTemplates("").Controller().Lister(),
		clusterManager:          mgmtCtx.ClientGetter.(*clustermanager.Manager),
	}
}

func (sp *ssoProvider) GetName() string {
	return Name
}

func (sp *ssoProvider) AuthenticateUser(input interface{}) (v3.Principal, []v3.Principal, string, error) {
	login, ok := input.(*v3public.SSOLogin)
	if !ok {
		return v3.Principal{}, nil, "", errors.New("unexpected input type")
	}
	return sp.loginUser(login, nil, false)
}

const (
	userType = "user"
)

func (sp *ssoProvider) loginUser(login *v3public.SSOLogin, config *v3.SSOConfig, test bool) (v3.Principal, []v3.Principal, string, error) {
	start := time.Now()
	defer func() {
		logrus.Debugln("loginUser time:", time.Since(start))
	}()
	var groupPrincipals []v3.Principal
	var userPrincipal v3.Principal
	var accessToken string
	var err error

	if config == nil {
		tcs := time.Now()
		config, err = sp.getSSOConfigCR()
		tce := time.Since(tcs)
		logrus.Debugln("getSSOConfig time:", tce)
		if err != nil {
			return v3.Principal{}, nil, "", err
		}
	}
	if login.Digest == "" {
		var user SUser
		user, accessToken, err = sp.ssoClient.GetUserInfo(login.Code, config)
		if err != nil {
			err = errors.Wrap(err, "failed to get user info from sso")
			logrus.Error(err)
			return userPrincipal, groupPrincipals, accessToken, err
		}
		userPrincipal = sp.toPrincipal(user, nil)
	} else {
		dClient := newDigestClient(login.Jwt, login.Digest, sp.ssoClient.httpClient)
		amClient := newAMClient(login.Jwt, login.Digest, login.Region, login.RegionClusterKeyName, sp.ssoClient.httpClient)
		accessToken = login.Jwt
		var user DUser
		var err error
		if login.Region == "" || login.RegionClusterKeyName == "" {
			user, err = dClient.GetUserInfo()
		} else {
			user, err = amClient.GetUserInfo()
		}
		if err != nil {
			err = errors.Wrapf(err, "failed to get user info with digest %s, region %s, cluster key %s", login.Digest, login.Region, login.RegionClusterKeyName)
			logrus.Error(err)
			return userPrincipal, groupPrincipals, accessToken, err
		}

		cluster, project, err := sp.GetUserClusterAndProject(user, login.RegionClusterKeyName)
		if err != nil {
			err = errors.Wrapf(err, "failed to get cluster & project with duser %+v", user)
			logrus.Error(err)
			return userPrincipal, groupPrincipals, accessToken, err
		}

		userPrincipal = sp.toPrincipal(user, nil)

		//don't need to return error if ensure project logging fails.
		if err := sp.ensureProjectLogging(cluster, project, user); err != nil {
			logrus.Errorf("failed to ensure project logging, error: %s", err.Error())
		}

		//don't need to return error if ensure project rolebinding fails.
		if err := sp.reconcileProjectRoleBinding(project, amClient, user); err != nil {
			logrus.Errorf("failed to ensure project role binding of project %s for user %+v, error: %s", project.Name, user, err.Error())
		}

		if err := sp.reconcileClusterRoleBinding(cluster, amClient, user); err != nil {
			logrus.Errorf("failed to ensure cluster role binding of cluster %s for user %+v, error: %s", cluster.Name, user, err.Error())
		}

		var tenantInfo *TenantInfo
		if !isUsingClusterKey(user) {
			tenantInfo, err = dClient.GetTenantInfo(user)
			if err != nil {
				logrus.Errorf("failed to get tenant info with duser %+v, error: %s", user, err.Error())
			}
		}
		if err := sp.ensureResourceQuota(project, user, tenantInfo); err != nil {
			logrus.Errorf("failed to ensure namespace quota for project %s, error:%s", project.Name, err.Error())
		}
	}

	userPrincipal.Me = true
	return userPrincipal, groupPrincipals, accessToken, nil
}

func (sp *ssoProvider) saveSSOConfig(config *v3.SSOConfig) error {
	storedSSOConfig, err := sp.getSSOConfigCR()
	if err != nil {
		return err
	}
	config.APIVersion = "management.cattle.io/v3"
	config.Kind = v3.AuthConfigGroupVersionKind.Kind
	config.Type = client.SSOConfigType
	config.ObjectMeta = storedSSOConfig.ObjectMeta

	logrus.Debugf("updating ssoConfig")
	_, err = sp.authConfigs.ObjectClient().Update(config.ObjectMeta.Name, config)
	if err != nil {
		return err
	}
	return nil
}

func (sp *ssoProvider) getSSOConfigCR() (*v3.SSOConfig, error) {
	authConfigObj, err := sp.authConfigs.ObjectClient().UnstructuredClient().Get(Name, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve SSOConfig, error: %v", err)
	}

	u, ok := authConfigObj.(runtime.Unstructured)
	if !ok {
		return nil, fmt.Errorf("failed to retrieve SSOConfig, cannot read k8s Unstructured data")
	}
	storedSSOConfigMap := u.UnstructuredContent()

	storedSSOConfig := &v3.SSOConfig{}
	mapstructure.Decode(storedSSOConfigMap, storedSSOConfig)

	metadataMap, ok := storedSSOConfigMap["metadata"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("failed to retrieve SSOConfig metadata, cannot read k8s Unstructured data")
	}

	typemeta := &metav1.ObjectMeta{}
	mapstructure.Decode(metadataMap, typemeta)
	storedSSOConfig.ObjectMeta = *typemeta

	return storedSSOConfig, nil
}

func (sp *ssoProvider) toPrincipal(user interface{}, token *v3.Token) v3.Principal {
	var princ v3.Principal
	if reflect.TypeOf(user).Name() == "DUser" {
		userDig := user.(DUser)
		displayName := userDig.Username
		userInfoJSON, _ := json.Marshal(userDig)
		princ = v3.Principal{
			ObjectMeta:  metav1.ObjectMeta{Name: Name + "_user://" + userDig.IamOpenID},
			DisplayName: displayName,
			LoginName:   userDig.Username,
			Provider:    Name,
			Me:          false,
			ExtraInfo: map[string]string{
				"userInfo": string(userInfoJSON),
			},
		}
	} else {
		userSSO := user.(SUser)
		displayName := userSSO.Username
		princ = v3.Principal{
			ObjectMeta:  metav1.ObjectMeta{Name: Name + "_user://" + userSSO.IamOpenid},
			DisplayName: displayName + "ssologin",
			LoginName:   userSSO.Username,
			Provider:    Name,
			Me:          false,
		}
	}

	princ.PrincipalType = "user"

	return princ
}

func (sp *ssoProvider) SearchPrincipals(name string, principalType string, token v3.Token) ([]v3.Principal, error) {
	return []v3.Principal{}, nil
}

func (sp *ssoProvider) GetPrincipal(principalID string, token v3.Token) (v3.Principal, error) {
	return v3.Principal{}, nil
}

func (sp *ssoProvider) CustomizeSchema(schema *types.Schema) {
	schema.ActionHandler = sp.actionHandler
	schema.Formatter = sp.formatter
}

func (sp *ssoProvider) TransformToAuthProvider(authConfig map[string]interface{}) map[string]interface{} {
	p := common.TransformToAuthProvider(authConfig)
	p[publicclient.SSOProviderFieldRedirectURL] = formSSORedirectURLFromMap(authConfig)
	return p
}

func (sp *ssoProvider) CanAccessWithGroupProviders(userPrincipalID string, groups []v3.Principal) (bool, error) {
	return true, nil
	// return false, nil
}

func (sp *ssoProvider) RefetchGroupPrincipals(principalID string, secret string) ([]v3.Principal, error) {
	// return nil, errors.New("Not implemented")
	return nil, nil
}
