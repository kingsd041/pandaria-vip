package sso

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/pkg/errors"
	"github.com/rancher/norman/httperror"
	"github.com/rancher/norman/types"
	"github.com/rancher/rancher/pkg/auth/providers/common"
	"github.com/rancher/rancher/pkg/settings"
	v3 "github.com/rancher/types/apis/management.cattle.io/v3"
	"github.com/rancher/types/apis/management.cattle.io/v3public"
	client "github.com/rancher/types/client/management/v3"
)

func (sp *ssoProvider) formatter(apiContext *types.APIContext, resource *types.RawResource) {
	common.AddCommonActions(apiContext, resource)
	resource.AddAction(apiContext, "configureTest")
	resource.AddAction(apiContext, "testAndApply")
}

func (sp *ssoProvider) actionHandler(actionName string, action *types.Action, request *types.APIContext) error {
	handled, err := common.HandleCommonAction(actionName, action, request, Name, sp.authConfigs)
	if err != nil {
		return err
	}
	if handled {
		return nil
	}

	if actionName == "configureTest" {
		return sp.configureTest(actionName, action, request)
	} else if actionName == "testAndApply" {
		return sp.testAndApply(actionName, action, request)
	}

	return httperror.NewAPIError(httperror.ActionNotAvailable, "")
}

func (sp *ssoProvider) configureTest(actionName string, action *types.Action, request *types.APIContext) error {
	ssoConfig := &v3.SSOConfig{}
	if err := json.NewDecoder(request.Request.Body).Decode(ssoConfig); err != nil {
		return httperror.NewAPIError(httperror.InvalidBodyContent,
			fmt.Sprintf("Failed to parse body: %v", err))
	}

	redirectURL := formSSORedirectURL(ssoConfig)
	data := map[string]interface{}{
		"redirectUrl": redirectURL,
		"type":        "ssoConfigTestOutput",
	}

	request.WriteResponse(http.StatusOK, data)
	return nil
}

func formSSORedirectURL(ssoConfig *v3.SSOConfig) string {
	return ssoRedirectURL(ssoConfig.Hostname, ssoConfig.ClientID, ssoConfig.TLS)
}

func formSSORedirectURLFromMap(config map[string]interface{}) string {
	hostname, _ := config[client.SSOConfigFieldHostname].(string)
	clientID, _ := config[client.SSOConfigFieldClientID].(string)
	tls, _ := config[client.SSOConfigFieldTLS].(bool)
	return ssoRedirectURL(hostname, clientID, tls)
}

func ssoRedirectURL(hostname, clientID string, tls bool) string {
	redirect := ""
	if hostname != "" {
		scheme := "http://"
		if tls {
			scheme = "https://"
		}
		redirect = scheme + hostname
	} else {
		redirect = settings.SaicSSOEndpoint.Get()
	}

	redirect = redirect + "/appAuthorize/authorize?client_id=" + clientID
	return redirect
}

func (sp *ssoProvider) testAndApply(actionName string, action *types.Action, request *types.APIContext) error {
	var ssoConfig v3.SSOConfig
	ssoConfigApplyInput := &v3.SSOConfigApplyInput{}

	if err := json.NewDecoder(request.Request.Body).Decode(ssoConfigApplyInput); err != nil {
		return httperror.NewAPIError(httperror.InvalidBodyContent,
			fmt.Sprintf("Failed to parse body: %v", err))
	}

	ssoConfig = ssoConfigApplyInput.SSOConfig
	ssoLogin := &v3public.SSOLogin{
		Code: ssoConfigApplyInput.Code,
	}

	//Call provider to testLogin
	userPrincipal, groupPrincipals, providerInfo, err := sp.loginUser(ssoLogin, &ssoConfig, true)
	if err != nil {
		if httperror.IsAPIError(err) {
			return err
		}
		return errors.Wrap(err, "server error while authenticating")
	}

	//if this works, save ssoConfig CR adding enabled flag
	user, err := sp.userMGR.SetPrincipalOnCurrentUser(request, userPrincipal)
	if err != nil {
		return err
	}

	ssoConfig.Enabled = ssoConfigApplyInput.Enabled
	err = sp.saveSSOConfig(&ssoConfig)
	if err != nil {
		return httperror.NewAPIError(httperror.ServerError, fmt.Sprintf("Failed to save sso config: %v", err))
	}

	return sp.tokenMGR.CreateTokenAndSetCookie(user.Name, userPrincipal, groupPrincipals, providerInfo, 0, "Token via SSO Configuration", request)
}
