package authn

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"reflect"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/rancher/norman/httperror"
	"github.com/rancher/norman/parse"
	"github.com/rancher/norman/types"
	"github.com/rancher/rancher/pkg/auth/providerrefresh"
	"github.com/rancher/rancher/pkg/settings"
	"github.com/rancher/types/apis/management.cattle.io/v3"
	"github.com/rancher/types/client/management/v3"
	"golang.org/x/crypto/bcrypt"
	"k8s.io/apimachinery/pkg/apis/meta/v1"
)

func (h *Handler) UserFormatter(apiContext *types.APIContext, resource *types.RawResource) {
	resource.AddAction(apiContext, "setpassword")
	resource.AddAction(apiContext, "setharborauth")
	resource.AddAction(apiContext, "updateharborauth")
	if canRefresh := h.userCanRefresh(apiContext); canRefresh {
		resource.AddAction(apiContext, "refreshauthprovideraccess")
	}
}

func (h *Handler) CollectionFormatter(apiContext *types.APIContext, collection *types.GenericCollection) {
	collection.AddAction(apiContext, "changepassword")
	if canRefresh := h.userCanRefresh(apiContext); canRefresh {
		collection.AddAction(apiContext, "refreshauthprovideraccess")
	}
}

type Handler struct {
	UserClient               v3.UserInterface
	GlobalRoleBindingsClient v3.GlobalRoleBindingInterface
	UserAuthRefresher        providerrefresh.UserAuthRefresher
}

func (h *Handler) Actions(actionName string, action *types.Action, apiContext *types.APIContext) error {
	switch actionName {
	case "changepassword":
		if err := h.changePassword(actionName, action, apiContext); err != nil {
			return err
		}
	case "setpassword":
		if err := h.setPassword(actionName, action, apiContext); err != nil {
			return err
		}
	case "refreshauthprovideraccess":
		if err := h.refreshAttributes(actionName, action, apiContext); err != nil {
			return err
		}
	case "setharborauth":
		if err := h.setHarborAuth(actionName, action, apiContext); err != nil {
			return err
		}
	case "updateharborauth":
		if err := h.updateHarborAuth(actionName, action, apiContext); err != nil {
			return err
		}
	default:
		return errors.Errorf("bad action %v", actionName)
	}

	if !strings.EqualFold(settings.FirstLogin.Get(), "false") {
		if err := settings.FirstLogin.Set("false"); err != nil {
			return err
		}
	}
	return nil
}

func (h *Handler) changePassword(actionName string, action *types.Action, request *types.APIContext) error {
	actionInput, err := parse.ReadBody(request.Request)
	if err != nil {
		return err
	}

	store := request.Schema.Store
	if store == nil {
		return errors.New("no user store available")
	}

	userID := request.Request.Header.Get("Impersonate-User")
	if userID == "" {
		return errors.New("can't find user")
	}

	currentPass, ok := actionInput["currentPassword"].(string)
	if !ok || len(currentPass) == 0 {
		return httperror.NewAPIError(httperror.InvalidBodyContent, "must specify current password")
	}

	newPass, ok := actionInput["newPassword"].(string)
	if !ok || len(newPass) == 0 {
		return httperror.NewAPIError(httperror.InvalidBodyContent, "invalid new password")
	}

	user, err := h.UserClient.Get(userID, v1.GetOptions{})
	if err != nil {
		return err
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(currentPass)); err != nil {
		return httperror.NewAPIError(httperror.InvalidBodyContent, "invalid current password")
	}

	newPassHash, err := HashPasswordString(newPass)
	if err != nil {
		return err
	}

	user.Password = newPassHash
	user.MustChangePassword = false
	user, err = h.UserClient.Update(user)
	if err != nil {
		return err
	}

	return nil
}

func (h *Handler) setPassword(actionName string, action *types.Action, request *types.APIContext) error {
	actionInput, err := parse.ReadBody(request.Request)
	if err != nil {
		return err
	}

	store := request.Schema.Store
	if store == nil {
		return errors.New("no user store available")
	}

	userData, err := store.ByID(request, request.Schema, request.ID)
	if err != nil {
		return err
	}

	newPass, ok := actionInput["newPassword"].(string)
	if !ok || len(newPass) == 0 {
		return errors.New("Invalid password")
	}

	userData[client.UserFieldPassword] = newPass
	if err := hashPassword(userData); err != nil {
		return err
	}
	userData[client.UserFieldMustChangePassword] = false
	delete(userData, "me")

	userData, err = store.Update(request, request.Schema, userData, request.ID)
	if err != nil {
		return err
	}

	request.WriteResponse(http.StatusOK, userData)
	return nil
}

func (h *Handler) refreshAttributes(actionName string, action *types.Action, request *types.APIContext) error {
	canRefresh := h.userCanRefresh(request)

	if !canRefresh {
		return errors.New("Not Allowed")
	}

	if request.ID != "" {
		h.UserAuthRefresher.TriggerUserRefresh(request.ID, true)
	} else {
		h.UserAuthRefresher.TriggerAllUserRefresh()
	}

	request.WriteResponse(http.StatusOK, nil)
	return nil
}

func (h *Handler) userCanRefresh(request *types.APIContext) bool {
	return request.AccessControl.CanDo(v3.UserGroupVersionKind.Group, v3.UserResource.Name, "create", request, nil, request.Schema) == nil
}

type HarborUser struct {
	UserID       int    `json:"user_id"`
	UserName     string `json:"username"`
	Email        string `json:"email"`
	Password     string `json:"password"`
	RealName     string `json:"realname"`
	Deleted      bool   `json:"deleted"`
	HasAdminRole bool   `json:"has_admin_role"`
}

type HarborPassword struct {
	OldPassword string `json:"old_password"`
	NewPassword string `json:"new_password"`
}

func (h *Handler) setHarborAuth(actionName string, action *types.Action, request *types.APIContext) error {
	actionInput, err := parse.ReadBody(request.Request)
	if err != nil {
		return err
	}
	store := request.Schema.Store
	if store == nil {
		return errors.New("no user store available")
	}

	userID := request.Request.Header.Get("Impersonate-User")
	if userID == "" {
		return errors.New("can't find user")
	}

	harborPwd := actionInput["password"].(string)
	harborEmail := actionInput["email"].(string)
	user, err := h.UserClient.Get(userID, v1.GetOptions{})
	if err != nil {
		return err
	}

	newUser := user.DeepCopy()
	// get harbor-server to sync user
	harborServer := settings.HarborServer.Get()
	harborUser := &HarborUser{
		UserName:     newUser.Username,
		Password:     harborPwd,
		Email:        harborEmail,
		RealName:     newUser.Username,
		Deleted:      false,
		HasAdminRole: false,
	}
	postUser, err := json.Marshal(harborUser)
	if err != nil {
		return err
	}
	auth := settings.HarborAdminAuth.Get()
	adminAuth := fmt.Sprintf("Basic %s", auth)
	_, err = serveHarbor("POST", fmt.Sprintf("%s/api/users", harborServer), adminAuth, postUser)
	if err != nil {
		return err
	}

	// save harbor user auth to rancher user
	harborAuth := fmt.Sprintf("%s:%s", newUser.Username, harborPwd)
	harborAuthStr := base64.StdEncoding.EncodeToString([]byte(harborAuth))
	annotations := newUser.Annotations
	if annotations == nil {
		annotations = map[string]string{}
	}
	annotations[HarborUserAnnotationAuth] = harborAuthStr
	annotations[HarborUserAnnotationEmail] = harborEmail
	newUser, err = h.UserClient.Update(newUser)
	if err != nil {
		return err
	}
	request.WriteResponse(http.StatusOK, nil)

	return nil
}

func (h *Handler) updateHarborAuth(actionName string, action *types.Action, request *types.APIContext) error {
	actionInput, err := parse.ReadBody(request.Request)
	if err != nil {
		return err
	}
	store := request.Schema.Store
	if store == nil {
		return errors.New("no user store available")
	}

	userID := request.Request.Header.Get("Impersonate-User")
	if userID == "" {
		return errors.New("can't find user")
	}

	newPwd := actionInput["newPassword"].(string)
	oldPwd := actionInput["oldPassword"].(string)
	harborEmail := actionInput["email"].(string)
	user, err := h.UserClient.Get(userID, v1.GetOptions{})
	if err != nil {
		return err
	}
	updateUser := user.DeepCopy()
	annotations := updateUser.Annotations
	if annotations == nil {
		return fmt.Errorf("please sync to harbor first")
	}

	// get harbor-server and auth to sync user
	harborServer := settings.HarborServer.Get()
	auth := fmt.Sprintf("Basic %s", annotations[HarborUserAnnotationAuth])
	result, err := serveHarbor("GET", fmt.Sprintf("%s/api/users/current", harborServer), auth, nil)
	if err != nil {
		return err
	}
	harborUser := &HarborUser{}
	err = json.Unmarshal(result, harborUser)
	if err != nil {
		return err
	}

	// update user e-mail
	if harborEmail != "" {
		harborUser.Email = harborEmail
		updateUserBody, err := json.Marshal(harborUser)
		if err != nil {
			return err
		}
		_, err = serveHarbor("PUT", fmt.Sprintf("%s/api/users/%d", harborServer, harborUser.UserID), auth, updateUserBody)
		if err != nil {
			return err
		}
		annotations[HarborUserAnnotationEmail] = harborEmail
	}

	if oldPwd != "" && newPwd != "" {
		// update user password
		pwd := &HarborPassword{
			OldPassword: oldPwd,
			NewPassword: newPwd,
		}

		updatePwdBody, err := json.Marshal(pwd)
		_, err = serveHarbor("PUT", fmt.Sprintf("%s/api/users/%d/password", harborServer, harborUser.UserID), auth, updatePwdBody)
		if err != nil {
			return err
		}
		harborAuth := fmt.Sprintf("%s:%s", user.Username, newPwd)
		harborAuthStr := base64.StdEncoding.EncodeToString([]byte(harborAuth))
		annotations[HarborUserAnnotationAuth] = harborAuthStr
	}

	// update user annotation for new harbor settings
	if !reflect.DeepEqual(user, updateUser) {
		_, err = h.UserClient.Update(updateUser)
		if err != nil {
			return err
		}
	}

	request.WriteResponse(http.StatusOK, nil)

	return nil
}

func serveHarbor(method, url, auth string, body []byte) ([]byte, error) {
	c := &http.Client{Timeout: 15 * time.Second}
	request, err := http.NewRequest(method, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}

	request.Header.Set("Authorization", auth)
	request.Header.Add("Content-Type", "application/json")
	response, err := c.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK && response.StatusCode != http.StatusCreated && response.StatusCode != http.StatusNoContent {
		result, err := ioutil.ReadAll(response.Body)
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("%s", string(result))
	}
	return ioutil.ReadAll(response.Body)
}
