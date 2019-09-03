package sso

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/rancher/rancher/pkg/settings"
	v3 "github.com/rancher/types/apis/management.cattle.io/v3"
	"github.com/sirupsen/logrus"
)

type ssoClient struct {
	httpClient *http.Client
}

type ssoSession struct {
	config      *v3.SSOConfig
	userCode    string
	accessToken string
	userToken   string
}

func (sc *ssoClient) endpoint(config *v3.SSOConfig) string {
	endpoint := settings.SaicSSOEndpoint.Get()
	if config.Hostname != "" {
		scheme := "http://"
		if config.TLS {
			scheme = "https://"
		}
		endpoint = scheme + config.Hostname
	}
	return endpoint
}

func (ss *ssoSession) getAccessToken(sc *ssoClient) error {
	url := fmt.Sprintf("%s/api/v1/oauth/token?client_id=%s&client_secret=%s", sc.endpoint(ss.config), ss.config.ClientID, ss.config.ClientSecret)

	var respMap map[string]interface{}
	resp, err := call(sc.httpClient, http.MethodGet, url, nil, &respMap)
	if err != nil {
		logrus.Errorf("SSO getSuccessToken: GET AccessToken %v received error from SSO, err: %v", url, err)
		return err
	}
	defer resp.Body.Close()

	if respMap["error"] != nil {
		desc := respMap["error_msg"]
		logrus.Errorf("Received Error from SSO %v, description from SSO %v", respMap["error"], desc)
		return fmt.Errorf("Received Error from SSO %v, description from SSO %v", respMap["error"], desc)
	}

	accessToken, ok := respMap["access_token"].(string)
	if !ok {
		return fmt.Errorf("Received Error reading accessToken from response %v", respMap)
	}
	ss.accessToken = accessToken
	return nil
}

func (ss *ssoSession) getUserToken(sc *ssoClient) error {
	url := fmt.Sprintf("%s/api/v1/user/get_usertoken?access_token=%s", sc.endpoint(ss.config), ss.accessToken)
	var respMap map[string]interface{}
	resp, err := call(sc.httpClient, http.MethodPost, url, map[string]string{"code": ss.userCode}, &respMap)
	if err != nil {
		logrus.Errorf("SSO getSuccessToken: GET AccessToken %v received error from SSO, err: %v", url, err)
		return err
	}
	defer resp.Body.Close()

	if respMap["error"] != nil {
		desc := respMap["error_msg"]
		logrus.Errorf("Received Error from SSO %v, description from SSO %v", respMap["error"], desc)
		return fmt.Errorf("Received Error from SSO %v, description from SSO %v", respMap["error"], desc)
	}
	userTokenMap, ok := respMap["data"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("Received Error reading accessToken from response %v", respMap)
	}
	ss.userToken = userTokenMap["user_token"].(string)
	return nil
}

func (sc *ssoClient) GetUserInfo(code string, config *v3.SSOConfig) (SUser, string, error) {
	var rtn SUser
	session := &ssoSession{
		config:   config,
		userCode: code,
	}
	if err := session.getAccessToken(sc); err != nil {
		return rtn, "", err
	}
	if err := session.getUserToken(sc); err != nil {
		return rtn, "", err
	}
	base, err := sc.getUserInfo(session)
	if err != nil {
		return rtn, "", err
	}
	return base.SUser, session.accessToken, nil
}

func (sc *ssoClient) getUserInfo(session *ssoSession) (SUserBasic, error) {
	var rtn SUserBasic
	url := fmt.Sprintf("%s/api/v1/user/get_info2?access_token=%s", sc.endpoint(session.config), session.accessToken)
	resp, err := call(sc.httpClient, http.MethodPost, url, map[string]string{"user_token": session.userToken}, &rtn)
	if err != nil {
		logrus.Errorf("SSO getSSOUser: GET User %v received error from SSO, err: %v", url, err)
		return rtn, err
	}
	defer resp.Body.Close()
	return rtn, nil
}

func responseSuccess(resp *http.Response) bool {
	if resp == nil {
		return false
	}
	return int(resp.StatusCode)/100 == 2
}

func newRequest(method, url string, data []byte) (*http.Request, error) {
	if len(data) == 0 {
		return http.NewRequest(method, url, nil)
	}
	return http.NewRequest(method, url, bytes.NewBuffer(data))
}

func call(client *http.Client, method, url string, input interface{}, output interface{}) (*http.Response, error) {
	var data []byte
	var err error
	if input != nil {
		data, err = json.Marshal(input)
		if err != nil {
			return nil, err
		}
	}
	logrus.Infof("Calling API %s %s with data (%s)", method, url, string(data))
	req, err := newRequest(method, url, data)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	logrus.Debugf("resp: %+v", resp)
	if output != nil {
		var buff bytes.Buffer
		_, err := io.Copy(&buff, resp.Body)
		if err != nil {
			logrus.Errorf("failed to copy response body of request %+v", req)
		} else if err := json.Unmarshal(buff.Bytes(), output); err != nil {
			logrus.Errorf("failed to decode response as json format, data: %s", buff.String())
		} else {
			logrus.Infof("marshal response data into json: %+v", output)
		}
	}
	return resp, nil
}
