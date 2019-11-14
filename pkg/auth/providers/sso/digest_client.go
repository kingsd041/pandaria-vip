package sso

import (
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/pkg/errors"
	"github.com/rancher/rancher/pkg/settings"
	"github.com/sirupsen/logrus"
)

type amClient struct {
	httpClient *http.Client
	endpoint   string
	digest     string
	jwt        string
	region     string
}

type productClient struct {
	httpClient *http.Client
	endpoint   string
}

type digestClient struct {
	httpClient *http.Client
	endpoint   string
	jwt        string
	digest     string
}

type TokenRoundTripper struct {
	token string
	next  http.RoundTripper
}

func (rt *TokenRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", rt.token))
	if rt.next != nil {
		return rt.next.RoundTrip(req)
	}
	return http.DefaultTransport.RoundTrip(req)
}

type JSONRoundTripper struct {
	next http.RoundTripper
}

func (rt *JSONRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Accept", "application/json")
	if rt.next != nil {
		return rt.next.RoundTrip(req)
	}
	return http.DefaultTransport.RoundTrip(req)
}

func newDigestClient(jwt, digest string, client *http.Client) *digestClient {
	t := &TokenRoundTripper{token: jwt}
	if client != nil {
		t.next = client.Transport
	}
	return &digestClient{
		jwt:        jwt,
		digest:     digest,
		httpClient: &http.Client{Transport: t},
		endpoint:   settings.SaicDigestHost.Get(),
	}
}

func newAMClient(jwt, digest, region string, client *http.Client) *amClient {
	endpoint := settings.SaicAMHost.Get()
	t := &TokenRoundTripper{token: jwt}
	if client != nil {
		t.next = client.Transport
	}
	return &amClient{
		httpClient: &http.Client{Transport: t},
		endpoint:   endpoint,
		region:     region,
		digest:     digest,
		jwt:        jwt,
	}
}

func newProductClient(client *http.Client) *productClient {
	endpoint := settings.SaicProductHost.Get()
	if client == nil {
		client = &http.Client{}
	}
	return &productClient{
		httpClient: client,
		endpoint:   endpoint,
	}
}

func (c *amClient) GetUserInfo() (DUser, error) {
	var tmp UserInfoResponse
	url := fmt.Sprintf("%s/v1/digest/%s", c.endpoint, c.digest)
	resp, err := call(c.httpClient, http.MethodGet, url, nil, &tmp)
	if err != nil {
		return DUser{}, errors.Wrapf(err, "failed to get digest info from %s", url)
	}
	defer resp.Body.Close()
	if tmp.UserInfo != nil {
		return tmp.UserInfo.ToDUser(), nil
	}
	return DUser{}, nil
}

func (c *amClient) GetUserByDigest() (DUser, error) {
	var tmp UserInfoResponse
	url := fmt.Sprintf("%s/v1/digest/%s", c.endpoint, c.digest)
	resp, err := call(c.httpClient, http.MethodGet, url, nil, &tmp)
	if err != nil {
		return DUser{}, errors.Wrapf(err, "failed to get digest info from %s", url)
	}
	defer resp.Body.Close()
	respData, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return DUser{}, errors.Wrapf(err, "GetUserByDigest: failed to read http response data")
	}
	if !responseSuccess(resp) {
		return DUser{}, &SAICLoginError{TenantLoginFailedClusters: "", Code: tmp.Code, Message: string(respData)}
	}
	if tmp.UserInfo != nil {
		return tmp.UserInfo.ToDUser(), nil
	}
	return DUser{}, nil
}

func (c *amClient) GetUserRoleFromAM() (*TenantActions, error) {
	url := fmt.Sprintf("%s/v1/csp/actions", c.endpoint)
	input := TenantActionInput{
		Region:     c.region,
		ServiceKey: settings.SaicServiceKeyName.Get(),
		Digest:     c.digest,
	}
	output := &TenantActions{}
	resp, err := call(c.httpClient, http.MethodPost, url, input, output)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get response from request %s %+v", url, input)
	}
	defer resp.Body.Close()
	respData, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to read http response data")
	}
	if !responseSuccess(resp) {
		return nil, fmt.Errorf("failed to call API to get iam actions, status code %d, response data %s", resp.StatusCode, string(respData))
	}

	return output, nil
}

func (c *amClient) GetUserRoleFromAMHost() (*TenantActions, error) {
	url := fmt.Sprintf("%s/v1/csp/actions", c.endpoint)
	input := TenantActionInput{
		Region:     c.region,
		ServiceKey: settings.SaicServiceKeyName.Get(),
		Digest:     c.digest,
	}
	output := &TenantActions{}
	resp, err := call(c.httpClient, http.MethodPost, url, input, output)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get response from request %s %+v", url, input)
	}
	defer resp.Body.Close()
	respData, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to read http response data")
	}
	if !responseSuccess(resp) {
		logrus.Errorf("failed to call API to get iam actions, status code %d, response data %s", resp.StatusCode, string(respData))
		return nil, &SAICLoginError{TenantLoginFailedClusters: "", Code: output.Code, Message: string(respData)}
	}

	return output, nil
}

func (c *amClient) GetUserRoleForClusterFromAM(clusterKey string) (string, error) {
	output, err := c.GetUserRoleFromAM()
	if err != nil {
		return "", err
	}
	var actions []string
	for _, cluster := range output.Data.ServiceRegionResp {
		if cluster.RegionClusterKeyName == clusterKey {
			actions = cluster.Actions
			break
		}
	}
	if len(actions) == 0 {
		return "", nil
	}

	value, ok := roleMap[actions[0]]
	if !ok {
		return "", nil
	}

	return value, nil
}

func (c *productClient) getRegionList(user DUser) ([]Region, error) {
	var output RegionList
	url := fmt.Sprintf("%s/service/api/regionList", c.endpoint)
	resp, err := call(c.httpClient, http.MethodGet, url, nil, &output)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to send request to product endpoint %s", url)
	}
	defer resp.Body.Close()
	return output.Data, nil
}

func (c *productClient) getClusterByServiceRegion(region string) ([]ClusterCommon, error) {
	var output ClusterList
	url := fmt.Sprintf("%s/service/api/clusterListByServiceRegion?sk=%s", c.endpoint, settings.SaicServiceKeyName.Get())
	if region != "" {
		url = url + "&region=" + region
	}
	resp, err := call(c.httpClient, http.MethodGet, url, nil, &output)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to send request to product endpoint %s", url)
	}
	defer resp.Body.Close()
	return output.Data, nil
}

func (dc *digestClient) GetUserInfo() (DUser, error) {
	url := fmt.Sprintf("%s/api/v1/service-bind/%s", dc.endpoint, dc.digest)
	var rtn DUser
	resp, err := call(dc.httpClient, http.MethodGet, url, nil, &rtn)
	if err != nil {
		return rtn, errors.Wrapf(err, "failed to get digest user info from %s", url)
	}
	defer resp.Body.Close()
	url = fmt.Sprintf("%s/v1/user/info", dc.endpoint)
	var openIDRtn map[string]interface{}
	resp, err = call(dc.httpClient, http.MethodGet, url, nil, &openIDRtn)
	if err != nil {
		return rtn, errors.Wrapf(err, "failed to get iam openid from %s", url)
	}
	defer resp.Body.Close()
	if v, ok := openIDRtn["iam_openid"].(string); ok {
		rtn.IamOpenID = v
	} else {
		return rtn, errors.New("iam_openid is not exist")
	}
	rtn.Jwt = dc.jwt
	return rtn, nil
}

func (dc *digestClient) GetTenantInfo(user DUser) (*TenantInfo, error) {
	url := fmt.Sprintf("%s/v1/tenants/%s/services/%s", dc.endpoint, user.TenantID, user.ServiceID)
	rtn := &TenantInfo{}
	resp, err := call(dc.httpClient, http.MethodGet, url, nil, rtn)
	if err != nil {
		return rtn, errors.Wrapf(err, "failed to get tenant info from %s", url)
	}
	defer resp.Body.Close()
	return rtn, nil
}

func GetRoleFromUser(user DUser, amClient *amClient, clusterKeyName string) (string, error) {
	if isUsingClusterKey(user) {
		return amClient.GetUserRoleForClusterFromAM(clusterKeyName)
	}

	var role string
	if user.TenantRole == "tenant_admin" {
		role = "project-owner"
	} else {
		role = "project-member"
	}
	return role, nil

}
