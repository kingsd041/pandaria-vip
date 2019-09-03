package sso

type SUserBasic struct {
	SUser     `json:"data"`
	ErrorCode string `json:"error_code"`
}

type SUser struct {
	OrgName          string `json:"org_name"`
	Nickname         string `json:"nickname"`
	IamOpenid        string `json:"iam_openid"`
	Username         string `json:"username"`
	Mobile           string `json:"mobile"`
	Workno           string `json:"workno"`
	UserEmail        string `json:"userEmail"`
	EmailList        string `json:"email_list"`
	IamWechatUnionid string `json:"iam_wechat_unionid"`
	IamWechatOpenid  string `json:"iam_wechat_openid"`
}

type DCommon struct {
	Email           string `json:"email"`
	UserID          string `json:"user_id"`
	Username        string `json:"username"`
	UserToken       string `json:"user_token"`
	TenantID        string `json:"tenant_id"`
	TenantName      string `json:"tenant_name"`
	TenantShortName string `json:"tenant_short_name"`
}

type DUser struct {
	DCommon
	ZoneID     string `json:"zone_id"`
	ServiceID  string `json:"service_id"`
	TenantRole string `json:"tenant_role"`
	Jwt        string `json:"jwt"`
	IamOpenID  string `json:"iam_openid,omitempty"`
}

type UserInfoResponse struct {
	Code     string   `json:"code"`
	Massage  string   `json:"msg"`
	UserInfo *DUserV2 `json:"data,omitempty"`
}

type DUserV2 struct {
	DCommon
	IamOpenID  string `json:"open_id,omitempty"`
	UserMobile string `json:"user_mobile,omitempty"`
}

func (user DUserV2) ToDUser() DUser {
	return DUser{
		DCommon:   user.DCommon,
		IamOpenID: user.IamOpenID,
	}
}

type TenantInfo struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	LogoURL     string `json:"logo_url"`
	Available   bool   `json:"available"`
	QuotaUsages []struct {
		Name          string `json:"name,omitempty"`
		Unit          string `json:"unit,omitempty"`
		QuotaUnitID   string `json:"quota_unit_id,omitempty"`
		ID            string `json:"id,omitempty"`
		Limit         int64  `json:"limit,omitempty"`
		InUse         int64  `json:"in_use,omitempty"`
		ReleaseSource int64  `json:"release_source,omitempty"`
	} `json:"quota_usages"`
}

type TenantActions struct {
	Code string `json:"code,omitempty"`
	Data struct {
		ServiceRegionResp []struct {
			Actions []string `json:"clusterActions"`
			ClusterCommon
		} `json:"serviceRegionResp,omitempty"`
		UserInfo struct {
			Address     string `json:"address,omitempty"`
			CompanyName string `json:"company_name,omitempty"`
			Email       string `json:"email,omitempty"`
			IamOpenid   string `json:"iam_openid,omitempty"`
			ShortName   string `json:"short_name,omitempty"`
			Username    string `json:"username,omitempty"`
			WorkPhone   string `json:"work_phone,omitempty"`
		} `json:"tenantInfo,omitempty"`
	} `json:"data,omitempty"`
	Massage string `json:"msg,omitempty"`
}

type TenantActionInput struct {
	Region     string `json:"region,omitempty"`
	ServiceKey string `json:"sk,omitempty"`
	Digest     string `json:"digestKey,omitempty"`
}

type Region struct {
	Name        string `json:"name"`
	CityName    string `json:"cityName"`
	KeyName     string `json:"keyName"`
	RegionCloud string `json:"regionCloud"`
}

type ProductResponseCommon struct {
	Code    string `json:"code"`
	Massage string `json:"msg"`
}

type RegionList struct {
	ProductResponseCommon
	Data []Region `json:"data"`
}

type ClusterCommon struct {
	Cluster                string `json:"cluster,omitempty"`
	ClusterName            string `json:"clusterName,omitempty"`
	Region                 string `json:"region,omitempty"`
	RegionClusterAliasName string `json:"regionClusterAliasName,omitempty"`
	RegionClusterKeyName   string `json:"regionClusterKeyName,omitempty"`
	RegionClusterName      string `json:"regionClusterName,omitempty"`
	RegionName             string `json:"regionName,omitempty"`
	Zone                   string `json:"zone,omitempty"`
	ZoneName               string `json:"zoneName,omitempty"`
	EnvType                string `json:"envType"`
}

type ClusterList struct {
	ProductResponseCommon
	Data []ClusterCommon `json:"data"`
}
