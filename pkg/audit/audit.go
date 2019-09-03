package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/pborman/uuid"
	"github.com/pkg/errors"
	k8stypes "k8s.io/apimachinery/pkg/types"
	utilnet "k8s.io/apimachinery/pkg/util/net"
)

const (
	contentTypeJSON = "application/json"
)

const (
	requestReceived  = "RequestReceived"
	responseComplete = "ResponseComplete"
	saicLogFormat    = "2006-01-02 15:04:05 -0700"
)

const (
	levelNull = iota
	levelMetadata
	levelRequest
	levelRequestResponse
)

var (
	bodyMethods = map[string]bool{
		http.MethodPut:  true,
		http.MethodPost: true,
	}
	sensitiveRequestHeader  = []string{"Cookie", "Authorization"}
	sensitiveResponseHeader = []string{"Cookie", "Set-Cookie"}
)

type auditLog struct {
	log     *log
	writer  *LogWriter
	req     *http.Request
	reqBody []byte
}

type log struct {
	// AuditID           k8stypes.UID `json:"auditID,omitempty"`
	// RequestURI        string       `json:"requestURI,omitempty"`
	// User              *UserInfo    `json:"user,omitempty"`
	// Method            string       `json:"method,omitempty"`
	// RemoteAddr        string       `json:"remoteAddr,omitempty"`
	// RequestTimestamp  string       `json:"requestTimestamp,omitempty"`
	// ResponseTimestamp string       `json:"responseTimestamp,omitempty"`
	// ResponseCode      int          `json:"responseCode,omitempty"`
	// RequestHeader     http.Header  `json:"requestHeader,omitempty"`
	// ResponseHeader    http.Header  `json:"responseHeader,omitempty"`
	// RequestBody       []byte       `json:"requestBody,omitempty"`
	// ResponseBody      []byte       `json:"responseBody,omitempty"`
	AuditID        k8stypes.UID `json:"auditID,omitempty"`
	RequestURI     string       `json:"requestURI,omitempty"`
	RequestBody    interface{}  `json:"requestBody,omitempty"`
	ResponseBody   interface{}  `json:"responseBody,omitempty"`
	ResponseStatus string       `json:"responseStatus,omitempty"`
	SourceIPs      []string     `json:"sourceIPs,omitempty"`
	User           *UserInfo    `json:"user,omitempty"`
	UserAgent      string       `json:"userAgent,omitempty"`
	Verb           string       `json:"verb,omitempty"`
	Stage          string       `json:"stage,omitempty"`
	StageTimestamp string       `json:"stageTimestamp,omitempty"`
}

var userKey struct{}

type UserInfo struct {
	Name  string   `json:"name,omitempty"`
	Group []string `json:"group,omitempty"`
	// RequestUser is the --as user
	RequestUser string `json:"requestUser,omitempty"`
	// RequestGroups is the --as-group list
	RequestGroups []string `json:"requestGroups,omitempty"`
}

func GetUserInfo(req *http.Request) *UserInfo {
	return &UserInfo{
		Name:  req.Header.Get("Impersonate-User"),
		Group: req.Header["Impersonate-Group"],
	}
}

func FromContext(ctx context.Context) (*UserInfo, bool) {
	u, ok := ctx.Value(userKey).(*UserInfo)
	return u, ok
}

func new(writer *LogWriter, req *http.Request) (*auditLog, error) {
	auditLog := &auditLog{
		writer: writer,
		req:    req,
		log: &log{
			AuditID:        k8stypes.UID(uuid.NewRandom().String()),
			RequestURI:     req.RequestURI,
			Verb:           req.Method,
			StageTimestamp: time.Now().Format(saicLogFormat),
		},
	}

	contentType := req.Header.Get("Content-Type")
	if writer.Level >= levelRequest && bodyMethods[req.Method] && contentType == contentTypeJSON {
		reqBody, err := readBodyWithoutLosingContent(req)
		if err != nil {
			return nil, err
		}
		auditLog.reqBody = reqBody
	}
	return auditLog, nil
}

func (a *auditLog) write(userInfo *UserInfo, reqHeaders, resHeaders http.Header, resCode int, resBody []byte) error {
	a.log.User = userInfo
	// a.log.ResponseTimestamp = time.Now().Format(time.RFC3339)
	// a.log.RequestHeader = filterOutHeaders(reqHeaders, sensitiveRequestHeader)
	// a.log.ResponseHeader = filterOutHeaders(resHeaders, sensitiveResponseHeader)
	// a.log.ResponseCode = resCode

	var buffer bytes.Buffer
	alByte, err := json.Marshal(a.log)
	if err != nil {
		return err
	}

	buffer.Write(bytes.TrimSuffix(alByte, []byte("}")))
	if a.writer.Level >= levelRequest && len(a.reqBody) > 0 {
		buffer.WriteString(`,"requestBody":`)
		buffer.Write(bytes.TrimSuffix(a.reqBody, []byte("\n")))
	}
	if a.writer.Level >= levelRequestResponse && resHeaders.Get("Content-Type") == contentTypeJSON && len(resBody) > 0 {
		buffer.WriteString(`,"responseBody":`)
		buffer.Write(bytes.TrimSuffix(resBody, []byte("\n")))
	}
	buffer.WriteString("}")

	var compactBuffer bytes.Buffer
	err = json.Compact(&compactBuffer, buffer.Bytes())
	if err != nil {
		return errors.Wrap(err, "compact audit log json failed")
	}

	compactBuffer.WriteString("\n")
	_, err = a.writer.Output.Write(compactBuffer.Bytes())
	return err
}

func readBodyWithoutLosingContent(req *http.Request) ([]byte, error) {
	if !bodyMethods[req.Method] {
		return nil, nil
	}

	bodyBytes, err := ioutil.ReadAll(req.Body)
	if err != nil {
		return nil, err
	}
	req.Body = ioutil.NopCloser(bytes.NewBuffer(bodyBytes))

	return bodyBytes, nil
}

func filterOutHeaders(headers http.Header, filterKeys []string) map[string][]string {
	newHeader := make(map[string][]string)
	for k, v := range headers {
		if isExist(filterKeys, k) {
			continue
		}
		newHeader[k] = v
	}
	return newHeader
}

func isExist(array []string, key string) bool {
	for _, v := range array {
		if v == key {
			return true
		}
	}
	return false
}

func (a *auditLog) writeRequest(userInfo *UserInfo, reqHeaders, resHeaders http.Header, resCode int, resBody []byte) error {
	var buffer bytes.Buffer
	a.log.User = userInfo
	a.log.Stage = requestReceived
	// a.log.StageTimestamp =time.Now().Format(saicLogFormat)
	// a.log.RequestHeader = filterOutHeaders(reqHeaders, sensitiveRequestHeader)
	ips := utilnet.SourceIPs(a.req)
	for _, ip := range ips {
		a.log.SourceIPs = append(a.log.SourceIPs, ip.String())
	}
	alByte, err := json.Marshal(a.log)
	if err != nil {
		return err
	}
	buffer.Write(bytes.TrimSuffix(alByte, []byte("}")))
	if a.writer.Level >= levelRequest && len(a.reqBody) > 0 {
		buffer.WriteString(`,"requestBody":`)
		buffer.Write(bytes.TrimSuffix(a.reqBody, []byte("\n")))
	}
	buffer.WriteString("}")
	var compactBuffer bytes.Buffer
	err = json.Compact(&compactBuffer, buffer.Bytes())
	if err != nil {
		return errors.Wrap(err, "compact audit log json failed")
	}
	compactBuffer.WriteString("\n")
	_, err = a.writer.Output.Write(compactBuffer.Bytes())
	return err
}

func (a *auditLog) writeResponse(userInfo *UserInfo, reqHeaders, resHeaders http.Header, resCode int, resBody []byte) error {
	var buffer bytes.Buffer
	a.log.Stage = responseComplete
	a.log.StageTimestamp = time.Now().Format(saicLogFormat)
	a.log.ResponseStatus = fmt.Sprint(resCode)
	// a.log.ResponseTimestamp = time.Now().Format(time.RFC3339)
	// a.log.ResponseHeader = filterOutHeaders(resHeaders, sensitiveResponseHeader)
	// a.log.ResponseCode = resCode
	alByte, err := json.Marshal(a.log)
	if err != nil {
		return err
	}
	buffer.Write(bytes.TrimSuffix(alByte, []byte("}")))
	if a.writer.Level >= levelRequestResponse && resHeaders.Get("Content-Type") == contentTypeJSON && len(resBody) > 0 {
		buffer.WriteString(`,"responseBody":`)
		buffer.Write(bytes.TrimSuffix(resBody, []byte("\n")))
	}
	buffer.WriteString("}")
	var compactBuffer bytes.Buffer
	err = json.Compact(&compactBuffer, buffer.Bytes())
	if err != nil {
		return errors.Wrap(err, "compact audit log json failed")
	}
	compactBuffer.WriteString("\n")
	_, err = a.writer.Output.Write(compactBuffer.Bytes())
	return err
}
