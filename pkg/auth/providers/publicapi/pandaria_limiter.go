package publicapi

import (
	"math"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/rancher/norman/httperror"
	"github.com/rancher/norman/types"

	"github.com/sirupsen/logrus"
	"golang.org/x/time/rate"
)

var (
	defaultRequestsPerSecond float64 = 1
	ipLookups                        = []string{"X-Forwarded-For", "X-Real-IP", "RemoteAddr"}
)

// IPRateLimiter .
type IPRateLimiter struct {
	ips map[string]*rate.Limiter
	mu  *sync.RWMutex
	r   rate.Limit
	b   int
}

func newIPRateLimiter() *IPRateLimiter {
	var max float64

	rateLimitEnv := os.Getenv("PANDARIA_LOGIN_RATELIMIT")
	if rateLimitEnv != "" {
		max, _ = strconv.ParseFloat(rateLimitEnv, 64)
	}

	if max <= 0 {
		max = defaultRequestsPerSecond
	}
	logrus.Infof("rate limit for login http request: %f/s", max)

	i := &IPRateLimiter{
		ips: make(map[string]*rate.Limiter),
		mu:  &sync.RWMutex{},
		r:   rate.Limit(max),
		b:   int(math.Max(1, max)),
	}

	return i
}

// AddIP creates a new rate limiter and adds it to the ips map,
// using the IP address as the key
func (i *IPRateLimiter) AddIP(ip string) *rate.Limiter {
	i.mu.Lock()
	defer i.mu.Unlock()

	limiter := rate.NewLimiter(i.r, i.b)

	i.ips[ip] = limiter

	return limiter
}

// GetLimiter returns the rate limiter for the provided IP address if it exists.
// Otherwise calls AddIP to add IP address to the map
func (i *IPRateLimiter) GetLimiter(ip string) *rate.Limiter {
	i.mu.Lock()
	limiter, exists := i.ips[ip]

	if !exists {
		i.mu.Unlock()
		return i.AddIP(ip)
	}

	i.mu.Unlock()

	return limiter
}

func lookupRemoteIP(r *http.Request) string {
	realIP := r.Header.Get("X-Real-IP")
	forwardedFor := r.Header.Get("X-Forwarded-For")

	for _, lookup := range ipLookups {
		if lookup == "RemoteAddr" {
			// 1. Cover the basic use cases for both ipv4 and ipv6
			ip, _, err := net.SplitHostPort(r.RemoteAddr)
			if err != nil {
				// 2. Upon error, just return the remote addr.
				return r.RemoteAddr
			}
			return ip
		}
		if lookup == "X-Forwarded-For" && forwardedFor != "" {
			// X-Forwarded-For is potentially a list of addresses separated with ","
			parts := strings.Split(forwardedFor, ",")
			for i, p := range parts {
				parts[i] = strings.TrimSpace(p)
			}

			partIndex := len(parts) - 1
			if partIndex < 0 {
				partIndex = 0
			}

			return parts[partIndex]
		}
		if lookup == "X-Real-IP" && realIP != "" {
			return realIP
		}
	}

	return ""
}

func limitByRequest(lmt *IPRateLimiter, request *types.APIContext) error {
	if os.Getenv("PANDARIA_LOGIN_RATELIMIT") != "" {
		limiter := lmt.GetLimiter(lookupRemoteIP(request.Request))
		if !limiter.Allow() {
			return httperror.NewAPIError(httperror.MaxLimitExceeded, "You have reached maximum request limit.")
		}
	}

	return nil
}
