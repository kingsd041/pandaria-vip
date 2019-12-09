package publicapi

import (
	"fmt"
	"math"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rancher/norman/httperror"
	"github.com/rancher/norman/types"

	"github.com/sirupsen/logrus"
	"golang.org/x/time/rate"
)

var (
	ipLookups = []string{"X-Forwarded-For", "X-Real-IP", "RemoteAddr"}
)

const (
	defaultRequestsPerSecond = 1.0
	defaultCooldown          = 20 * time.Second
	defaultFailureTimes      = 3
	loginCooldownEnv         = "PANDARIA_LOGIN_COOLDOWN"
	loginRateLimitEnv        = "PANDARIA_LOGIN_RATELIMIT"
	responseFailureHeader    = "X-Pandaria-Login-Failure"
	responseCooldownHeader   = "X-Pandaria-Login-CoolDown"
)

// AuthLimiter can only work for local auth provider
type AuthLimiter struct {
	df     map[string]int
	dt     map[string]time.Time
	mu     *sync.RWMutex
	period time.Duration
}

func newAuthLimiter() *AuthLimiter {
	var period time.Duration

	cooldown := os.Getenv(loginCooldownEnv)
	if cooldown != "" {
		period, _ = time.ParseDuration(cooldown)
	}

	if period <= 0 {
		period = defaultCooldown
	}
	logrus.Infof("Auth limit cooldown period for login http request: %s", period.String())

	return &AuthLimiter{
		df:     make(map[string]int),
		dt:     make(map[string]time.Time),
		mu:     &sync.RWMutex{},
		period: period,
	}
}

func (al *AuthLimiter) MarkFailure(key string, request *types.APIContext) int {
	if os.Getenv(loginCooldownEnv) == "" {
		return 0
	}

	al.mu.Lock()
	defer al.mu.Unlock()

	count, ok := al.df[key]
	if ok {
		if count < defaultFailureTimes {
			al.df[key] = count + 1
		}
		if al.df[key] >= defaultFailureTimes {
			al.dt[key] = time.Now().Add(al.period)
		}
	} else {
		al.df[key] = 1
	}

	request.Response.Header().Add(responseFailureHeader, strconv.Itoa(al.df[key]))
	return al.df[key]
}

func (al *AuthLimiter) getCooldownTime(key string) (time.Time, bool) {
	al.mu.Lock()
	defer al.mu.Unlock()

	t, ok := al.dt[key]
	return t, ok
}

func (al *AuthLimiter) reset(key string) {
	al.mu.Lock()
	defer al.mu.Unlock()

	delete(al.df, key)
	delete(al.dt, key)
}

func (al *AuthLimiter) LimitByUser(key string, request *types.APIContext) error {
	if os.Getenv(loginCooldownEnv) != "" {
		t, exist := al.getCooldownTime(key)
		if exist {
			cd := t.Sub(time.Now())
			if cd > 0 {
				displayCD := fmt.Sprintf("%0.2fs", cd.Seconds())
				request.Response.Header().Add(responseCooldownHeader, displayCD)
				return httperror.NewAPIError(httperror.PermissionDenied, fmt.Sprintf("You should try after %s.", displayCD))
			}
			al.reset(key)
		}
	}

	return nil
}

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

// addIP creates a new rate limiter and adds it to the ips map,
// using the IP address as the key
func (i *IPRateLimiter) addIP(ip string) *rate.Limiter {
	i.mu.Lock()
	defer i.mu.Unlock()

	limiter := rate.NewLimiter(i.r, i.b)

	i.ips[ip] = limiter

	return limiter
}

// getLimiter returns the rate limiter for the provided IP address if it exists.
// Otherwise calls addIP to add IP address to the map
func (i *IPRateLimiter) getLimiter(ip string) *rate.Limiter {
	i.mu.Lock()
	limiter, exists := i.ips[ip]

	if !exists {
		i.mu.Unlock()
		return i.addIP(ip)
	}

	i.mu.Unlock()

	return limiter
}

func (i *IPRateLimiter) LimitByRequest(request *types.APIContext) error {
	if os.Getenv(loginRateLimitEnv) != "" {
		limiter := i.getLimiter(lookupRemoteIP(request.Request))
		if !limiter.Allow() {
			return httperror.NewAPIError(httperror.MaxLimitExceeded, "You have reached maximum request limit.")
		}
	}

	return nil
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
