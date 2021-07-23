package corsproxy

import (
	"context"
	"encoding/base64"
	"fmt"
	"github.com/HayoVanLoon/go-commons/logjson"
	"github.com/rs/cors"
	"golang.org/x/oauth2"
	"google.golang.org/api/idtoken"
	"google.golang.org/api/option"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
)

// CreateCorsProxy will create a new proxying http.Handler that takes control of
// CORS.
func CreateCorsProxy(target *url.URL, origins []string, allowCredentials bool, transport *http.RoundTripper, debug bool) (http.Handler, error) {
	proxy, err := CreateIdTokenProxy(target, "", "", transport, debug)
	if err != nil {
		return nil, fmt.Errorf("error creating proxy: %s", err)
	}
	return CreateHandler(proxy, origins, allowCredentials)
}

// CreateHandler creates a CORS handling http.Handler from a reverse proxy.
func CreateHandler(proxy *httputil.ReverseProxy, origins []string, allow bool) (http.Handler, error) {
	var h http.Handler = proxy
	// be rather permissive
	fn, err := originsFn(origins...)
	if err != nil {
		return nil, err
	}
	if len(origins) == 1 && origins[0] == "*" && allow {
		logjson.Warn("The combination 'Access-Control-Allow-Origin: *' and 'Access-Control-Allow-Credentials: true' might lead to errors, see: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Origin")
	}
	h = cors.New(cors.Options{
		AllowOriginFunc:  fn,
		AllowedMethods:   []string{http.MethodHead, http.MethodGet, http.MethodPost, http.MethodDelete, http.MethodPatch, http.MethodHead},
		AllowedHeaders:   []string{"*"},
		AllowCredentials: allow,
	}).Handler(h)

	return h, nil
}

func originsFn(origins ...string) (func(string) bool, error) {
	if len(origins) == 0 || origins[0] == "*" {
		return func(o string) bool {
			return true
		}, nil
	}
	hosts := make(map[string]bool)
	for _, origin := range origins {
		expected, err := url.Parse(origin)
		if err != nil {
			return nil, fmt.Errorf("cannot parse '%s' as url: %s", origin, err)
		}
		hosts[expected.Host] = true
	}
	return func(o string) bool {
		u, err := url.Parse(o)
		if err != nil {
			return false
		}
		if strings.HasPrefix(u.Host, "localhost:") {
			return true
		}
		return hosts[u.Host]
	}, nil
}

// CreateIdTokenProxy will create a new reverse proxy. If an audience is
// specified, it will add (and possibly overwrite) Open ID tokens to the proxied
// requests.
//
// The identity token source will use the Google ADC system to retrieve
// credentials (https://cloud.google.com/docs/authentication/production). You
// can override this by specifying a credentials file path. When running on
// Google infrastructure however, the latter is highly discouraged.
func CreateIdTokenProxy(target *url.URL, audience, credentialsFile string, transport *http.RoundTripper, debug bool) (*httputil.ReverseProxy, error) {
	proxy := httputil.NewSingleHostReverseProxy(target)
	std := proxy.Director
	proxy.Director = func(r *http.Request) {
		std(r)
		r.Host = target.Host
	}

	if transport == nil {
		proxy.Transport = RemoveCorsTripper{Base: http.DefaultTransport}
	} else {
		proxy.Transport = RemoveCorsTripper{Base: *transport}
	}
	if debug {
		proxy.Transport = LogTripper{Base: proxy.Transport}
	}

	if audience != "" {
		if err := addIdTokenTransport(proxy, audience, credentialsFile); err != nil {
			return nil, fmt.Errorf("error creating id token source transport: %s", err)
		}
	}

	return proxy, nil
}

func addIdTokenTransport(proxy *httputil.ReverseProxy, aud, gacFile string) error {
	ctx := context.Background()

	var opts []idtoken.ClientOption
	if gacFile != "" {
		opts = append(opts, option.WithCredentialsFile(gacFile))
		opts = append(opts, option.WithAudiences(aud))
	}
	ts, err := idtoken.NewTokenSource(ctx, aud, opts...)
	if err != nil {
		return err
	}

	proxy.Transport = &oauth2.Transport{Source: ts, Base: proxy.Transport}
	return nil
}

// A RemoveCorsTripper removes all CORS headers from the incoming response.
type RemoveCorsTripper struct {
	Base http.RoundTripper
}

func (r RemoveCorsTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	resp, err := r.Base.RoundTrip(request)
	if resp != nil {
		resp.Header.Del("Access-Control-Allow-Origin")
		resp.Header.Del("Access-Control-Allow-Methods")
		resp.Header.Del("Access-Control-Allow-Headers")
		resp.Header.Del("Access-Control-Max-Age")
	}
	return resp, err
}

// A LogTripper logs information about underlying round trip. It will also
// decode and log the payload of a Jwt-token if one is found in the
// Authorization header.
type LogTripper struct {
	// RoundTripper to log about
	Base http.RoundTripper
}

func (l LogTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	logJwtHeaderPayload(request, "Authorization")
	resp, err := l.Base.RoundTrip(request)
	if err == nil {
		logjson.Debug("(%v) %s %s", resp.StatusCode, request.Method, request.URL)
	} else {
		logjson.Debug("(!!!) %s %s", request.Method, request.URL)
	}
	return resp, err
}

func logJwtHeaderPayload(r *http.Request, key string) {
	h := r.Header.Get(key)
	if h == "" {
		return
	}
	parts := strings.Split(h, ".")
	if len(parts) != 3 {
		return
	}
	bs, err := base64.RawStdEncoding.DecodeString(parts[1])
	if err != nil {
		return
	}
	logjson.Debug("%s: %s", key, bs)
}
