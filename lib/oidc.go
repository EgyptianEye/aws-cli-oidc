package lib

import (
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/pkg/browser"
	"github.com/pkg/errors"
	"golang.org/x/oauth2"
)

// type RESTClient struct {
// 	client *RestClient
// }

type oidcMetadataResponse struct {
	Issuer                                     string   `json:"issuer"`
	AuthorizationEndpoint                      string   `json:"authorization_endpoint"`
	TokenEndpoint                              string   `json:"token_endpoint"`
	TokenIntrospectionEndpoint                 string   `json:"token_introspection_endpoint"`
	UserinfoEndpoint                           string   `json:"userinfo_endpoint"`
	EndSessionEndpoint                         string   `json:"end_session_endpoint"`
	JwksURI                                    string   `json:"jwks_uri"`
	CheckSessionIframe                         string   `json:"check_session_iframe"`
	GrantTypesSupported                        []string `json:"grant_types_supported"`
	ResponseTypesSupported                     []string `json:"response_types_supported"`
	SubjectTypesSupported                      []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported           []string `json:"id_token_signing_alg_values_supported"`
	UserinfoSigningAlgValuesSupported          []string `json:"userinfo_signing_alg_values_supported"`
	RequestObjectSigningAlgValuesSupported     []string `json:"request_object_signing_alg_values_supported"`
	ResponseModesSupported                     []string `json:"response_modes_supported"`
	RegistrationEndpoint                       string   `json:"registration_endpoint"`
	TokenEndpointAuthMethodsSupported          []string `json:"token_endpoint_auth_methods_supported"`
	TokenEndpointAuthSigningAlgValuesSupported []string `json:"token_endpoint_auth_signing_alg_values_supported"`
	ClaimsSupported                            []string `json:"claims_supported"`
	ClaimTypesSupported                        []string `json:"claim_types_supported"`
	ClaimsParameterSupported                   bool     `json:"claims_parameter_supported"`
	ScopesSupported                            []string `json:"scopes_supported"`
	RequestParameterSupported                  bool     `json:"request_parameter_supported"`
	RequestURIParameterSupported               bool     `json:"request_uri_parameter_supported"`
	CodeChallengeMethodsSupported              []string `json:"code_challenge_methods_supported"`
	TLSClientCertificateBoundAccessTokens      bool     `json:"tls_client_certificate_bound_access_tokens"`
}

type idtoken struct {
	raw               string   `json:"-"`
	Username          string   `json:"username"`
	PreferredUsername string   `json:"preferred_username"`
	Roles             []string `json:"roles"`
}

func getOIDCConfig(c *Config) (*oauth2.Config, error) {
	resp, err := http.Get(c.MetaURL)
	if err != nil {
		return nil, err
	}
	var meta oidcMetadataResponse
	if err = json.NewDecoder(resp.Body).Decode(&meta); err != nil {
		return nil, err
	}
	return &oauth2.Config{
		ClientID:     c.ClientID,
		ClientSecret: c.ClientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:  meta.AuthorizationEndpoint,
			TokenURL: meta.TokenEndpoint,
		},
		RedirectURL: "",
		Scopes:      c.Scopes,
	}, nil
}

func codeFlow(config *Config) (*idtoken, error) {
	oconf, err := getOIDCConfig(config)
	if err != nil {
		return nil, err
	}
	listener, err := net.Listen("tcp", "127.0.0.1:")
	if err != nil {
		return nil, errors.Wrap(err, "Cannot start local http server to handle login redirect")
	}
	port := listener.Addr().(*net.TCPAddr).Port
	redir := fmt.Sprintf("http://127.0.0.1:%d", port)
	state := md5sum(time.Now().String() + redir)
	cv := newCodeVerifier(state[4:8])
	oconf.RedirectURL = redir
	url := oconf.AuthCodeURL(state,
		oauth2.SetAuthURLParam("code_challenge", cv.chanllenge()),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"))
	if err != nil {
		return nil, err
	}
	if code := launch(listener, url); code != "" {
		return exchangeToken(oconf, code, cv.verifier)
	} else {
		return nil, errors.New("Login failed, can't retrieve authorization code")
	}
}

func launch(listener net.Listener, url string) string {
	c := make(chan string)
	http.HandleFunc("/", func(res http.ResponseWriter, req *http.Request) {
		code := req.URL.Query().Get("code")
		res.Header().Set("Content-Type", "text/html")
		// Response result page
		message := "Login "
		close := " onload=\"window.close();\""
		if code != "" {
			message += "successful"
		} else {
			message += "failed"
			close = ""
		}
		res.Header().Set("Cache-Control", "no-store")
		res.Header().Set("Pragma", "no-cache")
		res.WriteHeader(200)
		res.Write([]byte(fmt.Sprintf(`<!DOCTYPE html>
<body%s>
%s
</body>
</html>
`, close, message)))
		if f, ok := res.(http.Flusher); ok {
			f.Flush()
		}
		time.Sleep(100 * time.Millisecond)
		c <- code
	})
	srv := &http.Server{}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	defer srv.Shutdown(ctx)
	go func() {
		if err := srv.Serve(listener); err != nil && err != http.ErrServerClosed {
			Exit(fmt.Errorf("error serving http callback: %w", err))
		}
	}()
	var code string
	if err := browser.OpenURL(url); err == nil {
		code = <-c
	}
	return code
}

func exchangeToken(oconf *oauth2.Config, code, verifier string) (*idtoken, error) {
	token, err := oconf.Exchange(context.TODO(), code, oauth2.SetAuthURLParam("code_verifier", verifier))
	if err != nil {
		return nil, err
	}
	token1, ok := token.Extra("id_token").(string)
	if !ok {
		return nil, errors.Wrap(err, "failed to turn code into token")
	}
	return unmarshall(token1)
}

func unmarshall(s string) (*idtoken, error) {
	part := strings.Split(s, ".")
	if len(part) != 3 {
		return nil, errors.New("invalid ID token")
	}
	var it idtoken
	if err := json.NewDecoder(base64.NewDecoder(base64.RawURLEncoding, strings.NewReader(part[1]))).Decode(&it); err != nil {
		return nil, err
	}
	it.raw = s
	return &it, nil
}

type codeVerifer struct {
	verifier string
}

func newCodeVerifier(s string) codeVerifer {
	set := append([]byte(s), 0x2d, 0x2e, 0x5f, 0x7e) // -._~
	length := len(set)
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	var sb strings.Builder
	for i := 0; i < 50; i++ {
		sb.WriteByte(set[r.Intn(length)])
	}
	return codeVerifer{sb.String()}
}

func (cv codeVerifer) chanllenge() string {
	s := sha256.Sum256([]byte(cv.verifier))
	return base64.RawURLEncoding.EncodeToString(s[:])
}

func md5sum(s string) string {
	bs := md5.Sum([]byte(s))
	return hex.EncodeToString(bs[:])
}
