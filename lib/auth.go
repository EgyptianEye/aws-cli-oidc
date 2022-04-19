package lib

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/beevik/etree"
	pkce "github.com/nirasan/go-oauth-pkce-code-verifier"
	"github.com/pkg/browser"
	"github.com/pkg/errors"
	"github.com/spf13/viper"
)

func Authenticate(client *OIDCClient, config *viper.Viper) (*AWSCredentials, error) {
	roleArn := config.GetString(IAM_ROLE_ARN)
	maxSessionDurationSeconds, _ := strconv.ParseInt(config.GetString(MAX_SESSION_DURATION_SECONDS), 10, 64)
	roleSessName := config.GetString(AWS_FEDERATION_ROLE_SESSION_NAME)
	var (
		awsCreds *AWSCredentials
		err      error
	)
	tokenResponse, err := doLogin(client, config)
	if err != nil {
		return nil, fmt.Errorf("failed to login the OIDC provider: %w", err)
	}
	Writeln("Login successful!")
	Traceln("ID token: %s", tokenResponse.IDToken)
	awsFedType := config.GetString(AWS_FEDERATION_TYPE)
	switch awsFedType {
	case AWS_FEDERATION_TYPE_OIDC:
		awsCreds, err = GetCredentialsWithOIDC(client, tokenResponse.IDToken, roleArn, roleSessName, maxSessionDurationSeconds)
		if err != nil {
			return nil, fmt.Errorf("failed to get aws credentials with OIDC: %w", err)
		}
	case AWS_FEDERATION_TYPE_SAML2:
		samlAssertion, err := getSAMLAssertion(client, config, tokenResponse)
		if err != nil {
			return nil, fmt.Errorf("failed to get SAML2 assertion from OIDC provider: %w", err)
		}
		samlResponse, err := createSAMLResponse(client, samlAssertion)
		if err != nil {
			return nil, fmt.Errorf("failed to create SAML Response: %w", err)
		}
		awsCreds, err = GetCredentialsWithSAML(samlResponse, maxSessionDurationSeconds, roleArn)
		if err != nil {
			return nil, fmt.Errorf("failed to get aws credentials with SAML2: %w", err)
		}
	default:
		return nil, fmt.Errorf("invalid AWS federation type: %s", strings.ToUpper(awsFedType))
	}
	return awsCreds, nil
}

func getSAMLAssertion(client *OIDCClient, config *viper.Viper, tokenResponse *TokenResponse) (string, error) {
	audience := config.GetString(OIDC_PROVIDER_TOKEN_EXCHANGE_AUDIENCE)
	subjectTokenType := config.GetString(OIDC_PROVIDER_TOKEN_EXCHANGE_SUBJECT_TOKEN_TYPE)

	var subjectToken string
	if subjectTokenType == TOKEN_TYPE_ID_TOKEN {
		subjectToken = tokenResponse.IDToken
	} else if subjectTokenType == TOKEN_TYPE_ACCESS_TOKEN {
		subjectToken = tokenResponse.AccessToken
	}

	form := client.ClientForm()
	form.Set("audience", audience)
	form.Set("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange")
	form.Set("subject_token", subjectToken)
	form.Set("subject_token_type", subjectTokenType)
	form.Set("requested_token_type", "urn:ietf:params:oauth:token-type:saml2")

	res, err := client.Token().
		Request().
		Form(form).
		Post()

	if err != nil {
		return "", fmt.Errorf("error sending client request: %w", err)
	}

	Traceln("Exchanged SAML assertion response status: %d", res.Status())

	if res.Status() != 200 {
		if res.MediaType() != "" {
			var json map[string]interface{}
			err := res.ReadJson(&json)
			if err == nil {
				return "", errors.Errorf("Failed to exchange saml2 token, error: %s error_description: %s",
					json["error"], json["error_description"])
			}
		}
		return "", errors.Errorf("Failed to exchange saml2 token, statusCode: %d", res.Status())
	}

	var saml2TokenResponse *TokenResponse
	err = res.ReadJson(&saml2TokenResponse)
	if err != nil {
		return "", errors.Wrap(err, "Failed to parse token exchange response")
	}

	Traceln("SAML2 Assertion: %s", saml2TokenResponse.AccessToken)

	// TODO: Validation
	return saml2TokenResponse.AccessToken, nil
}

func createSAMLResponse(client *OIDCClient, samlAssertion string) (string, error) {
	s, err := base64.RawURLEncoding.DecodeString(samlAssertion)
	if err != nil {
		return "", errors.Wrap(err, "Failed to decode SAML2 assertion")
	}

	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(s); err != nil {
		return "", errors.Wrap(err, "Parse error")
	}

	assertionElement := doc.FindElement(".//Assertion")
	if assertionElement == nil {
		return "", errors.New("No Assertion element")
	}

	issuerElement := assertionElement.FindElement("./Issuer")
	if issuerElement == nil {
		return "", errors.New("No Issuer element")
	}

	subjectConfirmationDataElement := doc.FindElement(".//SubjectConfirmationData")
	if subjectConfirmationDataElement == nil {
		return "", errors.New("No SubjectConfirmationData element")
	}

	recipient := subjectConfirmationDataElement.SelectAttr("Recipient")
	if recipient == nil {
		return "", errors.New("No Recipient attribute")
	}

	issueInstant := assertionElement.SelectAttr("IssueInstant")
	if issueInstant == nil {
		return "", errors.New("No IssueInstant attribute")
	}

	newDoc := etree.NewDocument()

	samlp := newDoc.CreateElement("samlp:Response")
	samlp.CreateAttr("xmlns:samlp", "urn:oasis:names:tc:SAML:2.0:protocol")
	if assertionElement.Space != "" {
		samlp.CreateAttr("xmlns:"+assertionElement.Space, "urn:oasis:names:tc:SAML:2.0:assertion")
	}
	samlp.CreateAttr("Destination", recipient.Value)
	// samlp.CreateAttr("ID", "ID_760649d5-ebe0-4d8a-a107-4a16dd3e9ecd")
	samlp.CreateAttr("Version", "2.0")
	samlp.CreateAttr("IssueInstant", issueInstant.Value)
	samlp.AddChild(issuerElement.Copy())

	status := samlp.CreateElement("samlp:Status")
	statusCode := status.CreateElement("samlp:StatusCode")
	statusCode.CreateAttr("Value", "urn:oasis:names:tc:SAML:2.0:status:Success")
	assertionElement.RemoveAttr("xmlns:saml")
	samlp.AddChild(assertionElement)

	// newDoc.WriteTo(os.Stderr)
	return newDoc.WriteToString()
}

func doLogin(client *OIDCClient, config *viper.Viper) (*TokenResponse, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:")
	if err != nil {
		return nil, errors.Wrap(err, "Cannot start local http server to handle login redirect")
	}
	port := listener.Addr().(*net.TCPAddr).Port

	clientId := config.GetString(CLIENT_ID)
	redirect := fmt.Sprintf("http://127.0.0.1:%d", port)
	v, err := pkce.CreateCodeVerifierWithLength(pkce.MaxLength)
	if err != nil {
		return nil, errors.Wrap(err, "Cannot generate OAuth2 PKCE code_challenge")
	}
	challenge := v.CodeChallengeS256()
	verifier := v.String()

	authReq := client.Authorization().
		QueryParam("response_type", "code").
		QueryParam("client_id", clientId).
		QueryParam("redirect_uri", redirect).
		QueryParam("code_challenge", challenge).
		QueryParam("code_challenge_method", "S256").
		QueryParam("scope", "openid")

	additionalQuery := config.GetString(OIDC_AUTHENTICATION_REQUEST_ADDITIONAL_QUERY)
	if additionalQuery != "" {
		queries := strings.Split(additionalQuery, "&")
		for _, q := range queries {
			kv := strings.Split(q, "=")
			if len(kv) == 1 {
				authReq = authReq.QueryParam(kv[0], "")
			} else if len(kv) == 2 {
				authReq = authReq.QueryParam(kv[0], kv[1])
			} else {
				return nil, errors.Errorf("Invalid additional query: %s", q)
			}
		}
	}
	url := authReq.Url()

	code := launch(client, url.String(), listener)
	if code != "" {
		return codeToToken(client, verifier, code, redirect)
	} else {
		return nil, errors.New("Login failed, can't retrieve authorization code")
	}
}

func launch(client *OIDCClient, url string, listener net.Listener) string {
	c := make(chan string)

	http.HandleFunc("/", func(res http.ResponseWriter, req *http.Request) {
		code := req.URL.Query().Get("code")

		res.Header().Set("Content-Type", "text/html")

		// Redirect to user-defined successful/failure page
		successful := client.RedirectToSuccessfulPage()
		if successful != nil && code != "" {
			url := successful.Url()
			res.Header().Set("Location", (&url).String())
			res.WriteHeader(302)
		}
		failure := client.RedirectToFailurePage()
		if failure != nil && code == "" {
			url := failure.Url()
			res.Header().Set("Location", (&url).String())
			res.WriteHeader(302)
		}

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

func codeToToken(client *OIDCClient, verifier string, code string, redirect string) (*TokenResponse, error) {
	form := client.ClientForm()
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("code_verifier", verifier)
	form.Set("redirect_uri", redirect)

	Traceln("code2token params: %+v", form)

	res, err := client.Token().Request().Form(form).Post()

	if err != nil {
		return nil, errors.Wrap(err, "Failed to turn code into token")
	}

	if res.Status() != 200 {
		if res.MediaType() != "" {
			var json map[string]interface{}
			err := res.ReadJson(&json)
			if err == nil {
				return nil, errors.Errorf("Failed to turn code into token, error: %s error_description: %s",
					json["error"], json["error_description"])
			}
		}
		return nil, errors.Errorf("Failed to turn code into token")
	}

	var tokenResponse TokenResponse
	res.ReadJson(&tokenResponse)
	return &tokenResponse, nil
}
