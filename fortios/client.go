package fortios

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/fgtdev/fortios-sdk-go/auth"
	"github.com/fgtdev/fortios-sdk-go/sdkcore"
	"gitlab.com/fortios/fortisdk"
)

// Config gets the authentication information from the given metadata
type Config struct {
	Hostname string
	Token    string
	Insecure *bool
	CABundle string
	Vdom     string
}

// FortiClient contains the basic FortiOS SDK connection information to FortiOS
// It can be used to as a client of FortiOS for the plugin
type FortiClient struct {
	//to sdk client
	Client *forticlient.FortiSDKClient

	SDK *fortisdk.ClientWithResponses
}

// CreateClient creates a FortiClient Object with the authentication information.
// It returns the FortiClient Object for the use when the plugin is initialized.
func (c *Config) CreateClient() (interface{}, error) {
	var fClient FortiClient

	config := &tls.Config{}

	auth := auth.NewAuth(c.Hostname, c.Token, c.CABundle, c.Vdom)

	if auth.Hostname == "" {
		auth.GetEnvHostname()
	}

	if auth.Token == "" {
		auth.GetEnvToken()
	}

	if auth.CABundle == "" {
		auth.GetEnvCABundle()
	}
	//auth.Hostname = auth.Hostname + ":10443"

	if auth.CABundle != "" {
		f, err := os.Open(auth.CABundle)
		if err != nil {
			return nil, fmt.Errorf("Error reading CA Bundle: %s", err)
		}
		defer f.Close()

		caBundle, err := ioutil.ReadAll(f)
		if err != nil {
			return nil, fmt.Errorf("Error reading CA Bundle: %s", err)
		}

		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM([]byte(caBundle)) {
			return nil, fmt.Errorf("Error reading CA Bundle")
		}
		config.RootCAs = pool
	}

	if c.Insecure == nil {
		b, _ := auth.GetEnvInsecure()
		config.InsecureSkipVerify = b
	} else {
		config.InsecureSkipVerify = *c.Insecure
	}

	if config.InsecureSkipVerify == false && auth.CABundle == "" {
		return nil, fmt.Errorf("Error getting CA Bundle, CA Bundle should be set when insecure is false")
	}

	tr := &http.Transport{
		TLSClientConfig: config,
	}

	client := &http.Client{
		Transport: tr,
		Timeout:   time.Second * 10,
	}

	fc := forticlient.NewClient(auth, client)

	fClient.Client = fc

	// Example providing your own provider using an anonymous function wrapping in the
	// InterceptoFn adapter. The behaviour between the InterceptorFn and the Interceptor interface
	// are the same as http.HandlerFunc and http.Handler.
	customProvider := func(req *http.Request, ctx context.Context) error {
		// Just log the request header, nothing else.
		log.Println(req.Header)
		query := req.URL.Query()
		query.Add("access_token", auth.Token)
		path := req.URL.Path

		noHTTP := strings.Replace(path, "https:", "PLACEHOLDER", -1)
		noHTTPSingleSlash := strings.Replace(noHTTP, "//", "/", -1)
		withHTTP := strings.Replace(noHTTPSingleSlash, "PLACEHOLDER", "https:", -1)
		req.URL.RawPath = withHTTP
		req.URL.RawQuery = query.Encode()
		raw := req.URL.RawQuery
		log.Println(string(raw))
		return nil
	}
	sdkClient, err := fortisdk.NewClient(
		context.Background(),
		[]fortisdk.ClientOption{
			fortisdk.WithBaseURL("https://" + auth.Hostname + "/api/v2/cmdb"),
			fortisdk.WithHTTPClient(client),
			fortisdk.WithRequestEditorFn(customProvider),
		}...,
	)
	if err != nil {
		return nil, err
	}

	fClient.SDK = sdkClient

	return &fClient, nil
}
