package fortios

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"time"

	"git.hv.devk.de/awsplattform/swagger-fortios"
	"github.com/fgtdev/fortios-sdk-go/auth"
	"github.com/fgtdev/fortios-sdk-go/sdkcore"
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

	SWG *SWG
}

// SWG is a wrapper for a swagger-generated client
type SWG struct {
	Ctx    context.Context
	Client *swagger.APIClient
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

	swaggerClientConfiguration := swagger.NewConfiguration()
	swaggerClientConfiguration.Host = auth.Hostname
	swaggerClientConfiguration.HTTPClient = client

	fClient.SWG = &SWG{
		Ctx:    context.WithValue(context.Background(), swagger.ContextAccessToken, auth.Token),
		Client: swagger.NewAPIClient(swaggerClientConfiguration),
	}

	return &fClient, nil
}
