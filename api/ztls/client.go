package ztls

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/gabstv/ztls/internal/pkix"
)

const DefaultEndpoint = "https://ztls.gabs.dev"

type Client struct {
	Endpoint string
	APIKey   string
}

var DefaultClient = &Client{}

func (c *Client) GetCA(ctx context.Context) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, c.url("/1/ca.crt.pem"), nil)
	if err != nil {
		// this error triggers if the method or url is invalid, hence the panic
		panic(err)
	}
	if c.APIKey != "" {
		req.Header.Set("X-API-KEY", c.APIKey)
	}
	req = req.WithContext(ctx)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("http status " + resp.Status)
	}
	buf := new(bytes.Buffer)
	_, err = io.Copy(buf, resp.Body)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (c *Client) NewKey() ([]byte, error) {
	return pkix.NewKey(4096)
}

type NewCSRInput struct {
	CommonName         string   // [REQUIRED] Usually the publicly acessible domain name or IP address.
	Country            []string // [OPTIONAL] Alpha2 Country Code
	Province           []string // [OPTIONAL]
	Locality           []string // [OPTIONAL]
	Organization       []string // [OPTIONAL] Organization Name
	OrganizationalUnit []string // [OPTIONAL]
	StreetAddress      []string // [OPTIONAL]
	PostalCode         []string // [OPTIONAL]
	IPs                []string // [OPTIONAL] Additional IPs
	Domains            []string // [OPTIONAL] Additional Domains
}

func CommonName(name string) NewCSRInput {
	return NewCSRInput{
		CommonName: name,
	}
}

func (c *Client) NewCSR(input NewCSRInput, key []byte) ([]byte, error) {
	nfo := pkix.CSRInfo{
		Country:            input.Country,
		Province:           input.Province,
		Locality:           input.Locality,
		Organization:       input.Organization,
		OrganizationalUnit: input.OrganizationalUnit,
		StreetAddress:      input.StreetAddress,
		PostalCode:         input.PostalCode,
		IPs:                input.IPs,
		Domains:            input.Domains,
		CommonName:         input.CommonName,
	}
	return pkix.NewCSRPEM(nfo, key, nil)
}

func (c *Client) NewCertificate(ctx context.Context, csr []byte) ([]byte, error) {
	ur0 := "/1/new-certificate"
	if c.APIKey != "" {
		ur0 = "/1/new-server-certificate"
	}
	rdr := bytes.NewReader([]byte(fmt.Sprintf("{\"csr\":\"%s\"}", strings.Replace(string(csr), "\n", "\\n", -1))))
	req, err := http.NewRequest(http.MethodPost, c.url(ur0), rdr)
	if err != nil {
		// this error triggers if the method or url is invalid, hence the panic
		panic(err)
	}
	if c.APIKey != "" {
		req.Header.Set("X-API-KEY", c.APIKey)
	}
	req = req.WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b2 := new(bytes.Buffer)
		io.Copy(b2, resp.Body)
		return nil, errors.New("http status " + resp.Status + " " + b2.String())
	}
	buf := new(bytes.Buffer)
	_, err = io.Copy(buf, resp.Body)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (c *Client) url(remainder string) string {
	if c.Endpoint != "" {
		return c.Endpoint + remainder
	}
	return DefaultEndpoint + remainder
}
