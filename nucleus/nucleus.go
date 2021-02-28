package nucleus

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
)

const (
	defaultBaseURLFmt = "https://%v.nucleussec.com/nucleus/api/"
	userAgent         = "go-nucleus"
)

// Client for Nucleus Security API
type Client struct {
	client *http.Client

	BaseURL *url.URL

	UserAgent string

	common service
}

type service struct {
	client *Client
}

// NewClient returns a new Nucleus Security API Client.
// If httpClient is nil, a new http.Client is created.
func NewClient(organisation string, httpClient *http.Client) *Client {
	if httpClient == nil {
		httpClient = &http.Client{}
	}

	baseURL, _ := url.Parse(fmt.Sprintf(defaultBaseURLFmt, organisation))

	c := &Client{client: httpClient, BaseURL: baseURL, UserAgent: userAgent}
	c.common.client = c

	return c
}

// NewRequest creates a new API request.
func (c *Client) NewRequest(method, urlStr string, body interface{}) (*http.Request, error) {
	if !strings.HasSuffix(c.BaseURL.Path, "/") {
		return nil, fmt.Errorf("BaseURL must have a trailing slash, but %q does not", c.BaseURL)
	}
	u, err := c.BaseURL.Parse(urlStr)
	if err != nil {
		return nil, err
	}

	var buf io.ReadWriter
	if body != nil {
		buf = &bytes.Buffer{}
		enc := json.NewEncoder(buf)
		enc.SetEscapeHTML(false)
		err := enc.Encode(body)
		if err != nil {
			return nil, err
		}
	}

	req, err := http.NewRequest(method, u.String(), buf)
	if err != nil {
		return nil, err
	}

	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	if c.UserAgent != "" {
		req.Header.Set("User-Agent", c.UserAgent)
	}
	return req, nil
}

// ErrorResponse reports an error caused by the API request.
type ErrorResponse struct {
	Response *http.Response
	Success  bool   `json:"success"`
	Code     int    `json:"code"`
	Message  string `json:"message"`
}

func (r *ErrorResponse) Error() string {
	return fmt.Sprintf("%d %v %v: %v %d - %v",
		r.Response.StatusCode, r.Response.Request.Method, r.Response.Request.URL,
		r.Success, r.Code, r.Message)
}

// Do sends API request and returns http.Response
func (c *Client) Do(ctx context.Context, req *http.Request, v interface{}) (*http.Response, error) {
	if ctx == nil {
		return nil, errors.New("context must be non-nil")
	}
	req = req.WithContext(ctx)

	resp, err := c.client.Do(req)
	if err != nil {
		// If we got an error, and the context has been canceled,
		// the context's error is probably more useful.
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
			return nil, err
		}
	}

	defer resp.Body.Close()

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return resp, err
	}

	// On success, decode in to v if given
	if c := resp.StatusCode; 200 <= c && c <= 299 {

		if v != nil && data != nil {
			decErr := json.Unmarshal(data, v)
			if decErr == io.EOF {
				decErr = nil
			}
			err = decErr
		}
		return resp, err
	}

	// On error, decode into ErrorResponse
	errResp := &ErrorResponse{Response: resp}
	if data != nil {
		err = json.Unmarshal(data, errResp)
		if err != nil {
			return resp, err
		}
	}
	return resp, errResp
}

// APIKeyTransport is an http.RoundTripper that authenticates all requests
// by adding the x-apikey header with the provided value.
type APIKeyTransport struct {
	APIKey    string
	Transport http.RoundTripper
}

// RoundTrip implements the RoundTripper interface.
func (t *APIKeyTransport) RoundTrip(req *http.Request) (*http.Response, error) {

	req2 := new(http.Request)
	*req2 = *req
	req2.Header = make(http.Header, len(req.Header))

	for k, s := range req.Header {
		req2.Header[k] = append([]string(nil), s...)
	}

	req2.Header.Add("x-apikey", t.APIKey)

	return t.transport().RoundTrip(req2)
}

// Client returns an *http.Client that makes requests that are authenticated
// using the x-apikey header.
func (t *APIKeyTransport) Client() *http.Client {
	return &http.Client{Transport: t}
}

func (t *APIKeyTransport) transport() http.RoundTripper {
	if t.Transport != nil {
		return t.Transport
	}
	return http.DefaultTransport
}
