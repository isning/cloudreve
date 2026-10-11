package oidc

import (
	"fmt"
	"io"
	"net/http"
	"time"
)

const maxProviderResponse = 2 << 20

type limitedTransport struct{ next http.RoundTripper }

func (t limitedTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	response, err := t.next.RoundTrip(request)
	if err != nil {
		return nil, err
	}
	if response.ContentLength > maxProviderResponse {
		response.Body.Close()
		return nil, fmt.Errorf("provider response is too large")
	}
	response.Body = &limitedBody{body: response.Body, remaining: maxProviderResponse}
	return response, nil
}

type limitedBody struct {
	body      io.ReadCloser
	remaining int
}

func (b *limitedBody) Read(data []byte) (int, error) {
	if b.remaining == 0 {
		var probe [1]byte
		n, err := b.body.Read(probe[:])
		if n > 0 {
			return 0, fmt.Errorf("provider response is too large")
		}
		return 0, err
	}
	if len(data) > b.remaining {
		data = data[:b.remaining]
	}
	n, err := b.body.Read(data)
	b.remaining -= n
	return n, err
}
func (b *limitedBody) Close() error { return b.body.Close() }
func providerHTTP(original *http.Client) *http.Client {
	client := http.Client{Timeout: 15 * time.Second}
	if original != nil {
		client = *original
		if client.Timeout <= 0 {
			client.Timeout = 15 * time.Second
		}
	}
	transport := client.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}
	client.Transport = limitedTransport{transport}
	client.CheckRedirect = func(request *http.Request, via []*http.Request) error {
		if len(via) >= 5 || len(via) == 0 || !validEndpoint(request.URL.String()) || request.URL.Host != via[0].URL.Host || request.URL.Scheme != via[0].URL.Scheme {
			return fmt.Errorf("untrusted provider redirect")
		}
		return nil
	}
	return &client
}
