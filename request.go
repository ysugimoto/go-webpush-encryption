package webpush

import (
	"bytes"

	"crypto/tls"
	"net/http"
)

type PushRequest struct {
	url     string
	buffer  []byte
	headers map[string]string
}

func NewPushRequest(url string, buffer []byte) *PushRequest {
	return &PushRequest{
		url:     url,
		buffer:  buffer,
		headers: make(map[string]string),
	}
}

func (p *PushRequest) setHeader(key, value string) {
	p.headers[key] = value
}

func (p *PushRequest) appendHeader(key, value string) {
	if v, ok := p.headers[key]; ok {
		p.headers[key] = v + value
	} else {
		p.headers[key] = value
	}
}

func (p *PushRequest) send() (*http.Response, error) {
	var request *http.Request
	var err error

	if len(p.buffer) > 0 {
		request, err = http.NewRequest("POST", p.url, nil)
	} else {
		request, err = http.NewRequest("POST", p.url, bytes.NewReader(p.buffer))
	}

	if err != nil {
		return nil, err
	}
	for k, v := range p.headers {
		request.Header.Set(k, v)
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}

	return client.Do(request)
}
