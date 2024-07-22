package ncpdns

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

type NcpDnsOptions struct {
	BaseUrl   string
	AccessKey string
	SecretKey string
}

type NcpDnsClient struct {
	client    *http.Client
	baseUrl   string
	accessKey string
	secretKey string
}

func NewNcpDnsClient(options NcpDnsOptions) *NcpDnsClient {
	return &NcpDnsClient{
		client:    &http.Client{},
		baseUrl:   options.BaseUrl,
		accessKey: options.AccessKey,
		secretKey: options.SecretKey,
	}
}

func (c *NcpDnsClient) GetDomainId(domainName string) (int, error) {

	url := fmt.Sprintf("%s/dns/v1/ncpdns/domain?page=0&size=20&domainName=%s", c.baseUrl, domainName)

	// log.Printf("request url: %s", url)
	req, err := c.createRequest("GET", url, nil)
	if err != nil {
		return 0, err
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	// log.Printf("resp.StatusCode: %d", resp.StatusCode)

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("failed to get domain id: %s", resp.Status)
	}

	var result struct {
		Content []struct {
			Id int `json:"id"`
		} `json:"content"`
	}
	err = json.NewDecoder(resp.Body).Decode(&result)
	if err != nil {
		return 0, err
	}

	// log.Printf("result: %v", result)

	if len(result.Content) == 0 {
		return 0, fmt.Errorf("no domain found")
	}

	return result.Content[0].Id, nil
}

func (c *NcpDnsClient) CreateTxtRecord(domainId int, name, value string) error {
	url := fmt.Sprintf("%s/dns/v1/ncpdns/record/%d", c.baseUrl, domainId)
	record := []map[string]interface{}{
		{
			"host":    name,
			"type":    "TXT",
			"content": value,
			"ttl":     300,
		},
	}
	req, err := c.createRequest("POST", url, record)
	if err != nil {
		return err
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to create TXT record: %s", resp.Status)
	}

	return c.ApplyChallenge(domainId)
}

func (c *NcpDnsClient) DeleteTxtRecord(domainId int, recordIds []int) error {
	url := fmt.Sprintf("%s/dns/v1/ncpdns/record/%d", c.baseUrl, domainId)
	req, err := c.createRequest("DELETE", url, recordIds)
	if err != nil {
		return err
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to delete TXT record: %s", resp.Status)
	}

	return c.ApplyChallenge(domainId)
}

func (c *NcpDnsClient) GetTxtRecordId(domainId int, name string) (int, error) {
	url := fmt.Sprintf("%s/dns/v1/ncpdns/record/%d?page=0&size=1&recordType=TXT&searchContent=%s", c.baseUrl, domainId, name)
	req, err := c.createRequest("GET", url, nil)
	if err != nil {
		return 0, err
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("failed to get TXT record id: %s", resp.Status)
	}

	var result struct {
		Content []struct {
			Id int `json:"id"`
		} `json:"content"`
	}
	err = json.NewDecoder(resp.Body).Decode(&result)
	if err != nil {
		return 0, err
	}

	if len(result.Content) == 0 {
		return 0, fmt.Errorf("no TXT record found")
	}

	return result.Content[0].Id, nil
}

func (c *NcpDnsClient) ApplyChallenge(domainId int) error {
	url := fmt.Sprintf("%s/dns/v1/ncpdns/record/apply/%d", c.baseUrl, domainId)
	req, err := c.createRequest("PUT", url, nil)
	if err != nil {
		return err
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to apply challenge: %s", resp.Status)
	}

	return nil
}

func (c *NcpDnsClient) createRequest(method, url string, body interface{}) (*http.Request, error) {
	var bodyBytes []byte
	var err error

	if body != nil {
		bodyBytes, err = json.Marshal(body)
		if err != nil {
			return nil, err
		}
	}

	req, err := http.NewRequest(method, url, bytes.NewBuffer(bodyBytes))
	if err != nil {
		return nil, err
	}

	timestamp := time.Now().UnixMilli()
	signature := c.makeSignature(method, req.URL.RequestURI(), timestamp)

	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("x-ncp-apigw-timestamp", fmt.Sprintf("%d", timestamp))
	req.Header.Add("x-ncp-iam-access-key", c.accessKey)
	req.Header.Add("x-ncp-apigw-signature-v2", signature)

	return req, nil
}

func (c *NcpDnsClient) makeSignature(httpMethod, uri string, timestamp int64) string {
	message := fmt.Sprintf("%s %s\n%d\n%s", httpMethod, uri, timestamp, c.accessKey)
	h := hmac.New(sha256.New, []byte(c.secretKey))
	h.Write([]byte(message))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}
