package ncpdns

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/pkg/errors"
)

// DNSClient는 NCP DNS API 클라이언트의 인터페이스입니다.
type DNSClient interface {
	GetDomainID(ctx context.Context, domainName string) (int, error)
	CreateTxtRecord(ctx context.Context, domainID int, name, value string) error
	DeleteTxtRecord(ctx context.Context, domainID int, recordIDs []int) error
	GetTxtRecordID(ctx context.Context, domainID int, name string) (int, error)
	ApplyChallenge(ctx context.Context, domainID int) error
}

// Options contains configuration for NCP DNS Client
type Options struct {
	BaseURL   string
	AccessKey string
	SecretKey string
	Timeout   time.Duration
}

// Client implements DNSClient interface for NCP DNS API
type Client struct {
	httpClient *http.Client
	baseURL    string
	accessKey  string
	secretKey  string
}

// TxtRecord represents a TXT DNS record
type TxtRecord struct {
	Host    string `json:"host"`
	Type    string `json:"type"`
	Content string `json:"content"`
	TTL     int    `json:"ttl"`
}

// DomainResponse represents API response for domain queries
type DomainResponse struct {
	Content       []Domain `json:"content"`
	TotalPages    int      `json:"totalPages"`
	TotalElements int      `json:"totalElements"`
	Last          bool     `json:"last"`
	First         bool     `json:"first"`
	Size          int      `json:"size"`
	Number        int      `json:"number"`
}

// Domain represents a domain in NCP DNS
type Domain struct {
	ID         int    `json:"id"`
	Name       string `json:"name"`
	CompleteYn bool   `json:"completeYn"`
	Status     string `json:"status"`
}

// RecordResponse represents API response for record queries
type RecordResponse struct {
	Content []Record `json:"content"`
}

// Record represents a DNS record in NCP DNS
type Record struct {
	ID int `json:"id"`
}

// NewClient creates a new NCP DNS client
func NewClient(opt Options) DNSClient {
	timeout := opt.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	return &Client{
		httpClient: &http.Client{Timeout: timeout},
		baseURL:    opt.BaseURL,
		accessKey:  opt.AccessKey,
		secretKey:  opt.SecretKey,
	}
}

// GetDomainID retrieves domain ID by domain name
func (c *Client) GetDomainID(ctx context.Context, domainName string) (int, error) {
	// domainName이 있으면 필터링으로 정확한 매칭을 시도
	if domainName != "" {
		if id, err := c.getDomainByFilter(ctx, domainName); err == nil {
			return id, nil
		}
	}

	// 필터링이 실패하거나 domainName이 없으면 전체 검색
	return c.getDomainByPagination(ctx, domainName)
}

// getDomainByFilter tries to get domain using domainName filter
func (c *Client) getDomainByFilter(ctx context.Context, domainName string) (int, error) {
	endpoint := fmt.Sprintf("%s/dns/v1/ncpdns/domain", c.baseURL)
	params := url.Values{
		"page":       []string{"0"},
		"size":       []string{"100"}, // 충분히 큰 값으로 설정
		"domainName": []string{domainName},
	}

	req, err := c.newRequest(ctx, http.MethodGet, endpoint+"?"+params.Encode(), nil)
	if err != nil {
		return 0, errors.Wrap(err, "failed to create request")
	}

	var result DomainResponse
	if err := c.doRequest(req, &result); err != nil {
		return 0, errors.Wrap(err, "failed to get domain")
	}

	// 정확히 매칭되는 도메인 찾기
	for _, domain := range result.Content {
		if domain.Name == domainName {
			return domain.ID, nil
		}
	}

	return 0, errors.New("domain not found")
}

// getDomainByPagination searches through all pages to find the domain
func (c *Client) getDomainByPagination(ctx context.Context, domainName string) (int, error) {
	const pageSize = 50
	page := 0

	for {
		endpoint := fmt.Sprintf("%s/dns/v1/ncpdns/domain", c.baseURL)
		params := url.Values{
			"page": []string{fmt.Sprintf("%d", page)},
			"size": []string{fmt.Sprintf("%d", pageSize)},
		}

		req, err := c.newRequest(ctx, http.MethodGet, endpoint+"?"+params.Encode(), nil)
		if err != nil {
			return 0, errors.Wrap(err, "failed to create request")
		}

		var result DomainResponse
		if err := c.doRequest(req, &result); err != nil {
			return 0, errors.Wrap(err, "failed to get domain")
		}

		// 현재 페이지에서 도메인 찾기
		for _, domain := range result.Content {
			if domain.Name == domainName {
				return domain.ID, nil
			}
		}

		// 마지막 페이지면 종료
		if result.Last || len(result.Content) == 0 {
			break
		}

		page++
	}

	return 0, errors.New("domain not found")
}

// CreateTxtRecord creates a new TXT record
func (c *Client) CreateTxtRecord(ctx context.Context, domainID int, name, value string) error {
	endpoint := fmt.Sprintf("%s/dns/v1/ncpdns/record/%d", c.baseURL, domainID)

	records := []TxtRecord{
		{
			Host:    name,
			Type:    "TXT",
			Content: value,
			TTL:     300,
		},
	}

	req, err := c.newRequest(ctx, http.MethodPost, endpoint, records)
	if err != nil {
		return errors.Wrap(err, "failed to create request")
	}

	if err := c.doRequest(req, nil); err != nil {
		return errors.Wrap(err, "failed to create TXT record")
	}

	return c.ApplyChallenge(ctx, domainID)
}

// DeleteTxtRecord deletes TXT records by IDs
func (c *Client) DeleteTxtRecord(ctx context.Context, domainID int, recordIDs []int) error {
	endpoint := fmt.Sprintf("%s/dns/v1/ncpdns/record/%d", c.baseURL, domainID)

	req, err := c.newRequest(ctx, http.MethodDelete, endpoint, recordIDs)
	if err != nil {
		return errors.Wrap(err, "failed to create request")
	}

	if err := c.doRequest(req, nil); err != nil {
		return errors.Wrap(err, "failed to delete TXT record")
	}

	return c.ApplyChallenge(ctx, domainID)
}

// GetTxtRecordID retrieves TXT record ID by name
func (c *Client) GetTxtRecordID(ctx context.Context, domainID int, name string) (int, error) {
	endpoint := fmt.Sprintf("%s/dns/v1/ncpdns/record/%d", c.baseURL, domainID)
	params := url.Values{
		"page":          []string{"0"},
		"size":          []string{"1"},
		"recordType":    []string{"TXT"},
		"searchContent": []string{name},
	}

	req, err := c.newRequest(ctx, http.MethodGet, endpoint+"?"+params.Encode(), nil)
	if err != nil {
		return 0, errors.Wrap(err, "failed to create request")
	}

	var result RecordResponse
	if err := c.doRequest(req, &result); err != nil {
		return 0, errors.Wrap(err, "failed to get TXT record")
	}

	if len(result.Content) == 0 {
		return 0, errors.New("TXT record not found")
	}

	return result.Content[0].ID, nil
}

// ApplyChallenge applies DNS record changes
func (c *Client) ApplyChallenge(ctx context.Context, domainID int) error {
	endpoint := fmt.Sprintf("%s/dns/v1/ncpdns/record/apply/%d", c.baseURL, domainID)

	req, err := c.newRequest(ctx, http.MethodPut, endpoint, nil)
	if err != nil {
		return errors.Wrap(err, "failed to create request")
	}

	if err := c.doRequest(req, nil); err != nil {
		return errors.Wrap(err, "failed to apply challenge")
	}

	return nil
}

func (c *Client) newRequest(ctx context.Context, method, url string, body interface{}) (*http.Request, error) {
	var bodyBytes []byte
	if body != nil {
		var err error
		bodyBytes, err = json.Marshal(body)
		if err != nil {
			return nil, errors.Wrap(err, "failed to marshal request body")
		}
	}

	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewBuffer(bodyBytes))
	if err != nil {
		return nil, errors.Wrap(err, "failed to create HTTP request")
	}

	timestamp := time.Now().UnixMilli()
	signature := c.makeSignature(method, req.URL.RequestURI(), timestamp)

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-ncp-apigw-timestamp", fmt.Sprintf("%d", timestamp))
	req.Header.Set("x-ncp-iam-access-key", c.accessKey)
	req.Header.Set("x-ncp-apigw-signature-v2", signature)

	return req, nil
}

func (c *Client) doRequest(req *http.Request, result interface{}) error {
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return errors.Wrap(err, "HTTP request failed")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return errors.Errorf("API request failed with status %d: %s", resp.StatusCode, resp.Status)
	}

	if result != nil {
		if err := json.NewDecoder(resp.Body).Decode(result); err != nil {
			return errors.Wrap(err, "failed to decode response")
		}
	}

	return nil
}

func (c *Client) makeSignature(httpMethod, uri string, timestamp int64) string {
	message := fmt.Sprintf("%s %s\n%d\n%s", httpMethod, uri, timestamp, c.accessKey)
	h := hmac.New(sha256.New, []byte(c.secretKey))
	h.Write([]byte(message))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}
