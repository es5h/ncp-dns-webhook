package main

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"strings"
	"time"

	"github.com/cert-manager/cert-manager/pkg/issuer/acme/dns/util"
	"github.com/pkg/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"github.com/cert-manager/cert-manager/pkg/acme/webhook/cmd"
	cmmetav1 "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/es5h/ncp-dns-webhook/ncpdns"
	extapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
)

const (
	defaultTimeout = 30 * time.Second
	solverName     = "ncp-dns-solver"
)

var groupName = os.Getenv("GROUP_NAME")

func main() {
	if groupName == "" {
		log.Fatal("GROUP_NAME environment variable must be specified")
	}

	solver := &NCPDNSProviderSolver{}
	cmd.RunWebhookServer(groupName, solver)
}

// NCPDNSProviderSolver implements the cert-manager webhook solver interface
type NCPDNSProviderSolver struct {
	kubeClient kubernetes.Interface
}

// Config represents the configuration for NCP DNS provider
type Config struct {
	AccessTokenRef cmmetav1.SecretKeySelector `json:"accessTokenSecretRef"`
	SecretKeyRef   cmmetav1.SecretKeySelector `json:"secretKeySecretRef"`
	BaseURL        string                     `json:"baseUrl"`
	Timeout        *metav1.Duration           `json:"timeout,omitempty"`
}

// Name returns the solver name
func (s *NCPDNSProviderSolver) Name() string {
	return solverName
}

// Present creates a TXT record for ACME challenge
func (s *NCPDNSProviderSolver) Present(ch *v1alpha1.ChallengeRequest) error {
	ctx := context.Background()

	cfg, err := s.loadConfig(ch.Config)
	if err != nil {
		return errors.Wrap(err, "failed to load configuration")
	}

	client, err := s.createDNSClient(ctx, cfg, ch.ResourceNamespace)
	if err != nil {
		return errors.Wrap(err, "failed to create DNS client")
	}

	cleanZone := strings.TrimSuffix(ch.ResolvedZone, ".")

	log.Printf("Getting domain ID for zone: %s", cleanZone)
	domainID, err := client.GetDomainID(ctx, cleanZone)
	if err != nil {
		return errors.Wrapf(err, "failed to get domain ID for zone %s", cleanZone)
	}

	recordName := s.extractRecordName(ch.ResolvedFQDN, cleanZone)
	log.Printf("Creating TXT record: %s with value: %s", recordName, ch.Key)

	if err := client.CreateTxtRecord(ctx, domainID, recordName, ch.Key); err != nil {
		return errors.Wrapf(err, "failed to create TXT record %s", recordName)
	}

	log.Printf("Successfully created TXT record for domain ID %d", domainID)
	return nil
}

// CleanUp removes the TXT record for ACME challenge
func (s *NCPDNSProviderSolver) CleanUp(ch *v1alpha1.ChallengeRequest) error {
	ctx := context.Background()

	cfg, err := s.loadConfig(ch.Config)
	if err != nil {
		return errors.Wrap(err, "failed to load configuration")
	}

	client, err := s.createDNSClient(ctx, cfg, ch.ResourceNamespace)
	if err != nil {
		return errors.Wrap(err, "failed to create DNS client")
	}

	cleanZone := strings.TrimSuffix(ch.ResolvedZone, ".")

	domainID, err := client.GetDomainID(ctx, cleanZone)
	if err != nil {
		return errors.Wrapf(err, "failed to get domain ID for zone %s", cleanZone)
	}

	recordName := s.extractRecordName(ch.ResolvedFQDN, cleanZone)
	recordID, err := client.GetTxtRecordID(ctx, domainID, recordName)
	if err != nil {
		return errors.Wrapf(err, "failed to get TXT record ID for %s", recordName)
	}

	log.Printf("Deleting TXT record: %s (ID: %d)", recordName, recordID)
	if err := client.DeleteTxtRecord(ctx, domainID, []int{recordID}); err != nil {
		return errors.Wrapf(err, "failed to delete TXT record %s", recordName)
	}

	log.Printf("Successfully deleted TXT record for domain ID %d", domainID)
	return nil
}

// Initialize sets up the Kubernetes client
func (s *NCPDNSProviderSolver) Initialize(kubeClientConfig *rest.Config, _ <-chan struct{}) error {
	client, err := kubernetes.NewForConfig(kubeClientConfig)
	if err != nil {
		return errors.Wrap(err, "failed to create Kubernetes client")
	}

	s.kubeClient = client
	return nil
}

func (s *NCPDNSProviderSolver) loadConfig(cfgJSON *extapi.JSON) (*Config, error) {
	cfg := &Config{}
	if cfgJSON == nil {
		return cfg, nil
	}

	if err := json.Unmarshal(cfgJSON.Raw, cfg); err != nil {
		return nil, errors.Wrap(err, "failed to decode solver configuration")
	}

	// Validate required fields
	if cfg.BaseURL == "" {
		return nil, errors.New("baseUrl is required in configuration")
	}

	return cfg, nil
}

func (s *NCPDNSProviderSolver) createDNSClient(ctx context.Context, cfg *Config, namespace string) (ncpdns.DNSClient, error) {
	accessToken, err := s.loadSecretData(ctx, cfg.AccessTokenRef, namespace)
	if err != nil {
		return nil, errors.Wrap(err, "failed to load access token from secret")
	}

	secretKey, err := s.loadSecretData(ctx, cfg.SecretKeyRef, namespace)
	if err != nil {
		return nil, errors.Wrap(err, "failed to load secret key from secret")
	}

	timeout := defaultTimeout
	if cfg.Timeout != nil {
		timeout = cfg.Timeout.Duration
	}

	opts := ncpdns.Options{
		BaseURL:   cfg.BaseURL,
		AccessKey: string(accessToken),
		SecretKey: string(secretKey),
		Timeout:   timeout,
	}

	return ncpdns.NewClient(opts), nil
}

func (s *NCPDNSProviderSolver) extractRecordName(fqdn, domain string) string {
	name := util.UnFqdn(fqdn)
	if idx := strings.Index(name, "."+domain); idx != -1 {
		return name[:idx]
	}
	return name
}

func (s *NCPDNSProviderSolver) loadSecretData(ctx context.Context, selector cmmetav1.SecretKeySelector, namespace string) ([]byte, error) {
	secret, err := s.kubeClient.CoreV1().Secrets(namespace).Get(ctx, selector.Name, metav1.GetOptions{})
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get secret %s/%s", namespace, selector.Name)
	}

	data, exists := secret.Data[selector.Key]
	if !exists {
		return nil, errors.Errorf("key %q not found in secret %s/%s", selector.Key, namespace, selector.Name)
	}

	if len(data) == 0 {
		return nil, errors.Errorf("key %q in secret %s/%s is empty", selector.Key, namespace, selector.Name)
	}

	return data, nil
}
