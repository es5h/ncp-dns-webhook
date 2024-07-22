package main

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/cert-manager/cert-manager/pkg/issuer/acme/dns/util"
	"log"
	"os"
	"strings"

	"github.com/pkg/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"github.com/cert-manager/cert-manager/pkg/acme/webhook/cmd"
	cmmetav1 "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/es5h/ncp-dns-webhook/ncpdns"
	extapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
)

var GroupName = os.Getenv("GROUP_NAME")

func main() {
	if GroupName == "" {
		panic("GROUP_NAME must be specified")
	}

	cmd.RunWebhookServer(GroupName,
		&ncpDNSProviderSolver{},
	)
}

type ncpDNSProviderSolver struct {
	client       *kubernetes.Clientset
	ncpDNSClient *ncpdns.NcpDnsClient
}

type ncpDNSProviderConfig struct {
	AccessToken cmmetav1.SecretKeySelector `json:"accessTokenSecretRef"`
	SecretToken cmmetav1.SecretKeySelector `json:"secretKeySecretRef"`
	BaseURL     string                     `json:"baseUrl"`
}

func (c *ncpDNSProviderSolver) Name() string {
	return "ncp-dns-solver"
}

func (c *ncpDNSProviderSolver) Present(ch *v1alpha1.ChallengeRequest) error {
	cfg, err := loadConfig(ch.Config)
	if err != nil {
		return err
	}

	accessToken, err := c.loadSecretData(cfg.AccessToken, ch.ResourceNamespace)
	if err != nil {
		return err
	}
	secretKey, err := c.loadSecretData(cfg.SecretToken, ch.ResourceNamespace)
	if err != nil {
		return err
	}

	client := ncpdns.NewNcpDnsClient(ncpdns.NcpDnsOptions{
		BaseUrl:   cfg.BaseURL,
		AccessKey: string(accessToken),
		SecretKey: string(secretKey),
	})
	c.ncpDNSClient = client

	log.Printf("Attempting to get domain ID for zone: %s", ch.ResolvedZone)

	// Remove trailing dot from resolved zone
	cleanResolvedZone := strings.TrimSuffix(ch.ResolvedZone, ".")
	domainID, err := c.ncpDNSClient.GetDomainId(cleanResolvedZone)

	if err != nil {
		return fmt.Errorf("ncpdns: error getting domain ID: %v", err)
	}

	log.Printf("Domain ID for zone %s is %d", ch.ResolvedZone, domainID)
	err = c.ncpDNSClient.CreateTxtRecord(domainID, c.extractRecordName(ch.ResolvedFQDN, cleanResolvedZone), ch.Key)
	if err != nil {
		return fmt.Errorf("ncpdns: error creating TXT record: %v", err)
	}
	return nil
}

func (c *ncpDNSProviderSolver) CleanUp(ch *v1alpha1.ChallengeRequest) error {
	cfg, err := loadConfig(ch.Config)
	if err != nil {
		return err
	}

	accessToken, err := c.loadSecretData(cfg.AccessToken, ch.ResourceNamespace)
	if err != nil {
		return err
	}
	secretKey, err := c.loadSecretData(cfg.SecretToken, ch.ResourceNamespace)
	if err != nil {
		return err
	}

	client := ncpdns.NewNcpDnsClient(ncpdns.NcpDnsOptions{
		BaseUrl:   cfg.BaseURL,
		AccessKey: string(accessToken),
		SecretKey: string(secretKey),
	})
	c.ncpDNSClient = client

	// Remove trailing dot from resolved zone
	cleanResolvedZone := strings.TrimSuffix(ch.ResolvedZone, ".")
	domainID, err := c.ncpDNSClient.GetDomainId(cleanResolvedZone)
	if err != nil {
		return fmt.Errorf("ncpdns: error getting domain ID: %v", err)
	}

	recordID, err := c.ncpDNSClient.GetTxtRecordId(domainID, c.extractRecordName(ch.ResolvedFQDN, cleanResolvedZone))
	if err != nil {
		return fmt.Errorf("ncpdns: error getting TXT record ID: %v", err)
	}

	err = c.ncpDNSClient.DeleteTxtRecord(domainID, []int{recordID})
	if err != nil {
		return fmt.Errorf("ncpdns: error deleting TXT record: %v", err)
	}
	return nil
}

func (c *ncpDNSProviderSolver) Initialize(kubeClientConfig *rest.Config, stopCh <-chan struct{}) error {
	cl, err := kubernetes.NewForConfig(kubeClientConfig)
	if err != nil {
		return err
	}

	c.client = cl

	return nil
}

func loadConfig(cfgJSON *extapi.JSON) (ncpDNSProviderConfig, error) {
	cfg := ncpDNSProviderConfig{}
	if cfgJSON == nil {
		return cfg, nil
	}
	if err := json.Unmarshal(cfgJSON.Raw, &cfg); err != nil {
		return cfg, fmt.Errorf("error decoding solver config: %v", err)
	}

	return cfg, nil
}

func (c *ncpDNSProviderSolver) extractRecordName(fqdn, domain string) string {
	name := util.UnFqdn(fqdn)
	if idx := strings.Index(name, "."+domain); idx != -1 {
		return name[:idx]
	}
	return name
}

func (c *ncpDNSProviderSolver) loadSecretData(selector cmmetav1.SecretKeySelector, ns string) ([]byte, error) {
	secret, err := c.client.CoreV1().Secrets(ns).Get(context.TODO(), selector.Name, v1.GetOptions{})
	if err != nil {
		return nil, errors.Wrapf(err, "failed to load secret %q", ns+"/"+selector.Name)
	}

	if data, ok := secret.Data[selector.Key]; ok {
		return data, nil
	}

	return nil, errors.Errorf("no key %q in secret %q", selector.Key, ns+"/"+selector.Name)
}
