# NCP DNS Webhook for cert-manager

네이버 클라우드 플랫폼(NCP) DNS API를 cert-manager와 연동하여 DNS-01 challenge를 통한 Let's Encrypt SSL 인증서 자동 발급을 지원하는 Kubernetes webhook입니다.

## 사전 요구사항
- 네이버 클라우드 플랫폼 계정 및 DNS 서비스 이용
- NCP API Access Key 및 Secret Key (DNS API 권한이 있는 계정)
## 설치

Certmanager Namespace가 `cert-manager`라고 가정합니다. 다른 네임스페이스를 사용하려면 아래 명령어에서 `-n cert-manager` 부분을 변경하세요.

### 1. NCP API 자격증명 Secret 생성

```bash
kubectl create secret generic ncp-dns-api-secret \
  --from-literal=access-Key=YOUR_NCP_ACCESS_KEY \
  --from-literal=secret-Key=YOUR_NCP_SECRET_KEY \
  -n cert-manager
```

### 3. Helm으로 ncp-dns-webhook 설치

```bash
helm install ncp-dns-webhook oci://ghcr.io/es5h/charts/ncp-dns-webhook \
  --version 0.2.0 \
  --namespace cert-manager \
  --set secretName=ncp-dns-api-secret \
  --set groupName=acme.yourdomain.com
```

### 4. ClusterIssuer 생성

```yaml
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: letsencrypt-ncp-issuer
spec:
  acme:
    server: https://acme-v02.api.letsencrypt.org/directory
    email: your-email@example.com
    privateKeySecretRef:
      name: letsencrypt-ncp-issuer-key
    solvers:
    - dns01:
        webhook:
          groupName: acme.yourdomain.com
          solverName: ncp-dns
          config:
            ncpAccessKeySecretRef:
              name: ncp-dns-api-secret
              key: access-Key
            ncpSecretKeySecretRef:
              name: ncp-dns-api-secret    
              key: secret-Key
            #공공 DNS를 사용하는 경우
            #baseUrl: https://globaldns.apigw.gov-ntruss.com
            baseUrl: https://globaldns.apigw.ntruss.com
```

위 YAML을 `clusterissuer.yaml`로 저장하고 적용:

```bash
kubectl apply -f clusterissuer.yaml
```

## 사용법

### Ingress에서 자동 SSL 인증서 발급 (권장)

cert-manager는 Ingress 리소스의 TLS 설정을 보고 자동으로 Certificate를 생성하고 관리합니다.

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: example-ingress
  namespace: default
  annotations:
    cert-manager.io/cluster-issuer: "letsencrypt-ncp-issuer"
spec:
  tls:
  - hosts:
    - example.com
    - www.example.com
    secretName: example-com-tls  # cert-manager가 자동으로 이 Secret을 생성합니다
  rules:
  - host: example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: example-service
            port:
              number: 80
  - host: www.example.com  
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: example-service
            port:
              number: 80
```

## 참고
- GitHub Issues: 버그 리포트 및 기능 요청
- Documentation: [cert-manager DNS01 challenge](https://cert-manager.io/docs/configuration/acme/dns01/)
- NCP DNS API: [네이버 클라우드 플랫폼 DNS API 문서](https://ncloud.apigw.ntruss.com/ncloud/docs/dns)
