# Running on Kubernetes

UAA is published as a Docker image and can be run on Kubernetes using that image. The official image is built and pushed by [Docker Image CI](../.github/workflows/docker-image.yml) on UAA releases.

**Image:** `docker.io/cfidentity/uaa`  
**Tags:** For release builds use a version tag (e.g. `v78.9.0`). See the [workflow](../.github/workflows/docker-image.yml) for the exact tagging rules.

## Configuration

The container expects configuration to be provided via:

- **`CLOUDFOUNDRY_CONFIG_PATH`** — Directory containing `uaa.yml` (and optionally `login.yml`). UAA loads its main config from `$CLOUDFOUNDRY_CONFIG_PATH/uaa.yml`.
- **`SECRETS_DIR`** — Directory containing secret files (e.g. JWT signing keys, DB credentials) referenced by the config.

Set the servlet context path to `/uaa` (e.g. `-Dserver.servlet.context-path=/uaa` or `SERVER_SERVLET_CONTEXT_PATH=/uaa`).

## Example: Docker run

With config and secrets in local directories:

```bash
docker run -p 8080:8080 \
  -e CLOUDFOUNDRY_CONFIG_PATH=/config \
  -e SECRETS_DIR=/secrets \
  -e SERVER_SERVLET_CONTEXT_PATH=/uaa \
  -v /path/to/your/uaa-config:/config:ro \
  -v /path/to/your/secrets:/secrets:ro \
  docker.io/cfidentity/uaa:v78.9.0
```

## Example: Kubernetes Deployment

Mount config and secrets from a ConfigMap and a Secret:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: uaa
spec:
  replicas: 1
  selector:
    matchLabels:
      app: uaa
  template:
    metadata:
      labels:
        app: uaa
    spec:
      containers:
        - name: uaa
          image: docker.io/cfidentity/uaa:v78.9.0
          ports:
            - containerPort: 8080
          env:
            - name: CLOUDFOUNDRY_CONFIG_PATH
              value: "/config"
            - name: SECRETS_DIR
              value: "/secrets"
            - name: SERVER_SERVLET_CONTEXT_PATH
              value: "/uaa"
          volumeMounts:
            - name: uaa-config
              mountPath: /config
              readOnly: true
            - name: uaa-secrets
              mountPath: /secrets
              readOnly: true
          livenessProbe:
            httpGet:
              path: /uaa/healthz
              port: 8080
            initialDelaySeconds: 60
            periodSeconds: 15
            failureThreshold: 5
          readinessProbe:
            httpGet:
              path: /uaa/healthz
              port: 8080
            initialDelaySeconds: 30
            periodSeconds: 10
            failureThreshold: 3
      volumes:
        - name: uaa-config
          configMap:
            name: uaa-config
        - name: uaa-secrets
          secret:
            secretName: uaa-secrets
```

Create the ConfigMap from your `uaa.yml` (and optionally `login.yml`), and the Secret from your signing keys, database credentials, and other secrets.

### Service

Expose the Deployment with a ClusterIP Service so other workloads or an Ingress can reach UAA:

```yaml
apiVersion: v1
kind: Service
metadata:
  name: uaa
  labels:
    app: uaa
spec:
  type: ClusterIP
  ports:
    - port: 8080
      targetPort: 8080
      name: http
      protocol: TCP
  selector:
    app: uaa
```

### Ingress

Because the app uses context path `/uaa`, route traffic to the Service with a path prefix of `/uaa`. Example using `networking.k8s.io/v1` Ingress:

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: uaa-ingress
spec:
  ingressClassName: nginx   # or your controller's class
  rules:
    - host: uaa.example.com
      http:
        paths:
          - path: /uaa
            pathType: Prefix
            backend:
              service:
                name: uaa
                port:
                  number: 8080
```

If UAA is the only app on the host, you can use `path: /` and ensure `uaa.yml` (or your reverse proxy) is configured so that the issuer and redirect URIs use the correct base URL including `/uaa`. Otherwise, using `path: /uaa` keeps all UAA endpoints under `/uaa` (e.g. `https://uaa.example.com/uaa/login`).

Adjust `host`, `ingressClassName`, and TLS according to your cluster and DNS.
