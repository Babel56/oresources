# oresources
Openshift/Kubernetes metrics exporter for Prometheus

# Build
```
git clone https://github.com/BrightForest/oresources.git
cd oresources
docker build -t my/oresources:tag .
```
# Environment Variables
```
AUTH_TOKEN string (empty string by default)
CLUSTER_ADDR string ("https://172.30.0.1:443" by default)
```
# How to get AUTH_TOKEN in Openshift
Replace **test** for your actual namespace name:
```
oc create project **test**
oc create sa resources-viewer
oc adm policy add-cluster-role-to-user cluster-admin system:serviceaccount:**test**:resources-viewer
oc describe sa resources-viewer
```
Here you get Tokens names info, so you need copy first token name end use it later:
```
oc describe secret **copied_token_name**
```
Token value == AUTH_TOKEN

# Metrics paths and Prometheus targets
```
app:8080/cpu - page with CPU information (nanocores)
app:8080/mem - page with memory usage information (bytes)
app:8080/storage - page with pods PVC storages information (bytes)
```
Prometheus Targets example:
```
- job_name: 'cpu-metrics'
  scrape_interval: 30s
  scheme: http
  metrics_path: /cpu
  static_configs:
  - targets: ['app-route:8080']

- job_name: 'memory-metrics'
  scrape_interval: 30s
  scheme: http
  metrics_path: /mem
  static_configs:
  - targets: ['app-route:8080']

- job_name: 'storage-metrics'
  scrape_interval: 30s
  scheme: http
  metrics_path: /storage
  static_configs:
  - targets: ['app-route:8080']
```
