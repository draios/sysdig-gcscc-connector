# Sysdig integration with Google Security Command Center

Read more on http://sysdig.com/blog/kubernetes-security-for-google-cloud-security-command-center/.

## Configuration

Configuration is done using environment variables.

Check the following list for environment variables used:

* SYSDIG_TOKEN: Sysdig access token
* ORG_ID: Organization ID
* PROJECT_ID: New findings are created under this project
* SECURITY_SERVICE_ACCOUNT_INFO: Raw credentials for accessing to security command center
* COMPUTE_PROJECT_ID: Kubernetes cluster instances are expected in this project
* COMPUTE_ZONE: Kubernetes cluster instances are expected in this compute zone
* COMPUTE_SERVICE_ACCOUNT_INFO: Raw credentials for accessing to compute API

## Console runner

Console runner is a long time process which queries policy events in Sysdig Secure
every minute and creates new findings in Security Command Center.

## Webhook runner

The webhook runner is a Flask application which receives an HTTP POST request
when a new event is created. This webhook should be configured in Sysdig Secure
notification settings.

## Docker support

We have deployed this integration in Google App Engine, using Docker support in flex plan.

### Build image

```
docker build -t sysdig/sysdig-cscc .
```

### Running WebHook

```
docker run -p 8080:8080 sysdig/sysdig-cscc
```

### Console

```
docker run sysdig/sysdig-cscc python main.py
```

## Google App Engine Deployment

Configure gcloud client with:

```
gcloud init
```

Create project:

```
gcloud app create
```

And deploy!

```
gcloud app deploy
```

### Logs

You can see logs with:

```
gcloud app logs tail -s default
```
