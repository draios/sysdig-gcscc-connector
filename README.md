# Sysdig integration with Google Security Command Center

Read more on http://sysdig.com/blog/kubernetes-security-for-google-cloud-security-command-center/.

## Before starting

As long as we have a lot of parameters to configure, we included a **settings**
file. Is a shell script sourceable file, which sets up environment variables for
working with this integration.

Once you fill all the variables, you can source it.

```shell
source settings
```

Also, a good trick is to use something like direnv/dotenv or similar.

### Setting up Google Cloud permissons

In order to work with the Google Cloud Security Command Center, you will need to
set up it in your organization. And once its setted up, we need a service account
for synchronizing between Sysdig world and Google world.

This service account must have the **roles/securitycenter.admin** role.

As this can be a bit cumbersome, we added an script which automates this step:

```shell
./scripts/generate_gcloud_keys
```

In order to execute this script, you will need the $ORG_ID and the $PROJECT_ID
environment variables. You can get this values directly form Google Cloud Console.

And finally, this will create a file called **controlcenter-sa.json** in your
filesystem (if you are using the settings provided sourceable file).

### Creating a Security Source on Google Cloud Security Center

Once we have the service account, we can go to this step. In the new version of
Google Cloud Security Control Center, you will need to set up the **Security Source**.

So, another time, just for making your experience better we crafted an script for doing this:

```shell
docker run \
  -e ORG_ID=$ORG_ID \
  -e SECURITY_SERVICE_ACCOUNT_INFO=$SECURITY_SERVICE_ACCOUNT_INFO \
  sysdig/sysdig-gcscc-connector create_security_source [falco | sysdig_secure]
```

You can choose between Falco and Sysdig Secure. Once you executed this script:

```shell

The security source for Sysdig Secure has been successfully created.
Please export its ID before starting to run the integration:

export SOURCE_ID="xxXXXxXX"
```

And then, you can put the SOURCE_ID value into our settings file. And we
are ready to deploy one of the connectors.

## Connectors

There are three diferent flavors of connectors for this integration. Two for
Sysdig Secure and one more for Falco

### Sysdig Secure Polling

The Sysdig Secure Poller is a daemon which queries to Sysdig Secure API every 60
seconds looking for all the security events happened in latest 60 seconds. If
there are new security alerts, transforms its to finding.

Right now is the connector with less latency. It ensures that if an event
happened in latest 60 seconds, it will be created under Security Control Center.

```shell
docker run \
  -e SYSDIG_TOKEN=$SYSDIG_TOKEN \
  -e ORG_ID=$ORG_ID \
  -e SOURCE_ID=$SOURCE_ID \
  -e SECURITY_SERVICE_ACCOUNT_INFO=$SECURITY_SERVICE_ACCOUNT_INFO \
  sysdig/sysdig-gcscc-connector sysdig_secure_polling
```

### Sysdig Secure Webhook

The Sysdig Secure webhook connector is a webhook which well be called when
a new event is created on Sysdig Secure. It is configured in Sysdig Secure as
a *notification channel*

```shell
docker run \
  -e SYSDIG_TOKEN=$SYSDIG_TOKEN \
  sysdig/sysdig-gcscc-connector create_notification_channel WEBHOOK_URL WEBHOOK_AUTHENTICATION_TOKEN
```

And this returns something like:

```shell
The Google Cloud Security Center notification channel has been created on Sysdig Secure
Please export its ID's before starting to run the integration:

export WEBHOOK_URL="WEBHOOK_URL"
export WEBHOOK_AUTHENTICATION_TOKEN="WEBHOOK_AUTHENTICATION_TOKEN"
```

And then, deploy the webhook server:

```shell
docker run \
  -e SYSDIG_TOKEN=$SYSDIG_TOKEN \
  -e ORG_ID=$ORG_ID \
  -e SOURCE_ID=$SOURCE_ID \
  -e SECURITY_SERVICE_ACCOUNT_INFO=$SECURITY_SERVICE_ACCOUNT_INFO \
  -e WEBHOOK_AUTHENTICATION_TOKEN=$WEBHOOK_AUTHENTICATION_TOKEN \
  sysdig/sysdig-gcscc-connector sysdig_secure_webhook
```

### Falco Webhook

In the same way we had a webhook server for Sysdig Secure, we built a webhook
server for Falco. When Falco detects some abnormal behavior and raises an alert
it is sent to this sever.

You can deploy the Falco webhook server using the Docker image:

```shell
docker run \
  -e SYSDIG_TOKEN=$SYSDIG_TOKEN \
  -e ORG_ID=$ORG_ID \
  -e SOURCE_ID=$SOURCE_ID \
  -e SECURITY_SERVICE_ACCOUNT_INFO=$SECURITY_SERVICE_ACCOUNT_INFO \
  -e WEBHOOK_AUTHENTICATION_TOKEN=$WEBHOOK_AUTHENTICATION_TOKEN \
  sysdig/sysdig-gcscc-connector falco_webhook
```

And Falco must be configured with the following values in the /etc/falco/falco.yaml file:

```
json_include_output_property: true

program_output:
  enabled: true
  keep_alive: false
  program: "curl -d @- -X POST --header 'Content-Type: application/json' --header 'Authorization: WEBHOOK_AUTHENTICATION_TOKEN' WEBHOOK_URL"
```

Replace WEBHOOK_AUTHENTICATION_TOKEN and WEBHOOK_URL with your settings and
make sure you are running Falco with the --unbuffered flag. Ensure that
WEBHOOK_URL ends with the **/events** url path, because is the endpoint which
will receive and process the Falco alert.

## Production Deployments

### Google App Engine

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

#### Logs

You can see logs with:

```
gcloud app logs tail -s default
```

### Kubernetes

We have included a file for helping you to deploy connector in your Kubernetes
cluster.

Take a look to deployment.yaml file and adapt ConfigMaps and Secrets to your
needs. Remember that Secrets must be encoded using base64.

Once you have configured with your seetings, you can deploy with the following
command:

```
kubectl create -f deployment.yaml
```

And our server will be listening to alerts in the following URL:

http://sysdig-gcscc-connector.default.svc.cluster.local:8080/events
