docker: build push

build:
	docker build -t sysdig/sysdig-gcscc-connector .

push:
	docker push sysdig/sysdig-gcscc-connector

kubernetes/sysdig-connector-poller/deploy:
	kubectl create configmap sysdig-gcscc-connector \
		--from-literal=org_id=$(ORG_ID) \
		--from-literal=source_id=$(SOURCE_ID)
	\
	kubectl create secret generic sysdig-gcscc-connector \
		--from-literal=sysdig_token=$(SYSDIG_TOKEN) \
		--from-file=security_service_account_info=$(KEY_LOCATION)
	\
	kubectl apply -f kubernetes/sysdig-connector-poller

kubernetes/sysdig-connector-poller/clean:
	kubectl delete -f kubernetes/sysdig-connector-poller
	kubectl delete secret sysdig-gcscc-connector
	kubectl delete configmap sysdig-gcscc-connector
