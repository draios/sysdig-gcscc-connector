docker: build push

build:
	docker build -t sysdig/sysdig-gcscc-connector .

push:
	docker push sysdig/sysdig-gcscc-connector
