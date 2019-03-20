FROM python:3-slim

RUN pip install pipenv

WORKDIR /app

ADD . /app
RUN pipenv install --system --deploy

EXPOSE 8080
ENTRYPOINT ["./docker-entrypoint.sh"]
CMD ["sysdig_secure_webhook"]
