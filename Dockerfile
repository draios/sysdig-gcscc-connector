FROM python:3-slim

RUN pip install pipenv==2018.11.26

WORKDIR /app

COPY . /app
RUN pipenv install --system --deploy

EXPOSE 8080
ENTRYPOINT ["./docker-entrypoint.sh"]
CMD ["sysdig_secure_webhook"]
