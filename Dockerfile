FROM python:3-stretch

RUN pip install pipenv

WORKDIR /app

ADD vendor /app/vendor
ADD Pipfile /app/Pipfile
ADD Pipfile.lock /app/Pipfile.lock
RUN pipenv install --system --deploy

ADD . /app

EXPOSE 8080
CMD ["gunicorn", "-b", "0.0.0.0:8080", "server:app"]
