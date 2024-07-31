FROM python:3.10-alpine

ENV BUILD_DEPS=""
ENV RUNTIME_DEPS="tzdata"

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

RUN mkdir -p /burp-probe

WORKDIR /burp-probe
COPY . /burp-probe

RUN apk update &&\
    apk add --no-cache $BUILD_DEPS $RUNTIME_DEPS &&\
    pip install --no-cache-dir --upgrade pip &&\
    pip install --no-cache-dir -r requirements.txt &&\
    apk del $BUILD_DEPS &&\
    rm -rf /var/cache/apk/*

ENV TZ America/New_York

RUN chmod +x entrypoint.sh
CMD ./entrypoint.sh
