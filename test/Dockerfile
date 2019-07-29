FROM alpine:edge

RUN apk add --no-cache wpa_supplicant freeradius freeradius-eap &&\
    apk add --no-cache -X http://dl-cdn.alpinelinux.org/alpine/edge/testing cfssl
ADD * /test/
WORKDIR /test