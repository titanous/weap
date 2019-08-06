FROM golang:buster AS go-builder
ADD . /weap/
RUN cd /weap && GOPROXY=https://proxy.golang.org go build -race ./cmd/weapd

FROM alpine:edge AS hostap-builder
ADD test/build_eapol_test.sh /build/
RUN cd /build && ./build_eapol_test.sh

FROM alpine:edge
RUN apk add --no-cache freeradius freeradius-eap wget &&\
    apk add --no-cache -X http://dl-cdn.alpinelinux.org/alpine/edge/testing cfssl &&\
    wget -q -O /etc/apk/keys/sgerrand.rsa.pub https://alpine-pkgs.sgerrand.com/sgerrand.rsa.pub &&\
    wget https://github.com/sgerrand/alpine-pkg-glibc/releases/download/2.29-r0/glibc-2.29-r0.apk &&\
    apk add glibc-2.29-r0.apk && rm glibc-2.29-r0.apk
COPY --from=go-builder /weap/weapd /test/
COPY --from=hostap-builder /build/hostap/wpa_supplicant/eapol_test /usr/local/bin/
ADD test /test
WORKDIR /test
ENTRYPOINT [ "/test/test.sh" ]