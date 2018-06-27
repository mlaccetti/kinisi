FROM ubuntu:18.04 as build

RUN apt-get update && apt-get dist-upgrade -y && \
  apt-get install -y build-essential libpcap-dev curl inetutils-ping software-properties-common && \
  add-apt-repository -y ppa:hnakamur/golang-1.10 && \
  apt-get update && \
  apt-get install -y golang-go golang-doc && \
  mkdir -p /root/go/bin && \
  curl https://raw.githubusercontent.com/golang/dep/master/install.sh | sh

WORKDIR /go/src/github.com/mlaccetti/kinisi

ENTRYPOINT ["/bin/bash"]