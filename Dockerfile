FROM ubuntu:18.04 as build

ENV GOPATH="/go"
ENV PATH="${PATH}:${GOPATH}/bin"

WORKDIR /go/src/github.com/mlaccetti/kinisi

RUN apt-get update && apt-get dist-upgrade -y
RUN apt-get install -y build-essential libpcap-dev curl inetutils-ping software-properties-common vim-gocomplete
RUN add-apt-repository -y ppa:hnakamur/golang-1.10
RUN apt-get update
RUN apt-get install -y golang-go golang-doc
RUN mkdir -p /go/bin && \
  curl https://raw.githubusercontent.com/golang/dep/master/install.sh | sh

ENTRYPOINT ["/bin/bash"]
