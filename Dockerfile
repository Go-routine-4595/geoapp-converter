FROM ubuntu:latest
LABEL authors="christophe2bu"

WORKDIR /geoapp-utils
EXPOSE 8883
EXPOSE 1883
COPY geoapp-converter-linux-arm64 ./geoapp-converter-linux
COPY config.yaml ./
CMD ["/geoapp-utils/geoapp-converter-linux"]