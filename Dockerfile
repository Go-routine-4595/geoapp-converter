FROM ubuntu:latest
LABEL authors="christophe2bu"

WORKDIR /geoapp-utils
EXPOSE 8883
EXPOSE 1883
COPY geoapp-converter-linux ./geoapp-converter
COPY config.yaml ./
CMD ["/geoapp-utils/geoapp-converter"]