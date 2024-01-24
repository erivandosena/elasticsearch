# Dockerfile for Elasticsearch
#
# Maintainer: Erivando Sena <erivandosena@gmail.com>
# Author: elastic/elasticsearch
#
# Description: This multi stage Dockerfile was generated from the template at https://github.com/distribution/distribution/blob/main/Dockerfile
#
# Build instructions:
#   docker build -f ./Dockerfile -t erivando/elasticsearch:8.8.2 --build-arg VERSION=3.0.2 --build-arg COMMIT_SHA=$(git rev-parse --short HEAD) --no-cache .
#   docker push erivando/elasticsearch:8.8.2
#
# Usage:
#
#   docker run -it --rm -d -p 8092:9200 --name elasticsearch erivando/elasticsearch:8.8.2
#   docker logs -f --tail --until=2s elasticsearch
#   docker exec -it elasticsearch bash
#   docker inspect --format='{{json .Config.Labels}}' erivando/elasticsearch:8.8.2 | jq .
#   docker exec -it elasticsearch bin/elasticsearch-setup-passwords interactive
#
# Dependencies: debian:stable
#
# Environment variables:
#
#   COMMIT_SHA: o hash SHA-1 de um determinado commit do Git.
#   VERSION: usado na tag de imagem ou como parte dos metadados da mesma.
#
# Notes:
#
# - Este Dockerfile assume que o código do aplicativo está localizado no diretório atual ou (./source)
# - O aplicativo pode ser acessado em um navegador da Web em https://<elasticsearch>.unilab.edu.br/
#
# Version: 1.0
# syntax=docker/dockerfile:1

################################################################################
# Build stage 0 `builder`:
# Extract Elasticsearch artifact
################################################################################

FROM debian:stable AS builder

# `tini` é um init minúsculo, mas válido para contêineres. Ele é usado para limpar
# control como o ES e quaisquer processos filhos quando desligados.
#
# A página tini GitHub fornece instruções para verificar o binário usando
# gpg, mas os servidores de chaves são lentos para retornar a chave e isso pode falhar no
# build. Em vez disso, verificamos o binário em relação à soma de checksum publicada.

RUN set -eux ; \
    apt-get update ; \
    apt-get install -y curl ; \
    tini_bin="" ; \
    case "$(dpkg --print-architecture)" in \
        arm64) tini_bin='tini-arm64' ;; \
        amd64) tini_bin='tini-amd64' ;; \
        *) echo >&2 ; echo >&2 "Unsupported architecture $(dpkg --print-architecture)" ; echo >&2 ; exit 1 ;; \
    esac ; \
    curl --retry 10 -S -L -O https://github.com/krallin/tini/releases/download/v0.19.0/${tini_bin} ; \
    curl --retry 10 -S -L -O https://github.com/krallin/tini/releases/download/v0.19.0/${tini_bin}.sha256sum ; \
    sha256sum -c ${tini_bin}.sha256sum ; \
    rm ${tini_bin}.sha256sum ; \
    mv ${tini_bin} /bin/tini ; \
    chmod +x /bin/tini

RUN mkdir /usr/share/elasticsearch

WORKDIR /usr/share/elasticsearch

# Opcional
# COPY elasticsearch-8.8.2-linux-x86_64.tar.gz /opt/elasticsearch.tar.gz
RUN curl --retry 10 -S -L --output /opt/elasticsearch.tar.gz https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-8.8.2-linux-x86_64.tar.gz
RUN tar zxf /opt/elasticsearch.tar.gz --strip-components=1
RUN grep ES_DISTRIBUTION_TYPE=tar /usr/share/elasticsearch/bin/elasticsearch-env \
    && sed -ie 's/ES_DISTRIBUTION_TYPE=tar/ES_DISTRIBUTION_TYPE=docker/' /usr/share/elasticsearch/bin/elasticsearch-env \
    && find ./jdk -type d -exec chmod 0755 {} + \
    && rm /opt/elasticsearch.tar.gz
RUN mkdir -p config data logs
RUN chmod 0775 config data logs

################################################################################
# Build stage 1 (the actual Elasticsearch image):
#
# Copy elasticsearch from stage 0
# Add entrypoint
################################################################################

FROM debian:stable

RUN set -eux ; \
    apt-get update ; \
    apt-get install -y \
      procps netcat-openbsd zip unzip ca-certificates ; \
    apt-get clean ; \
    exit_code=0 ; \
    for iter in $(seq 1 10); do \
      apt-get update ; \
      apt-get install -y \
        procps netcat-openbsd zip unzip ca-certificates && \
      apt-get clean && \
      exit_code=0 && \
      break || \
      exit_code=$? && \
      echo "apt-get error: retry $iter in 10s" && \
      sleep 10 ; \
    done ; \
    exit $exit_code

ENV ES_PATH_CONF /etc/elasticsearch
ARG COMMIT_SHA
ARG VERSION

COPY config/sysctl-local.conf /etc/sysctl.d/local.conf
COPY config/java.policy /tmp/java.policy
COPY config/role_mapping.yml $ES_PATH_CONF/role_mapping.yml
COPY config/log4j2.properties $ES_PATH_CONF/log4j2.properties
COPY config/elasticsearch.yml config/jvm.options $ES_PATH_CONF/
COPY bin/file-based-users $ES_PATH_CONF/users
COPY bin/file-based-users-roles $ES_PATH_CONF/users_roles
COPY bin/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
COPY bin/docker-openjdk /etc/ca-certificates/update.d/docker-openjdk

RUN groupadd -g 1000 elasticsearch && \
    useradd -u 1000 -g 1000 -G 0 -d /usr/share/elasticsearch -s /bin/bash elasticsearch && \
    mkdir -p /usr/share/elasticsearch/cluster/data && \
    mkdir -p /usr/share/elasticsearch/cluster/logs && \
    mkdir -p /usr/share/elasticsearch/cluster/snapshot && \
    chmod 0775 /usr/share/elasticsearch && \
    chown -R 1000:0 /usr/share/elasticsearch && \
    chmod 0775 $ES_PATH_CONF && \
    chown -R 1000:0 $ES_PATH_CONF

ENV ELASTIC_CONTAINER true
ENV ELASTICSEARCH_ALLOW_UNSIGNED true

WORKDIR /usr/share/elasticsearch
COPY --from=builder --chown=1000:0 /usr/share/elasticsearch /usr/share/elasticsearch
COPY --from=builder --chown=0:0 /bin/tini /bin/tini

ENV PATH /usr/share/elasticsearch/bin:$PATH
ENV PATH $JAVA_HOME/bin:$PATH

# 1. Sincronize as permissões de usuário e grupo de /etc/passwd
# 2. Defina as permissões corretas do ponto de entrada
# 3. Certifique-se de que não haja arquivos com setuid ou setgid, para mitigar ataques "stackclash".
# Já executados isso em camadas anteriores, então deve ser um no-op.
# 4. Substitua o armazenamento de chaves do certificado CA interno do OpenJDK pelo do sistema operacional
#    fornecedor. Este último é superior em vários aspectos.
# REF: https://github.com/elastic/elasticsearch-docker/issues/171

RUN chmod g=u /etc/passwd && \
    chmod 0775 /usr/local/bin/docker-entrypoint.sh && \
    find / -xdev -perm -4000 -exec chmod ug-s {} + && \
    ln -sf /etc/pki/ca-trust/extracted/java/cacerts /usr/share/elasticsearch/jdk/lib/security/cacerts && \
    cat /tmp/java.policy >> /usr/share/elasticsearch/jdk/lib/security/default.policy

USER elasticsearch

EXPOSE 9200 9300

LABEL org.label-schema.build-date="023-07-06T00:02:43.325594Z -0300" \
  org.label-schema.license="Elastic-License" \
  org.label-schema.name="Elasticsearch" \
  org.label-schema.schema-version="1.0" \
  org.label-schema.url="https://github.com/elastic/elasticsearch" \
  org.label-schema.usage="https://github.com/erivandosena/elasticsearch/blob/development/README.md" \
  org.label-schema.vcs-ref="${COMMIT_SHA}" \
  org.label-schema.vcs-url="https://github.com/erivandosena/elasticsearch" \
  org.label-schema.vendor="Elastic" \
  org.label-schema.version="8.8.2-linux-x86_64" \
  org.opencontainers.image.created="2023-07-06T00:02:43.325594Z -0300" \
  org.opencontainers.image.documentation="https://www.elastic.co/guide/en/elasticsearch/reference/8.8/index.html" \
  org.opencontainers.image.licenses="Elastic-License" \
  org.opencontainers.image.version="${VERSION}" \
  org.opencontainers.image.revision="${COMMIT_SHA}" \
  org.opencontainers.image.source="https://github.com/elastic/elasticsearch" \
  org.opencontainers.image.title="Elasticsearch" \
  org.opencontainers.image.url="https://www.elastic.co/products/elasticsearch" \
  org.opencontainers.image.vendor="Elastic" \
  org.opencontainers.image.maintainer="Erivando Sena<erivandosena@gmail.com>"

ENTRYPOINT ["/bin/tini", "--", "/usr/local/bin/docker-entrypoint.sh"]

CMD ["eswrapper"]

################################################################################
# End of multi-stage Dockerfile
################################################################################