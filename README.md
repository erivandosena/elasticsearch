# Elasticsearch
Elasticsearch v8.8.2 and Docker image Debian

Built by Backporting the 6.8 ARM64 Dockerfile and copying the JDK from the 20.1 ElasticSearch docker distribution for AMD 32/64 to the 8.8 ElasticSearch distribution in this repo (elasticsearch-8.8.2-linux-x86_64.tar.gz)

# Building the image
``` bash
docker build . -t erivando/elasticsearch:8.8.2
```

# Running the image
To run it:

``` bash
docker run -p 9200:9200 -p 9300:9300 -e "discovery.type=single-node"  -e "xpack.ml.enabled=false" erivando/elasticsearch:8.8.2
```

## Image
> https://hub.docker.com/r/erivando/elasticsearch