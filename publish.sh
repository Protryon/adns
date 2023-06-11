#!/bin/bash
set -ex
here=$(realpath $(dirname "$0"))
cd "$here"

if [ -z ${1+x} ] ; then
    echo "missing tag"
    exit 1
fi

export TAG=$1

docker build -t protryon/adns-server:$TAG -f ./Dockerfile .
docker push protryon/adns-server:$TAG
docker image rm protryon/adns-server:$TAG

echo "Uploaded image protryon/adns-server:$TAG"
