#!/bin/bash
#
docker login

docker build --no-cache -t norisjunior/lwpubsub-iotagent-ccm:v2.10 . \
  --build-arg GITHUB_ACCOUNT=norisjunior \
  --build-arg GITHUB_REPOSITORY=iotagent-ul \
  --build-arg SOURCE_BRANCH=lwpubsub-iotagent-ccm

docker push norisjunior/lwpubsub-iotagent-ccm:v2.10
