#!/bin/bash
#
docker build --no-cache -t norisjunior/lwpubsub-iotagent-ccm:v2.0 . \
  --build-arg GITHUB_ACCOUNT=norisjunior \
  --build-arg GITHUB_REPOSITORY=iotagent-ul \
  --build-arg SOURCE_BRANCH=origin/lwpubsub-iotagent-ccm
