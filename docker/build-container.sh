#!/bin/bash
#
docker build --no-cache -t norisjunior/lwpubsub-iotagent:v1.12 . \
  --build-arg GITHUB_ACCOUNT=norisjunior \
  --build-arg GITHUB_REPOSITORY=iotagent-ul \
  --build-arg SOURCE_BRANCH=origin/release/1.12.0
