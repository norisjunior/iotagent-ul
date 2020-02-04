#!/bin/bash
#
docker build --no-cache -t lwpubsub-iotagent . \
    --build-arg GITHUB_ACCOUNT=norisjunior \
    --build-arg GITHUB_REPOSITORY=iotagent-ul \
    --build-arg SOURCE_BRANCH=lwpubsub-iotagent
