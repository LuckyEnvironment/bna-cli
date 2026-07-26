ARG NODE_VERSION=20
FROM node:${NODE_VERSION}-bookworm-slim

WORKDIR /verify
COPY package.tgz ./
COPY fixtures ./fixtures
COPY verify.sh ./
RUN chmod +x verify.sh

# Nothing is installed at build time on purpose. The install happens at run
# time under --network none, so it can only succeed if the tarball carries
# every runtime dependency with it.
CMD ["bash", "/verify/verify.sh"]
