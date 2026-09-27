FROM node:24.18.1-bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends python3 util-linux ca-certificates git && rm -rf /var/lib/apt/lists/*
COPY --from=docker.io/cloudflare/sandbox:0.12.10 /container-server/sandbox /sandbox
COPY runtime /opt/clawsweeper
WORKDIR /opt/clawsweeper
ENTRYPOINT ["/sandbox"]
