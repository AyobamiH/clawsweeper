FROM node:24.18.1-bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends gh ripgrep bubblewrap python3 util-linux ca-certificates git curl jq sudo unzip zip zstd tar gzip libicu72 libssl3 && rm -rf /var/lib/apt/lists/*
COPY --from=docker.io/cloudflare/sandbox:0.12.10 /container-server/sandbox /sandbox
COPY runtime /opt/clawsweeper
RUN mkdir -p /opt/actions-runner && curl -fsSL https://github.com/actions/runner/releases/download/v2.337.0/actions-runner-linux-x64-2.337.0.tar.gz -o /tmp/runner.tar.gz && echo "70920811a4f8ad4328818682bca5c6469c1c942fab52448868071d0063816613  /tmp/runner.tar.gz" | sha256sum -c - && tar xzf /tmp/runner.tar.gz -C /opt/actions-runner && rm /tmp/runner.tar.gz
COPY start-runner.sh /opt/start-runner.sh
RUN chmod 755 /opt/start-runner.sh
WORKDIR /opt/clawsweeper
ENTRYPOINT ["/sandbox"]
