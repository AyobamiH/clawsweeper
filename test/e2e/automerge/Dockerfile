ARG AUTOMERGE_E2E_BASE_IMAGE=clawsweeper-automerge-e2e-base:local
FROM ${AUTOMERGE_E2E_BASE_IMAGE}

WORKDIR /workspace

# The actual E2E runner is deliberately network-isolated after image build.
# Corepack prepares each target in a fresh disposable home, so seed the two
# approved fixture pnpm versions at image-build time rather than relying on
# a registry fetch from inside the unprivileged nested Docker worker.
RUN mkdir -p /opt/clawsweeper-e2e-corepack \
  && COREPACK_HOME=/opt/clawsweeper-e2e-corepack corepack prepare pnpm@11.10.0 --activate \
  && COREPACK_HOME=/opt/clawsweeper-e2e-corepack corepack prepare pnpm@11.2.2 --activate \
  && chmod -R a+rX /opt/clawsweeper-e2e-corepack
ENV CLAWSWEEPER_E2E_REQUIRE_OFFLINE_COREPACK=1

COPY package.json pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile

COPY . .
# Docker COPY preserves restrictive source directory modes but assigns root
# ownership. Keep the image runnable by the host UID selected by the wrapper.
RUN chmod -R a+rX /workspace
RUN pnpm run build:node

CMD ["node", "scripts/e2e/automerge.mjs", "--scenario", "all"]
