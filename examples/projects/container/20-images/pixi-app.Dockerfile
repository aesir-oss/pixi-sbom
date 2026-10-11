# pixi's production layout: the environment installed from the lockfile in a build stage, then copied
# into a slim image on its own, without the manifest or the lockfile.
FROM ghcr.io/prefix-dev/pixi:0.81.0-bookworm-slim AS build
WORKDIR /app
COPY pixi/02-flask/pixi.toml pixi/02-flask/pixi.lock ./
RUN pixi install --locked --environment default

FROM debian:bookworm-slim
COPY --from=build /app/.pixi/envs/default /app/.pixi/envs/default
