#!/bin/sh
set -eu
# Toolchain provisioning is a separate trusted operation. Override with a reviewed
# node@sha256:... image in release validation to make the toolchain immutable.
test_image=${DROPSYNC_TEST_IMAGE:-node:22-bookworm-slim}
workspace_path=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
exec docker run --rm --pull=never --init --network=none --read-only \
  --cap-drop=ALL --security-opt=no-new-privileges --user=65534:65534 \
  --pids-limit=96 --memory=1g --memory-swap=1g --cpus=2 \
  --ulimit=cpu=180:180 --ulimit=nofile=256:256 --ulimit=fsize=67108864:67108864 \
  --tmpfs=/tmp:rw,nosuid,nodev,noexec,size=512m,nr_inodes=16384,mode=1777 \
  --mount "type=bind,src=$workspace_path,dst=/work,readonly" --workdir=/work \
  --entrypoint=/bin/sh "$test_image" -c \
  'mkdir -p /tmp/home; exec /usr/bin/env -i PATH=/usr/local/bin:/usr/bin:/bin HOME=/tmp/home TMPDIR=/tmp LANG=C.UTF-8 /usr/bin/timeout --signal=KILL 180 /usr/local/bin/node --test test/*.test.js'
