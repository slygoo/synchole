#!/usr/bin/env bash
# Regenerate Go code for every .proto in this directory.
#
# Requires (already installed in the research env):
#   apt-get install -y protobuf-compiler              # protoc (use v3.21.x to match all.pb.go)
#   go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
#
# NOTE: all.pb.go was generated from an all.proto that is not in the repo; it is
# left as-is. New types live in extra.proto (same `syncproto` package) and are
# generated here. Running this only (re)generates files for .proto present here.
set -euo pipefail
cd "$(dirname "$0")"
export PATH="$PATH:$(go env GOPATH)/bin"

shopt -s nullglob
protos=(*.proto)
if [ ${#protos[@]} -eq 0 ]; then echo "no .proto files"; exit 0; fi

# Skip protos that define no messages (protoc still emits an empty .pb.go).
for p in "${protos[@]}"; do
  if grep -qE '^\s*message\s+\w+' "$p"; then
    echo "[gen] $p"
    protoc --go_out=. --go_opt=paths=source_relative "$p"
  else
    echo "[skip] $p (no messages yet)"
  fi
done
echo "done. Run 'go build ./...' from the module root."
