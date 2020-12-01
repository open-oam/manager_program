#!/usr/bin/env bash

# Get current directory.
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

# Find all directories containing at least one prototfile.
# Based on: https://buf.build/docs/migration-prototool#prototool-generate.
for dir in $(find ${DIR} -name '*.proto' -print0 | xargs -0 -n1 dirname | sort | uniq); do
  files=$(find "${dir}" -name '*.proto')

  # Generate all files with protoc-gen-go.
  protoc -I ${DIR} --go_opt=paths=source_relative:${DIR} --go-grpc_out=${files} --go-grpc_opt=paths=source_relative  # --go_out=plugins=grpc,paths=source_relative:${DIR} ${files}
done
