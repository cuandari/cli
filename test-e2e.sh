#!/bin/bash

set -euo pipefail

export CGO_ENABLED=1

cd test-e2e && go run runner.go $@