#!/usr/bin/env bash
# Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.
#
# Enable this repository's mandatory git hooks (one-time, per clone).
#
# core.hooksPath is a local setting git does not apply automatically on
# clone, so each working copy runs this once. It points git at the tracked
# .githooks directory: pre-commit runs the fast quality gates and pre-push
# runs the full `./gradlew check` floor.

set -euo pipefail

root=$(git rev-parse --show-toplevel)
git -C "${root}" config core.hooksPath .githooks
echo "git hooks enabled: core.hooksPath = .githooks"
