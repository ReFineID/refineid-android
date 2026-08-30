#!/usr/bin/env bash
# Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.
#
# Fast quality gates for the pre-commit hook: Kotlin formatting and static
# analysis, Rust formatting, and shell lint. The full floor -- warnings-as-
# errors compilation, tests, lint, Clippy, and the release-artifact checks --
# runs in the pre-push gate via `./gradlew check`.

set -euo pipefail
cd "$(dirname "$0")/.."

# shellcheck source=Scripts/gradle-environment.sh
source Scripts/gradle-environment.sh

./gradlew --quiet spotlessCheck detekt :app:detekt rustFormatCheck shellCheck
echo "pre-commit gates passed"
