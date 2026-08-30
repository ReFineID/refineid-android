# Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.
#
# Shared build-environment resolution for hook and helper scripts. Sourced,
# not executed: exports JAVA_HOME and puts the rustup-managed toolchain on
# PATH when the shell that invoked git lacks them (GUI clients, hooks).

if [[ -z "${JAVA_HOME:-}" ]] && [[ "$(uname)" == "Darwin" ]]; then
  if command -v brew > /dev/null; then
    brew_jdk="$(brew --prefix openjdk 2> /dev/null)/libexec/openjdk.jdk/Contents/Home"
    if [[ -d "${brew_jdk}" ]]; then
      export JAVA_HOME="${brew_jdk}"
    fi
  fi
  if [[ -z "${JAVA_HOME:-}" ]]; then
    studio_jdk="/Applications/Android Studio.app/Contents/jbr/Contents/Home"
    if [[ -d "${studio_jdk}" ]]; then
      export JAVA_HOME="${studio_jdk}"
    fi
  fi
fi

if command -v brew > /dev/null; then
  rustup_bin="$(brew --prefix rustup 2> /dev/null)/bin"
  if [[ -d "${rustup_bin}" ]]; then
    export PATH="${rustup_bin}:${HOME}/.cargo/bin:${PATH}"
  fi
fi
