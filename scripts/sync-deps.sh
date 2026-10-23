#!/usr/bin/env bash
# lmweather has no third-party source dependencies (own FFT, Gauss-Legendre and spherical-harmonic code).
# This script exists so the CI steps and test.sh are uniform with the other hosts.
set -eu
[ "${1:-}" = "--verify" ] && echo "no third-party dependencies" || echo "no third-party dependencies to fetch"
exit 0
