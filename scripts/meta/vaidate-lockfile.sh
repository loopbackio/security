#!/bin/sh
# SPDX-FileCopyrightText: LoopBack Contributors
# SPDX-License-Identifier: MIT

set -eu
export POSIXLY_CORRECT=1

SCRIPT_PATH="$(dirname $0)"
REPO_PATH="$SCRIPT_PATH/../../"

find "$REPO_PATH" \
    -name package-lock.json \
    -type f \
    -exec \
        npx --no-install \
            lockfile-lint \
                --allowed-hosts=npm \
                --allowed-schemes=https: file: \
                --path='{}' \;
