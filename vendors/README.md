<!--
  SPDX-FileCopyrightText: LoopBack Contributors
  SPDX-License-Identifier: MIT
-->

# Vendors

This directory contains directories (Usually Git Submodules) that are depended upon by this Git
repository. If the directory is prefixed with `local-`, it is not a Git Submodule.

| Directory | Used by | Git Submodule?
|-|-|-
| `local-cpe/` | [CPE 2.3 Extended Dictionary validation](../cpe/README.md#scripts) | No
| `osv-schema/` | [OSV 1.2.0 validation](../advisories/README.md#scripts) | Yes
| `secvisogram/` | [CSAF 2.0 validation](../advisories/README.md#scripts) | Yes
