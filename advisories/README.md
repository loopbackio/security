<!--
  SPDX-FileCopyrightText: LoopBack Contributors
  SPDX-License-Identifier: MIT
-->

# LoopBack Security Advisories (LBSA)

> Note: This is a work-in-progress and may be incomplete. Please see
> <https://loopback.io/doc/en/sec/index.html> for a canonical list of security
> advisories.

This section of the Git repository is where all LBSAs are stored. They are
written as [CSAF 2.0](https://docs.oasis-open.org/csaf/csaf/v2.0/csaf-v2.0.html)
documents and
[OSV 1.2.0](https://github.com/ossf/osv-schema/tree/5e3cbf8abb4e192f87d00354b23e56340388cf98).

The naming convention is as follows:

```
lbsa-YYYYMMDD.csaf.json <-- CSAF 2.0
lbsa-YYYYMMDD.osv.json  <-- OSV 1.2.0
```

Where:

- `YYYY` is the year of
- `MM` is the month
- `DD` is the day

## Scripts

Validation of the CSAF 2.0 documents are done by
<../scripts/advisories/validate-csaf20.ts>. This is triggered automatically
during a Git commit, and as part of the
[CI pipeline](../.github/workflows/ci.yaml). It can also be triggered by running
`npm run validate-csaf20`.

Validation of OSV 1.2.0 documents are done by
<../scripts/advisories/validate-osv.ts>. This is triggered automatically during
a Git commit, and as aprt of the [CI pipeline](../.github/workflows/ci.yaml). It
can also be triggered by running `npm run validate-osv`.

CSAF 2.0 acts as the "source of truth" of which the other formats are validated
against as it is the most comprehensive format. Hence, any deviations from the
CSAF 2.0 document must also be reflected back in the CSAF 2.0 document itself.

## Vendors

This section depends on [Secvisogram](../vendors/README.md#submodules) for
validation, its ports of JSON Schemas from Draft-04 (No first-class AJV support)
to Draft-2019, and for a strict variant of CSAF 2.0 JSON Schema. There are plans
to utilise the other parts of the codebase for more thorough validation.

It also depends on
[Open Source Vulnerability schema](../vendors/README.md#submodules) for JSON
Schema-based OSV validation.

## Dependents

There's current no known dependents on these CSAF 2.0 documents. However, there
are future plans to add integration:

| Integration                                                                                           | Status  |
| ----------------------------------------------------------------------------------------------------- | ------- |
| Generation of security advisories on [loopback.io website](https://loopback.io/doc/en/sec/index.html) | Planned |
| Publishing as a CSAF Provider through csaf.data.loopback.io                                           | Planned |
| Down-conversion and publication of CVRF 1.2                                                           | Planned |
| Sync with Gitlab Advisory Database                                                                    | Planned |
