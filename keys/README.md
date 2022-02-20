<!--
  SPDX-FileCopyrightText: LoopBack Contributors
  SPDX-License-Identifier: MIT
-->

# LoopBack PGP Keys

> Note: This is a work-in-progress and may be incomplete.

This section of the Git repository is where all the relevant PGP public keys are
stored. This would include:

- Main Key ([`main/`])
- Core Maintainers ([`core-maintainers/`])
- Security Team ([`security-team/`])
- Publications ([`publications/`])

Each directory would contain:

- PGP Key(s)
- Metalink (`.meta4`) for each PGP Key

## PGP Key Policies

### General

General policies apply to all PGP keys in this section of the Git Repository.

- All non-Primary Keys MUST expire within **1 year**.
- Primary Keys SHOULD be kept on a separate, network-isolated system. This can
  be a network-isolated virtual machine on a Qubes OS-based host system.
- Primary Keys MUST NOT be used except for certifying other PGP keys.
- All keys MUST be encrypted with a reasonably secure passphrase.

#### Identity Attestation

Identity Attestation of the LoopBack Project's Core Maintainers are done by:

1. Signing of Mantainer's Key against Main Key
2. Publishing of the Maintainer's Key to the `main` branch of this Git
   repository

Before the LoopBack Project can attest to the identity of a maintainer, a secure
mechanism of exchanging the Maintainer's Key must be done while satisfying the
following requirements:

1. The Maintainer's Key is shared over at least 2 trusted channels where the
   core maintainer has already established the authenticity of their account.
   This can be: e-mail, Slack, and GitHub Teams
2. The process, artifacts (e.g. screenshots, e-mail source code), and
   justification for the pre-established trust of the account are documented
   and stored in an encrypted medium.

#### Private Key Exposure

- All potential private key exposure MUST be communicated with the Security
  Team over e-mail or Slack.
- A Revocation Certificate MUST be generated and published to all key sharing
  systems that's well known, and where the key has been publised as soon as
  feasible by the party in possession of the compromised Private Key.
- A Revocation Certificate MUST be generated and published to all key sharing
  systems that's well known, and where the key has been published within 24
  hours of notification by the party responsible for maintaining the Main Key.

##### Well-known key sharing systems

The following are considered well known PGP Key Servers in alphabetical order:

- <https://keyserver.pgp.com>
- <https://keyserver.ubuntu.com>
- <https://keys.openpgp.org>
- <https://pgp.mit.edu>

### Main Key

The Main Key is used only to certify and sign other PGP Keys used in the
LoopBack Project.

- The Main Key MUST be stored ONLY in a network-isolated system; This can
  include a network-isolated virtual machine on a Qubes OS-based host system.

### Core Maintainers

The Core Maintainers' Key are held by each participating Core Maintianer for
signing of Git commits.

- Each Core Maintainer is responsible for keeping their maintainers' key safe
- This key MUST only be possessed by the
- This key MUST be used for signing Git commits
- This key SHOULD NOT be used except for signing Git commits
  - For avoidance of doubt, this key SHOULD NOT be used for Git
    authentication. Consider using a dedicated SSH key instead.
- This key SHOULD NOT be used except for signing Git commits for the LoopBack
  Project
