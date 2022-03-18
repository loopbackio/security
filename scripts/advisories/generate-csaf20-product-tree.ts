// SPDX-FileCopyrightText: LoopBack Contributors
// SPDX-License-Identifier: MIT

// This is a rudimentary script which reads a newline-delimited list of
// `<package name>@<package semver>` from stdin and generates the final branch
//  of the CSAF 2.0 Product Tree to stdout.
//
// To generate a list of Git Tags for this script (LoopBack 4 monorepo only):
//    git tag | grep <package name>@
//
// To generate a list of versions from NPM:
//     npm view --json <package name> versions \
//         | jq "\"<package name>@\" + .[]" \
//         | sed -e 's/^.\{1\}//' -e 's/.\{1\}$//'

import readline from 'readline';

var rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
  terminal: false,
});

const entries = [];

rl.on('line', line => {
  const nameVerSeperator = line.lastIndexOf('@');
  const name = line.substring(0, nameVerSeperator);
  const version = line.substring(nameVerSeperator + 1);

  entries.push({
    category: 'product_version',
    name: `${version}`,
    product: {
      name: `${name}@${version}`,
      product_id: `${entries.length + 1}`,
      product_identification_helper: {
        cpe: `cpe:2.3:a:loopback:${name
          .replace('/', '_')
          .replace('@', '')}:${version}:*:*:*:*:*:*:*`,
        purl: `pkg:npm/${encodeURIComponent(name).replace(
          '%2F',
          '/',
        )}@${version}`,
      },
    },
  });
});

rl.on('close', () => {
  console.log(JSON.stringify(entries, undefined, 2));
});
