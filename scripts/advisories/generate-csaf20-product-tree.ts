// SPDX-FileCopyrightText: LoopBack Contributors
// SPDX-License-Identifier: MIT

// This is a rudimentary script which reads a newline-delimited list of GitHub
// tag name of format `<package name>@<package semver>` and generates the final
// branch of the CSAF 2.0 Product Tree to stdout. Currently, it's only designed
// for LoopBack 4 packages (i.e. `@loopback/*`).
//
// To generate a list of Git Tags for this script:
//   git tag --sort=taggerdate | grep <package name>@

import readline from 'readline';

var rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
  terminal: false,
});

const entries = [];

rl.on('line', line => {
  if (line.startsWith('@loopback/')) {
    const nameVerSeperator = line.lastIndexOf('@');
    const name = line.substring(0, nameVerSeperator);
    const version = line.substring(nameVerSeperator + 1);

    entries.push({
      category: 'product_version',
      name: `Version ${version}`,
      product: {
        name: `${name} - Version ${version}`,
        product_id: `${entries.length + 1}`,
        product_identification_helper: {
          cpe: `cpe:2.3:a:loopback:${name
            .replace('/', '_')
            .replace('@', '')}:${version}:*:*:*:*:*:*:*`,
          purl: `pkg:npm/${encodeURIComponent(name)}@${version}`,
        },
      },
    });
  }
});

rl.on('close', () => {
  console.log(JSON.stringify(entries, undefined, 2));
});
