// SPDX-FileCopyrightText: LoopBack Contributors
// SPDX-License-Identifier: MIT

import path from 'path';
import glob from 'glob';
import createCore from 'secvisogram/dist/shared/Core';

const csaf20DocumentGlob = '../../advisories/*.csaf.json';

console.log(`Validating CSAF 2.0 documents... (Glob: ${csaf20DocumentGlob})`);

glob(path.resolve(__dirname, csaf20DocumentGlob), async (err, matches) => {
  if (err) throw Error;

  const {document} = createCore();

  let errorCount = 0;

  for (const filePath of matches) {
    process.stdout.write(
      `  L Validating: ${path.relative(process.cwd(), filePath)}...`,
    );
    const fileContents = require(filePath);
    const {isValid, errors} = await document.validate({document: fileContents});

    if (isValid) console.log('Done!');
    else {
      errorCount += errors.length;
      console.log(`${errors.length} error(s) found:`);
      for (let i = 0; i < errors.length; i++) {
        console.log(`    L Error #${i + 1}`);
        console.log(`      L Instance path : ${errors[i].instancePath}`);
        console.log(`      L Message       : ${errors[i].message ?? 'N/A'}`);
      }
    }
  }

  if (matches.length === 0) console.log('No CSAF 2.0 documents found!');

  if (errorCount > 0) {
    console.log(`${errorCount} error(s) found.`);
    process.exit(1);
  }

  console.log('CSAF 2.0 validation done.');
});
