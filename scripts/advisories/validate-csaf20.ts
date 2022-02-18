import path from 'path';
import glob from 'glob';
import addFormats from 'ajv-formats';
import Ajv2020 from 'ajv/dist/2020';
import csaf20StrictJsonSchema from '../../vendors/secvisogram/app/lib/shared/Core/csaf_2.0_strict.json';
import cvss20JsonSchema from '../../vendors/secvisogram/app/lib/shared/Core/cvss-v2.0.json';
import cvss30JsonSchema from '../../vendors/secvisogram/app/lib/shared/Core/cvss-v3.0.json';
import cvss31JsonSchema from '../../vendors/secvisogram/app/lib/shared/Core/cvss-v3.1.json';

const csaf20DocumentGlob = '../../advisories/*.csaf.json';

console.log(`Validating CSAF 2.0 documents... (Glob: ${csaf20DocumentGlob})`);

glob(path.resolve(__dirname, csaf20DocumentGlob), (err, matches) => {
  if (err) throw Error;

  let errorCount = 0;

  const validate = addFormats(new Ajv2020({strict: false, allErrors: true}))
    .addSchema(cvss20JsonSchema, 'https://www.first.org/cvss/cvss-v2.0.json')
    .addSchema(cvss30JsonSchema, 'https://www.first.org/cvss/cvss-v3.0.json')
    .addSchema(cvss31JsonSchema, 'https://www.first.org/cvss/cvss-v3.1.json')
    .compile(csaf20StrictJsonSchema);

  for (const filePath of matches) {
    process.stdout.write(
      `  L Validating: ${path.relative(process.cwd(), filePath)}...`,
    );
    const fileContents = require(filePath);
    if (validate(fileContents)) console.log('Done!');
    else {
      console.log(`${validate.errors.length} error(s) found:`);
      for (let i = 0; i < validate.errors.length; i++) {
        errorCount++;
        console.log(`    L Error #${i + 1}`);
        console.log(
          `      L Instance path : ${validate.errors[i].instancePath}`,
        );
        console.log(`      L Message       : ${validate.errors[i].message}`);
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
