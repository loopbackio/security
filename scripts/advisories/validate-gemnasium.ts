// SPDX-FileCopyrightText: LoopBack Contributors
// SPDX-License-Identifier: MIT

import addFormats from 'ajv-formats';
import Ajv from 'ajv';
import fs from 'fs';
import glob from 'glob';
import gemnasiumSchema from '../../vendors/local-gemnasium/schema.json';
import path from 'path';
import yaml from 'js-yaml';

const osvDocumentGlob = '../../advisories/*/*.gemnasium.yaml';

console.log(`Validating OSV 1.2.0 documents... (Glob: ${osvDocumentGlob})`);

interface ValidationResult {
  isValid: boolean;
  errors: {
    instancePath: string;
    message?: string;
  }[];
}

glob(path.resolve(__dirname, osvDocumentGlob), async (err, matches) => {
  if (err) throw Error;

  let errorCount = 0;

  for (const filePath of matches) {
    process.stdout.write(
      `  L Validating: ${path.relative(process.cwd(), filePath)}...`,
    );
    const fileContents = yaml.load(fs.readFileSync(filePath));
    const validationResults: Record<string, ValidationResult> = {
      jsonSchema: validateJsonSchema(fileContents),
      csaf20Sync: validateCSAF20Sync(filePath, fileContents),
    };

    const errors = Object.values(validationResults).flatMap(x => x.errors);
    const isValid = errors.length < 1;

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

  if (matches.length === 0) console.log('No Gemnasium DB Advisory documents found!');

  if (errorCount > 0) {
    console.log(`${errorCount} error(s) found.`);
    process.exit(1);
  }

  console.log('OSV 1.2.0 validation done.');
});

function validateJsonSchema(fileContents: any): ValidationResult {
  const validate = addFormats(
    new Ajv({strict: false, allErrors: true}),
  ).compile(gemnasiumSchema);
  const isValid = validate(fileContents);

  return {
    isValid,
    errors: validate.errors ?? [],
  };
}

function validateCSAF20Sync(filePath: string, gemnasiumDocument: any): ValidationResult {
  const errors: ValidationResult['errors'] = [];
  const csaf20Document = require(filePath.replace('.gemnasium.yaml', '.csaf.json'));

  // ID sync
  const csaf20ID = csaf20Document.document.tracking.id;
  const gemnasiumIDs = gemnasiumDocument.identifiers;
    
  if (!gemnasiumIDs.includes(csaf20ID)) {
    errors.push({
      instancePath: '/identifiers',
      message: 'identifiers must contain CSAF 2.0 `/document/tracking/id`.',
    });
  }

  // CVE sync
  const csaf20CVE = csaf20Document.vulnerabilities[0].cve

  if (!gemnasiumIDs.includes(csaf20CVE)) {
    errors.push({
      instancePath: '/identifiers',
      message: 'identifiers must contain CSAF 2.0 `/vulnerabilities/0/cve`.',
    });
  }

  // title sync
  const csaf20Title = csaf20Document.document.title;
  const gemnasiumTitle = gemnasiumDocument.title;

  if (gemnasiumTitle !== csaf20Title) {
    errors.push({
      instancePath: '/title',
      message: 'title must match CSAF 2.0 `/document/title`.',
    });
  }

  // credit / acknowledgments sync
  const csaf20Acknowledgements = csaf20Document.document.acknowledgments.flatMap(x => x.names);
  const gemnasiumCredits = gemnasiumDocument.credit.split(';');

  if (gemnasiumCredits.length >= csaf20Acknowledgements) {
    for (let i = 0; i < gemnasiumCredits.length; i++) {
      if (!csaf20Acknowledgements.includes(gemnasiumCredits[i])) {
        errors.push({
          instancePath: `/credits/${i}`,
          message: `entry \`${gemnasiumCredits[i]}\` not found in CSAF 2.0 \`/document/acknowledgements\`.`,
        });
      }
    }
  } else {
    for (let i = 0; i < csaf20Acknowledgements.lenght; i++) {
      if (!gemnasiumCredits.includes(csaf20Acknowledgements[i])) {
        errors.push({
          instancePath: `/credits`,
          message: `missing entry \`${csaf20Acknowledgements[i]}\` from CSAF 2.0 \`/document/acknowledgements\``,
        });
      }
    }
  }

  // urls & links / references sync
  const csaf20References = [
    ...csaf20Document.document.references.map(x => x.url),
    ...csaf20Document.vulnerabilities
      .flatMap(x => x.references)
      .map(x => x.url),
  ];
  const gemnasiumReferences = [...(gemnasiumDocument.urls ?? []), ...(gemnasiumDocument.links ?? []).map(x => x.url)]

  if (gemnasiumReferences.length >= csaf20References.length) {
    for (let i = 0; i < gemnasiumReferences.length; i++) {
      if (!csaf20References.includes(gemnasiumReferences[i])) {
        errors.push({
          instancePath: `/urls|links/${i}`,
          message: `entry \`${gemnasiumReferences[i]}\` not found in CSAF 2.0 \`/document/references\`.`,
        });
      }
    }
  } else {
    for (let i = 0; i < csaf20References.length; i++) {
      if (!gemnasiumReferences.includes(csaf20References[i])) {
        errors.push({
          instancePath: '/urls|links',
          message: `urls or links entry missing \`${csaf20References[i]}\` from CSAF 2.0 \`/document/references\`.`,
        });
      }
    }
  }

  // CWE sync
  const csaf20CWEs = csaf20Document.vulnerabilities.map(x => x.cwe.id);
  const gemnasiumCWEs = gemnasiumDocument.cwe_ids;

  if (gemnasiumCWEs.length >= csaf20CWEs.length) {
    for (let i = 0; i < gemnasiumCWEs.length; i++) {
      if (!csaf20CWEs.includes(gemnasiumCWEs[i])) {
        errors.push({
          instancePath: `/cwe_ids/${i}`,
          message: `cwe_ids entry \`${gemnasiumCWEs[i]}\` not found in CSAF 2.0 \`/document/vulnerabilities/?/cwe/id`,
        })
      }
    }
  } else {
    for (let i = 0; i < csaf20CWEs.length; i++) {
      if (!gemnasiumCWEs.includes(csaf20CWEs[i])) {
        errors.push({
          instancePath: '/cwe_ids',
          message: `missing entry \`${csaf20CWEs[i]}\` from CSAF 2.0 \`/vulnerabilities/?/cwe/id\`.`,
        });
      }
    }
  }

  // description sync
  const csaf20Description = csaf20Document.vulnerabilities[0].notes.find(x => x.category === 'description').text;
  const gemnasiumDescription = gemnasiumDocument.description;

  if (csaf20Description !== gemnasiumDescription) {
    errors.push({
      instancePath: '/description',
      message: 'description must match CSAF 2.0 `/vulnerabilities/0/notes[category=description]/text',
    });
  }

  // CVSS 3 sync
  const csaf20CVSS3 = csaf20Document.vulnerabilities[0].scores[0].cvss_v3.vectorString;
  const gemnasiumCVSS3 = gemnasiumDocument.cvss_v3;

  if (!csaf20CVSS3.includes(gemnasiumCVSS3)) {
    errors.push({
      instancePath: '/cvss_v3',
      message: 'cvss_v3 must be substring of CSAF 2.0 `/vulnerabilities/0/scores/cvss_v3/vectorString'
    });
  }

  return {
    isValid: errors.length < 1,
    errors,
  }
}
