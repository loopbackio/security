// SPDX-FileCopyrightText: LoopBack Contributors
// SPDX-License-Identifier: MIT

import path from 'path';
import glob from 'glob';
import Ajv2020 from 'ajv/dist/2020';
import addFormats from 'ajv-formats';
import osvSchema from '../../vendors/osv-schema/validation/schema.json';
import semver from 'semver';

const osvDocumentGlob = '../../advisories/*.osv.json';

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
    const fileContents = require(filePath);
    const validationResults: Record<string, ValidationResult> = {
      jsonSchema: validateJsonSchema(fileContents),
      schemaVersion: validateSchemaVersion(fileContents),
      affectedVersions: validateAffectedVersions(fileContents),
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

  if (matches.length === 0) console.log('No OSV 1.2.0 documents found!');

  if (errorCount > 0) {
    console.log(`${errorCount} error(s) found.`);
    process.exit(1);
  }

  console.log('OSV 1.2.0 validation done.');
});

function validateJsonSchema(fileContents: any): ValidationResult {
  const validate = addFormats(
    new Ajv2020({strict: false, allErrors: true}),
  ).compile(osvSchema);
  const isValid = validate(fileContents);

  return {
    isValid,
    errors: validate.errors ?? [],
  };
}

function validateSchemaVersion(fileContents: any): ValidationResult {
  const errors: ValidationResult['errors'] = [];

  if (fileContents.schema_version !== '1.2.0') {
    errors.push({
      instancePath: '/schema_version',
      message: 'schema_version must be `1.2.0`.',
    });
  }

  return {
    isValid: errors.length < 1,
    errors,
  };
}

function validateAffectedVersions(fileContents: any): ValidationResult {
  const errors: ValidationResult['errors'] = [];

  if (!fileContents.affected) {
    errors.push({
      instancePath: '/affected',
      message: 'affected must exist.',
    });
  }

  for (const affected of fileContents.affected) {
    const versions = affected.versions;

    if (versions !== undefined) {
      const semverEvents = (affected.ranges as any[]).find(
        x => x.type === 'SEMVER',
      ).events;
      const semverRange =
        '>=' +
        semverEvents.find(x => x.introduced).introduced +
        ' <' +
        semverEvents.find(x => x.fixed).fixed;

      for (let i = 0; i < versions.length; i++) {
        const version = versions[i];

        if (
          !semver.satisfies(version, semverRange, {includePrerelease: true})
        ) {
          errors.push({
            instancePath: `/affected/versions/${i}`,
            message:
              'versions must be within introduced and fixed semver range.',
          });
        }
      }
    } else {
      errors.push({
        instancePath: '/affected/ranges/versions',
        message: 'versions must exist.',
      });
    }
  }

  return {
    isValid: errors.length < 1,
    errors,
  };
}

function validateCSAF20Sync(
  filePath: string,
  osvDocument: any,
): ValidationResult {
  const csaf20Document = require(filePath.replace('.osv.json', '.csaf.json'));
  const errors: ValidationResult['errors'] = [];

  // ID sync
  const csaf20ID = csaf20Document.document.tracking.id;
  const osvID = osvDocument.id;

  if (osvID !== csaf20ID) {
    errors.push({
      instancePath: '/id',
      message: 'id must match CSAF 2.0 `/document/tracking/id`.',
    });
  }

  // Summary sync
  const csaf20Summary = csaf20Document.vulnerabilities[0].notes?.find(
    x => x.category === 'summary',
  ).text;
  const osvSummary = osvDocument.summary;

  if (csaf20Summary !== osvSummary) {
    errors.push({
      instancePath: '/summary',
      message: 'summary must match CSAF 2.0 `/document/notes` instance.',
    });
  }

  // Description / Details sync
  const csaf2SDescription = csaf20Document.vulnerabilities[0].notes.find(
    x => x.category === 'description',
  ).text;
  const osvDetails = osvDocument.details;

  if (csaf2SDescription !== osvDetails) {
    errors.push({
      instancePath: '/details',
      message: 'details must match CSAF 2.0 `/document/notes` instance.',
    });
  }

  // CVE sync
  const csaf20CVE = csaf20Document.vulnerabilities[0].cve;
  const osvCVE = osvDocument.aliases.find(x => x.startsWith('CVE-'));

  if (csaf20CVE !== osvCVE) {
    errors.push({
      instancePath: '/aliases',
      message: 'alises must match CSAF `/vulnerabilities/0/cve`.',
    });
  }

  // CVSS V3 sync
  const csaf20CVSS3 =
    csaf20Document.vulnerabilities[0].scores[0].cvss_v3?.vectorString;
  const osvCVSS3Index = osvDocument.severity.findIndex(
    x => x.type === 'CVSS_V3',
  );
  const osvCVSS3 =
    osvCVSS3Index > -1 ? osvDocument.severity[osvCVSS3Index].score : undefined;

  if (csaf20CVSS3 !== osvCVSS3) {
    errors.push({
      instancePath: `/severity/score/${osvCVSS3Index}`,
      message:
        'score must match CSAF 2.0 `/vulnerabilities/0/scores/0/cvss_v3/attackVector`.',
    });
  }

  // CWE sync
  const csaf20CWE = csaf20Document.vulnerabilities[0].cwe.id;
  const osvCWE = osvDocument.database_specific.CWE;

  if (csaf20CWE !== osvCWE) {
    errors.push({
      instancePath: '/database_specific/cwe',
      message: 'cwe must match CSAF 2.0 `/vulnerabilities/0/cwe/id`.',
    });
  }

  // References sync
  const csaf20References = [
    ...csaf20Document.document.references.map(x => x.url),
    ...csaf20Document.vulnerabilities
      .flatMap(x => x.references)
      .map(x => x.url),
  ];
  const osvReferences = osvDocument.references
    .map(x => x.url)
    .filter(x => x !== 'https://loopback.io');

  if (osvReferences.length >= csaf20References.length) {
    for (let i = 0; i < osvReferences.length; i++) {
      if (!csaf20References.includes(osvReferences[i])) {
        errors.push({
          instancePath: `/references/${i}`,
          message: `entry \`${osvReferences[i]}\` not found in CSAF 2.0 \`/document/references\`.`,
        });
      }
    }
  } else {
    for (let i = 0; i < csaf20References.length; i++) {
      if (!osvReferences.includes(csaf20References[i])) {
        errors.push({
          instancePath: '/references',
          message: `references missing \`${csaf20References[i]}\` from CSAF 2.0 \`/document/references\`.`,
        });
      }
    }
  }

  // Acknowledgments / credits sync
  const csaf20Acknowledgments = csaf20Document.document.acknowledgments.flatMap(
    x => x.names,
  ) as string[];
  const osvCredits = osvDocument.credits.flatMap(x => x.name) as string[];

  if (osvCredits.length >= csaf20Acknowledgments.length) {
    for (let i = 0; i < osvCredits.length; i++) {
      const osvCredit = osvCredits[i];
      if (!csaf20Acknowledgments.includes(osvCredit)) {
        errors.push({
          instancePath: `/credits/${i}`,
          message: `entry \`${osvCredit}\` not found in CSAF 2.0 \`/document/acknowledgments\`.`,
        });
      }
    }
  } else {
    for (let i = 0; i < csaf20Acknowledgments.length; i++) {
      const csaf20Acknowledgement = csaf20Acknowledgments[i];
      if (!osvCredits.includes(csaf20Acknowledgement)) {
        errors.push({
          instancePath: `/credits`,
          message: `missing entry \`${csaf20Acknowledgement}\` from CSAF 2.0 \`/document/acknowledgments\`.`,
        });
      }
    }
  }

  return {
    isValid: errors.length < 1,
    errors,
  };
}
