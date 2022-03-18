// SPDX-FileCopyrightText: LoopBack Contributors
// SPDX-License-Identifier: MIT

import path from 'path';
import glob from 'glob';
import createCore from 'secvisogram/dist/shared/Core';

const csaf20DocumentGlob = '../../advisories/*/*.csaf.json';

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
    const validationResults: Record<string, ValidationResult> = {
      secvisogram: await document.validate({document: fileContents}),
      revisionDate: validateTracking(fileContents),
      distribution: validateDistribution(fileContents),
      productTree: validateProductTree(fileContents),
      publisher: validatePublisher(fileContents),
      references: validateReferences(fileContents),
    };

    const validationResultsValues = Object.values(validationResults);

    const errors = validationResultsValues.flatMap(x => x.errors);
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

  if (matches.length === 0) console.log('No CSAF 2.0 documents found!');

  if (errorCount > 0) {
    console.log(`${errorCount} error(s) found.`);
    process.exit(1);
  }

  console.log('CSAF 2.0 validation done.');
});

interface ValidationResult {
  isValid: boolean;
  errors: {
    instancePath: string;
    message?: string;
  }[];
}

function validateTracking(fileContents: any): ValidationResult {
  const tracking = fileContents.document.tracking;
  let errors: ValidationResult['errors'] = [];

  if (!/^(LBSEC-[1-9][0-9]*-[1-9][0-9]*)$/.test(tracking.id)) {
    errors.push({
      instancePath: 'document/tracking/id',
      message: 'id must match `/^(LBSEC-[1-9][0-9]*-[1-9][0-9]*)$/`.',
    });
  }

  if (tracking.revision_history[0].date != tracking.current_release_date) {
    errors.push({
      instancePath: '/document/tracking/current_release_date',
      message: 'current_release_date does not match latest revision history.',
    });
  }

  if (
    tracking.revision_history[tracking.revision_history.length - 1].date !=
    tracking.initial_release_date
  ) {
    errors.push({
      instancePath: '/document/tracking/initial_release_date',
      message: 'initial_release_date does not match first revision history.',
    });
  }

  function getVersioningSystem(str: string): 'integer' | 'semver' {
    const intVersioningRegex = /^(0|[1-9][0-9]*)$/;
    return intVersioningRegex.test(str) ? 'integer' : 'semver';
  }

  if (tracking.revision_history.length > 1) {
    const versioningSystem = getVersioningSystem(
      tracking.revision_history[0].number,
    );

    for (let i = 1; i < tracking.revision_history.length; i++) {
      if (
        getVersioningSystem(tracking.revision_history[i].number) !==
        versioningSystem
      ) {
        errors.push({
          instancePath: `/document/revision_history/${i}/number`,
          message: 'number version system inconsistent.',
        });
      }
    }
  }

  return {
    isValid: errors.length < 1,
    errors,
  };
}

function validateDistribution(fileContents: any): ValidationResult {
  const distribution = fileContents.document.distribution;
  const errors: ValidationResult['errors'] = [];
  const standardisedDistributionInfo =
    'Disclosure is not limited.\n' +
    'SPDX-FileCopyrightText: LoopBack Contributors\n' +
    'SPDX-License-Identifier: MIT';

  if ((distribution.text as string) !== standardisedDistributionInfo) {
    errors.push({
      instancePath: '/document/distribution/text',
      message: `text must be \`${standardisedDistributionInfo}\``,
    });
  }

  if (distribution.tlp?.label !== 'WHITE') {
    errors.push({
      instancePath: '/document/distribution/tlp/label',
      message: 'label must be `WHITE`',
    });
  }

  return {
    isValid: errors.length < 1,
    errors,
  };
}

function validateProductTree(fileContents: any): ValidationResult {
  const productTree = fileContents.product_tree.branches;
  const errors: ValidationResult['errors'] = [];
  const lbRootBranchIndex = (productTree as any[])?.findIndex(
    v => v.name === 'LoopBack',
  );

  if (lbRootBranchIndex > -1) {
    const lbRootBranch = productTree[lbRootBranchIndex];
    if (lbRootBranch.category !== 'vendor') {
      errors.push({
        instancePath: `/product_tree/branches/${lbRootBranchIndex}/category`,
        message: 'category must be `vendor` for `LoopBack` vendor root branch.',
      });
    }
  } else {
    errors.push({
      instancePath: '/product_tree/branches',
      message: '`LoopBack` vendor root branch must exist.',
    });
  }

  return {
    isValid: errors.length < 1,
    errors,
  };
}

function validatePublisher(fileContents: any): ValidationResult {
  const publisher = fileContents.document.publisher;
  const errors: ValidationResult['errors'] = [];

  if (publisher.category !== 'vendor') {
    errors.push({
      instancePath: '/document/publisher/category',
      message: 'category must equal `vendor`',
    });
  }

  if (publisher.name !== 'LoopBack') {
    errors.push({
      instancePath: '/document/publisher/name',
      message: 'name must equal `LoopBack`',
    });
  }

  if (publisher.namespace !== 'https://loopback.io') {
    errors.push({
      instancePath: '/document/publisher/namespace',
      message: 'namespace must equal `https://loopback.io`',
    });
  }

  return {
    isValid: errors.length < 1,
    errors,
  };
}

function validateReferences(fileContents: any): ValidationResult {
  const errors: ValidationResult['errors'] = [];
  const documentReferences = fileContents.document.references;
  const vulnerabilityReferences = fileContents.vulnerabilities.flatMap(
    x => x.references,
  );

  // Ensure references with standardised summary uses a consistent URL.

  // Do not re-order this array.
  const allReferences = [...documentReferences, ...vulnerabilityReferences];

  const refRegexMapping: Record<string, RegExp> = {
    'CVE Record':
      /^https:\/\/www\.cve\.org\/CVERecord\?id=CVE-[1-9][0-9]{3}-\d{4,}(-\d+)?$/,
    NPM: /^https:\/\/www\.npmjs\.com\/package\/([a-z0-9-]|(@[a-z0-9._-]+\/))[a-z0-9._-]+$/,
    'NVD CVE Detail':
      /^https:\/\/nvd\.nist\.gov\/vuln\/detail\/CVE-[1-9][0-9]{3}-\d{4}$/,
    'GitHub Commit':
      /^(https:\/\/github\.com\/(strongloop|loopbackio)\/[A-Za-z0-9._-]+\/commit\/[a-z0-9]+)$/,
    'GitHub Pull Request':
      /^(https:\/\/github\.com\/(strongloop|loopbackio)\/[A-Za-z0-9._-]+\/pull\/[1-9]\d*)$/,
    'X-Force Vulnerability Report':
      /^https:\/\/exchange\.xforce\.ibmcloud\.com\/vulnerabilities\/[1-9]\d*$/,
  };

  for (let i = 0; i < allReferences.length; i++) {
    const ref = allReferences[i];
    const matchedRegex =
      refRegexMapping[
        Object.keys(refRegexMapping).findIndex(x => ref.summary.startsWith(x))
      ];

    if (matchedRegex) {
      if (!matchedRegex.test(ref.url)) {
        // Hacky way of paritally reconstructing the instance path.
        const baseInstancePath =
          i < documentReferences.length
            ? '/document/references/'
            : '/vulnerabilities/?/';
        const refIndex =
          i < documentReferences.length ? i : i - documentReferences.length;

        errors.push({
          instancePath: baseInstancePath + refIndex + '/url',
          message: `url must match \`${matchedRegex}\`.`,
        });
      }
    }
  }

  // Ensure no duplicate URLs between document-level and vulnerability-level
  // references
  const documentReferenceUrls = documentReferences.map(x => x.url);
  const vulnerabilityReferenceUrls = vulnerabilityReferences.map(x => x.url);

  if (documentReferenceUrls.length >= vulnerabilityReferenceUrls) {
    for (let i = 0; i < documentReferenceUrls.length; i++) {
      if (vulnerabilityReferenceUrls.includes(documentReferenceUrls[i])) {
        errors.push({
          instancePath: `/document/references/${i}/url`,
          message:
            'url must not be duplicate in `/vulnerabilities/*/references/*/url`.',
        });
      }
    }
  } else {
    for (let i = 0; i < vulnerabilityReferenceUrls.length; i++) {
      if (documentReferenceUrls.includes(vulnerabilityReferenceUrls[i])) {
        errors.push({
          instancePath: `/vulnerabilities/?/references/${i}/url`,
          message: 'url not must be duplicate in `/document/references/*/url',
        });
      }
    }
  }

  return {
    isValid: errors.length < 1,
    errors,
  };
}
