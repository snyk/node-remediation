module.exports = stripInvalidPatches;

const semver = require('semver');

function stripInvalidPatches(vulns) {
  // strip the irrelevant patches from the vulns at the same time, collect
  // the unique package vulns
  return vulns.map(vuln => {
    // strip verbose meta
    delete vuln.description;
    delete vuln.credit;

    if (vuln.patches) {
      vuln.patches = vuln.patches.filter(patch => {
        return semver.satisfies(vuln.version, patch.version);
      });

      // sort by patchModification, then pick the latest one
      vuln.patches = vuln.patches.sort((a, b) => {
        return b.modificationTime < a.modificationTime ? -1 : 1;
      }).slice(0, 1);

      // FIXME hack to give all the patches IDs if they don't already
      if (vuln.patches[0] && !vuln.patches[0].id) {
        vuln.patches[0].id = vuln.patches[0].urls[0].split('/').slice(-1).pop();
      }
    }

    return vuln;
  });
}
