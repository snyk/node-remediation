'use strict';
module.exports = remediation;

const debug = require('debug')('snyk:remediation');
const last = x => x[x.length - 1];

// pick the best remediation
function remediation(vulns) {
  // note - vulns are in the correct order

  /**
   * response object:
   * [{
   *   package: String,
   *   upgrades: <Array name@version>
   *   vulns: <Array vulnIds>
   * }]
   */

  return vulns.reduce((acc, curr) => {
    // TODO this should be a feature that the user can opt out of:
    // ignore anything being filtered out due to policy
    if (curr.filtered) {
      debug('skipping filtered %s', curr.id);
      return acc;
    }

    let pkg = curr.from[1];

    // we don't need any of the sub-updates, since we'll take the top level
    if (curr.grouped && curr.grouped.main === false) {
      debug('grouped but not main %s', curr.id);
      // but find the current upgrade path and add this as something that
      // gets updated too
      if (acc[pkg].vulns.indexOf(curr.id) === -1) {
        acc[pkg].vulns.push(curr.id);
        acc[pkg].upgrades.push(last(curr.from));
      }

      return acc;
    }

    acc[pkg] = {
      upgradeTo: curr.upgradePath[1],
      upgrades: [last(curr.from)],
      vulns: [curr.id],
    };

    return acc;
  }, {});
}
