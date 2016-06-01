'use strict';
module.exports = remediation;

const debug = require('debug')('snyk:remediation');
const moduleToObject = require('snyk-module');

// pick the best remediation
function remediation(vulns) {
  var now = (new Date()).toJSON();
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
    let id = curr.id;

    // TODO this should be a feature that the user can opt out of:
    // ignore anything being filtered out due to policy
    if (curr.filtered) {
      debug('skipping filtered %s', id);
      return acc;
    }

    // we don't need any of the sub-updates, since we'll take the top level
    if (curr.grouped && curr.grouped.main === false) {
      return acc;
    }

    acc[id] = {
      paths: [],
    };

    // if this was grouped, then let's also add in the additional
    // paths that get patched
    if (curr.grouped) {
      curr.grouped.upgrades.forEach(patch => {
        acc[id].paths.push(pathRule({
          from: patch.from,
          id,
        }, now));
      });
    } else {
      acc[id].paths.push(pathRule(curr, now));
    }

    return acc;
  }, {});
}

function pathRule(vuln, now) {
  return {
    [vuln.from.slice(1).map(pkg => moduleToObject(pkg).name).join(' > ')]: {
      patched: now,
    },
  };
}
