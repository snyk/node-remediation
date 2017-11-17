'use strict';
module.exports = upgrades;
module.exports.remediation = require('./upgrade-remediation');

const stripInvalidPatches = require('./utils/strip-invalid-patches');
const canBeUpgraded = require('./utils/can-be-upgraded');
const sort = require('./utils/sort');
const moduleToObject = require('snyk-module');
const cloneDeep = require('lodash.clonedeep');

function upgrades(vulns, semver) {
  if (!vulns || vulns.length === 0) {
    return [];
  }

  let res = stripInvalidPatches(cloneDeep(vulns), semver).filter(canBeUpgraded);

  // sort by vulnerable package and the largest version
  res.sort(semverSortUpgradePrompts(semver));

  let copy = null;
  let offset = 0;
  // mutate our objects so we can try to group them
  // note that I use slice first becuase the `res` array will change length
  // and `reduce` _really_ doesn't like when you change the array under
  // it's feet
  res.slice(0).reduce((acc, curr, i) => {
    var from = curr.from[1];

    if (!acc[from]) {
      // only copy the biggest change
      copy = cloneDeep(curr);
      acc[from] = curr;
      return acc;
    }

    var upgrades = curr.upgradePath.slice(-1).shift();
    // otherwise it's a patch and that's hidden for now
    if (upgrades && curr.upgradePath[1]) {
      if (!acc[from].grouped) {
        acc[from].grouped = {
          affected: moduleToObject(from),
          main: true,
          id: acc[from].id + '-' + i,
          count: 1,
          upgrades: [],
        };
        acc[from].grouped.affected.full = from;

        // splice this vuln into the list again so if the user choses to review
        // they'll get this individual vuln and remediation
        copy.grouped = {
          main: false,
          requires: acc[from].grouped.id,
        };

        res.splice(i + offset, 0, copy);
        offset++;
      }

      acc[from].grouped.count++;

      curr.grouped = {
        main: false,
        requires: acc[from].grouped.id,
      };

      var p = moduleToObject(upgrades);
      if (p.name !== acc[from].grouped.affected.name &&
        (' ' + acc[from].grouped.upgrades.join(' ') + ' ')
          .indexOf(p.name + '@') === -1) {

        acc[from].grouped.upgrades.push(upgrades);
      }
    }

    return acc;
  }, {});

  // now strip anything that doesn't have an upgrade path
  res = res.filter(curr => !!curr.upgradePath[1]);

  return res;
}

function semverSortUpgradePrompts(semver) {

  return function sortUpgradePrompts(a, b) {
    var res = 0;

    // first sort by module affected
    if (!a.from[1]) {
      return -1;
    }

    if (!b.from[1]) {
      return 1;
    }

    var pa = moduleToObject(a.from[1]);
    var pb = moduleToObject(b.from[1]);
    res = sort('name')(pa, pb);
    if (res !== 0) {
      return res;
    }

    // we should have the same module, so the depth should be the same
    if (a.upgradePath[1] && b.upgradePath[1]) {
      // put upgrades ahead of patches
      if (b.upgradePath[1] === false) {
        return 1;
      }
      var pua = moduleToObject(a.upgradePath[1]);
      var pub = moduleToObject(b.upgradePath[1]);

      res = semver.compare(pua.version, pub.version) * -1;

      if (res !== 0) {
        return res;
      }
    } else {
      if (a.upgradePath[1]) {
        return -1;
      }

      if (b.upgradePath[1]) {
        return 1;
      }

      // if no upgrade, then hopefully a patch
      res = sort('publicationTime')(b, a);
    }

    return res;
  }

}
