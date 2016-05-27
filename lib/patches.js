'use strict';
module.exports = patches;
module.exports.remediation = require('./patch-remediation');

const stripInvalidPatches = require('./utils/strip-invalid-patches');
const canBeUpgraded = require('./utils/can-be-upgraded');
const sort = require('./utils/sort');
const semver = require('semver');
const moduleToObject = require('snyk-module');
const cloneDeep = require('lodash.cloneDeep');

function patches(vulns) {
  if (!vulns || vulns.length === 0) {
    return [];
  }

  var res = stripInvalidPatches(cloneDeep(vulns)).filter(function (vuln) {
    // if there's any upgrade available, then remove it
    return canBeUpgraded(vuln) ? false : true;
  });

  // sort by vulnerable package and the largest version
  res.sort(sortPatchPrompts);

  // console.log(res.map(_ => `${_.name}@${_.version}`));

  var copy = {};
  var offset = 0;
  // mutate our objects so we can try to group them
  // note that I use slice first becuase the `res` array will change length
  // and `reduce` _really_ doesn't like when you change the array under
  // it's feet
  res.slice(0).reduce((acc, curr, i, all) => {
    // var upgrades = curr.upgradePath[1];
    // otherwise it's a patch and that's hidden for now
    if (curr.patches && curr.patches.length) {
      // TODO allow for cross over patches on modules (i.e. patch can work
      // on A-1 and A-2)
      var last = curr.id;

      if (acc[curr.id]) {
        last = curr.id;
      } else {
        // try to find the right vuln id based on the publication times
        last = (all.filter(vuln => {
          var patch = vuln.patches[0];

          // don't select the one we're looking at

          if (curr.id === vuln.id) {
            return false;
          }

          // only look at packages with the same name
          if (curr.name !== vuln.name || !patch) {
            return false;
          }

          // and ensure the patch can be applied to *our* module version
          if (semver.satisfies(curr.version, patch.version)) {

            // finally make sure the publicationTime is newer than the curr
            // vulnerability
            if (curr.publicationTime < vuln.publicationTime) {
              return true;
            }
          }
        }).shift() || curr).id;
      }

      if (!acc[last]) {
        // only copy the biggest change
        copy[last] = cloneDeep(curr);
        acc[last] = curr;
        return acc;
      }

      // only happens on the 2nd time around
      if (!acc[last].grouped) {
        acc[last].grouped = {
          affected: moduleToObject(acc[last].name + '@' + acc[last].version),
          main: true,
          id: acc[last].id + '-' + i,
          count: 1,
          upgrades: [{
            // all this information is used when the user selects group patch
            // specifically: in ./tasks.js~42
            from: acc[last].from,
            filename: acc[last].__filename,
            patches: acc[last].patches,
            version: acc[last].version,
          },],
          patch: true,
        };

        acc[last].grouped.affected.full = acc[last].name;

        // splice this vuln into the list again so if the user choses to review
        // they'll get this individual vuln and remediation
        copy[last].grouped = {
          main: false,
          requires: acc[last].grouped.id,
        };

        res.splice(i + offset, 0, copy[last]);
        offset++;
      }

      acc[last].grouped.count++;

      curr.grouped = {
        main: false,
        requires: acc[last].grouped.id,
      };

      // add the from path to our group upgrades if we don't have it already
      var have = !!acc[last].grouped.upgrades.filter(upgrade => {
        return upgrade.from.join(' ') === curr.from.join(' ');
      }).length;

      if (!have) {
        acc[last].grouped.upgrades.push({
          from: curr.from,
          filename: curr.__filename,
          patches: curr.patches,
          version: curr.version,
        });
      } else {
        if (!acc[last].grouped.includes) {
          acc[last].grouped.includes = [];
        }
        acc[last].grouped.includes.push(curr.id);
      }
    }

    return acc;
  }, {});

  // FIXME this should not just strip those that have an upgrade path, but
  // take into account the previous answers, and if the package has been
  // upgraded, it should be left *out* of our list.
  res = res.filter(curr => {
    if (!curr.patches || curr.patches.length === 0) {
      return false;
    }

    return true;
  });

  return res;
}

function sortPatchPrompts(a, b) {
  var res = 0;

  // first sort by module affected
  var afrom = a.from.slice(1).pop();
  var bfrom = b.from.slice(1).pop();

  if (!afrom) {
    return -1;
  }

  if (!bfrom[1]) {
    return 1;
  }

  var pa = moduleToObject(afrom);
  var pb = moduleToObject(bfrom);
  res = sort('name')(pa, pb);
  if (res !== 0) {
    return res;
  }

  // if no upgrade, then hopefully a patch
  res = sort('publicationTime')(b, a);

  return res;
}
