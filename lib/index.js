module.exports = remediate;

const upgrades = require('./upgrades');
const patches = require('./patches');
const Promise = global.Promise || require('es6-promise').Promise;

const values = obj => Object.keys(obj).map(_ => obj[_]);

function remediate(vulns) {
  return new Promise(resolve => {
    const upgrade = upgrades.remediation(upgrades(vulns));
    const patch = patches.remediation(patches(vulns));

    // calculate the remaining vulns
    const vulnIds = Array.from(vulns || []).reduce((acc, curr) => {
      acc[curr.id] = curr;
      return acc;
    }, {});

    for (const u of values(upgrade)) {
      for (const id of u.vulns) {
        delete vulnIds[id];
      }
    }

    for (const id of Object.keys(patch)) {
      delete vulnIds[id];
    }

    return resolve({
      // send unresolved as an array
      unresolved: values(vulnIds),
      upgrade,
      patch,
    });
  });
}
