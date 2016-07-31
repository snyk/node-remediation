module.exports = remediate;

const upgrades = require('./upgrades');
const patches = require('./patches');
const ignores = require('./ignore');
const Promise = global.Promise || require('es6-promise').Promise;

const values = obj => Object.keys(obj).map(_ => obj[_]);

function remediate(vulns, options = {}) {
  return new Promise(resolve => {
    // calculate the remaining vulns
    const vulnIds = Array.from(vulns || []).reduce((acc, curr) => {
      acc[curr.id] = curr;
      return acc;
    }, {});
    const upgrade = upgrades.remediation(upgrades(vulns));
    let ignore = {};
    let patch = {};

    if (options.ignore) {
      ignore = ignores.remediation(ignores(vulns, options.ignore));
      vulns = vulns.filter(v => !(v.id in ignore));
    }

    if (options.patch !== false) {
      patch = patches.remediation(patches(vulns));
    }

    for (const u of values(upgrade)) {
      for (let id of u.vulns) {
        delete vulnIds[id];
      }
    }

    for (const id of Object.keys(ignore)) {
      delete vulnIds[id];
    }

    for (const id of Object.keys(patch)) {
      delete vulnIds[id];
    }

    return resolve({
      // send unresolved as an array
      unresolved: values(vulnIds),
      upgrade,
      patch,
      ignore,
    });
  });
}
