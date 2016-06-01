module.exports = remediate;

const upgrades = require('./upgrades');
const patches = require('./patches');

function remediate(vulns) {
  return new Promise(resolve => {
    return resolve({
      upgrade: upgrades.remediation(upgrades(vulns)),
      patch: patches.remediation(patches(vulns)),
    });
  });
}

