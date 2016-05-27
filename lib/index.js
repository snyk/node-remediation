module.exports = remediate;

const upgrades = require('./upgrades');
const patches = require('./patches');

function remediate(vulns) {
  return new Promise(resolve => {
    return resolve({
      upgrades: upgrades.remediation(upgrades(vulns)),
      patches: patches.remediation(patches(vulns)),
    });
  });
}

