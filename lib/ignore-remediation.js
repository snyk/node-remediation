'use strict';
module.exports = remediation;

const moduleToObject = require('snyk-module');
const ONE_DAY = 1000 * 60 * 60 * 24;

function remediation(vulns) {
  return vulns.reduce((acc, curr) => {
    const id = curr.id;
    if (!(id in acc)) {
      acc[id] = {
        paths: [],
      };
    }
    const days = curr.meta.days || 30;
    acc[id].paths.push(
      pathRule(curr,
               curr.meta.reason || 'None given',
               new Date(Date.now() + (ONE_DAY * days)).toJSON()));
    return acc;
  }, {});
}

function pathRule(vuln, reason, expires) {
  return {
    [vuln.from.slice(1).map(pkg => moduleToObject(pkg).name).join(' > ')]: {
      reason,
      expires,
    },
  };
}