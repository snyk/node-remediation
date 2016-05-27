module.exports = stripVersions;

const moduleToObject = require('snyk-module');

function stripVersions(packages) {
  return packages.map(pkg => moduleToObject(pkg).name);
}
