const lib = require('../lib');
const vulns = require('../test/fixtures/goof.json');

module.exports = function (args, settings, body) {
  if (!body) {
    body = vulns;
  } else {
    body = JSON.parse(body);
  }

  return lib(body.vulnerabilities).then(res => JSON.stringify(res, '', 2));
};
