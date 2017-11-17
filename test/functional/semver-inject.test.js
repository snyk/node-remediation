const test = require('tap').test;
const sinon = require('sinon');
const lib = require('../../');

test('inject semver', t => {
  const customSemver = {
    satisfies() { return true; },
    compare() { return 0; },
  };
  const satisfies = sinon.spy(customSemver, 'satisfies');
  const compare = sinon.spy(customSemver, 'compare');
  const vulns = require(`../fixtures/jsbin.json`);
  const expect = require(`../fixtures/jsbin-expect.json`);
  return lib(vulns.vulnerabilities, { semver: customSemver })
    .then(() => {
      t.ok(satisfies.called, 'called `satisfies` on injected semver');
      t.ok(compare.called, 'called `compare` on injected semver');
    });
})
