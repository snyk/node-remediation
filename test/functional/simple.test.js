const test = require('tap-only');
const lib = require('../../');
const MockDate = require('mockdate');

// force the date to pin to this when we generate patches
MockDate.set('2000-09-13 04:00:00.007Z');

test('simple tests', t => {
  return Promise.all(['goof', 'jsbin'].map(name => {
    const vulns = require(`../fixtures/${name}.json`);
    const expect = require(`../fixtures/${name}-expect.json`);

    t.test(name, t => {
      return lib(vulns.vulnerabilities).then(res => {
        t.deepEqual(res, expect);
      });
    });
  }));
});
