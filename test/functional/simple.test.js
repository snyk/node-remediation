const test = require('tap-only');
const lib = require('../../');
const MockDate = require('mockdate');

// force the date to pin to this when we generate patches
MockDate.set('2000-09-13 04:00:00.007Z');

test('simple tests', t => {
  return Promise.all(['goof', 'jsbin', 'mean', 'vuln-test'].map(name => {
    const vulns = require(`../fixtures/${name}.json`);
    const expect = require(`../fixtures/${name}-expect.json`);

    const unresolved = {
      jsbin: 12,
      mean: 0,
      goof: 1,
      'vuln-test': 0,
    };

    t.test(name, t => {
      return lib(vulns.vulnerabilities, name === 'vuln-test' ? {
        ignore: {
          'npm:gmail-js:20160721': {
            paths: [
              ['fiction@0.2.0', 'gmail-js@0.5.0'],
            ],
            meta: {
              reason: 'no fix',
            },
          },
        },
      } : {}).then(res => {
        t.deepEqual({
          upgrade: res.upgrade,
          patch: res.patch,
          ignore: res.ignore,
        }, expect);
        if (unresolved[name] !== null) {
          t.equal(res.unresolved.length, unresolved[name]);
        }
      });
    });
  }));
});

test('do not patch', t => {
  const name = 'goof';
  const vulns = require(`../fixtures/${name}.json`);
  const expect = require(`../fixtures/${name}-expect.json`);

  const unresolved = {
    goof: 3,
  };

  return t.test(name, t => {
    return lib(vulns.vulnerabilities, { patch: false }).then(res => {
      t.deepEqual({ upgrade: res.upgrade, patch: res.patch }, {
        upgrade: expect.upgrade,
        patch: {},
      });

      if (unresolved[name] !== null) {
        t.equal(res.unresolved.length, unresolved[name]);
      }
    });
  });
});

test('early exit', t => {
  return lib().then(res => {
    t.deepEqual(res, { unresolved: [], upgrade: {}, patch: {}, ignore: {} });
  });
});
