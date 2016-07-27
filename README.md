# node-remediation

Given a snyk test JSON source, create all the possible remediation paths, and optionally return the *best* remediation (where all vulns is fixed).

**Note that this project is developed using Node @ 6**

The deployed version (in [npm](https://npmjs.com/snyk-remediation/)) is compatible with node@0.10 upwards.

## Usage


```js
const remediation = require('snyk-remediation');
const fixes = remediation(vulns);

// list of upgrades
console.log(fixes.upgrade);

// list of patches
console.log(fixes.patch);

// list of vulns that have no possible remediation
console.log(fixes.unresolved);
```

This can also be used on the command line to experiment with:

```bash
$ snyk test snyk/goof --json | node cli
{
  "unresolved": [],
  "upgrade": {
    "errorhandler@1.2.0": {
      "upgradeTo": "errorhandler@1.4.3",
      "upgrades": [
        "negotiator@0.4.9"
      ],
      "vulns": [
        "npm:negotiator:20160616"
      ]
    },
…
```

**Important** the default usage (both on the CLI and in the module) is to return the best remediation.

## How to test

There are no external dependencies, only to install the development dependencies and run `npm test`.

## License

* [License: Apache License, Version 2.0](LICENSE)
