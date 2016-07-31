'use strict';
module.exports = ignore;
module.exports.remediation = require('./ignore-remediation');

const stripVersions = require('./utils/strip-versions');

const joinPath = p => p.join(' > ');

function ignore(vulns, ignoredPaths) {
  const pathsById = Object.keys(ignoredPaths).reduce((paths, id) => {
    paths[id] = new Set(ignoredPaths[id].paths
      .map(stripVersions)
      .map(joinPath));
    return paths;
  }, {});
  return vulns.filter(
    v => v.id in pathsById && pathsById[v.id].has(
      joinPath(stripVersions(v.from.slice(1))))
  ).map(v => ({
    id: v.id,
    from: v.from,
    meta: ignoredPaths[v.id].meta,
  }));
}