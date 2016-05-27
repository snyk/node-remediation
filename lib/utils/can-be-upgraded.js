module.exports = canBeUpgraded;

function canBeUpgraded(vuln) {
  if (vuln.bundled) {
    return false;
  }

  if (vuln.shrinkwrap) {
    return false;
  }

  return vuln.upgradePath.some((pkg, i) => {
    // if the upgade path is to upgrade the module to the same range the
    // user already asked for, then it means we need to just blow that
    // module away and re-install
    if (vuln.from.length > i && pkg === vuln.from[i]) {
      return true;
    }

    // if the upgradePath contains the first two elements, that is
    // the project itself (i.e. jsbin) then the direct dependency can be
    // upgraded. Note that if the first two elements
    if (vuln.upgradePath.slice(0, 2).filter(Boolean).length) {
      return true;
    }
  });
}
