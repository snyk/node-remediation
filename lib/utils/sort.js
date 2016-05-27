'use strict';
module.exports = sort;

function sort(prop) {
  let sortOrder = 1;
  if (prop[0] === '-') {
    sortOrder = -1;
    prop = prop.substr(1);
  }

  return (a, b) => {
    let result = (a[prop] < b[prop]) ? -1 : (a[prop] > b[prop]) ? 1 : 0;
    return result * sortOrder;
  };
}
