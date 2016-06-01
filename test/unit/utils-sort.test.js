const test = require('tap-only');
const sort = require('../../lib/utils/sort');

test('utils.sort (asc)', t => {
  const fn = sort('age');

  const cats = Array.from({ length: 3 }).map((_, n) => ({ age: n }));

  t.deepEqual(cats, cats.sort(fn));
  t.end();
});

test('utils.sort (desc)', t => {
  const fn = sort('-age');

  const cats = Array.from({ length: 3 }).map((_, n) => ({ age: n }));

  t.deepEqual(Array.from(cats).reverse(), cats.sort(fn));
  t.end();
});
