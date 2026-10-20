import assert from 'node:assert/strict';
import { assertExportableSelection, minimumLastPageLines } from '../src/main/export-guard.ts';

const LPP = 60;

assert.throws(
  () => assertExportableSelection({ pages: [], totalLines: 0, pickedLines: 0 }),
  /没有可导出的代码内容/,
);

assert.strictEqual(minimumLastPageLines(60), 40, '60 行/页的 2/3 应为 40 行');
assert.strictEqual(minimumLastPageLines(50), 34, '50 行/页的 2/3 应向上取整为 34 行');

// 末页 2/3 是「警告」级提示，不是退回风险：即使末页很短也必须允许导出。
assert.doesNotThrow(() => assertExportableSelection({
  pages: [
    { no: 1, lines: Array.from({ length: LPP }, (_, i) => `line${i}`), startFile: 'a.ts', endFile: 'a.ts' },
    { no: 2, lines: ['const ok = true;'], startFile: 'main.ts', endFile: 'main.ts' },
  ],
  totalLines: LPP + 1,
  pickedLines: LPP + 1,
}), '末页过短只提示，不得阻断导出');

// 单页的小项目同样必须能导出。
assert.doesNotThrow(() => assertExportableSelection({
  pages: [{ no: 1, lines: ['const ok = true;'], startFile: 'main.ts', endFile: 'main.ts' }],
  totalLines: 1,
  pickedLines: 1,
}), '单页材料必须允许导出');

console.log('✅ export guard 全部通过');
