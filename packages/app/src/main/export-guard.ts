import type { Selection } from '@codedoc/core';

type ExportableSelection = Pick<Selection, 'pages' | 'totalLines' | 'pickedLines'>;

/**
 * 末页至少需要的行数：与 core/audit.ts 的 2/3 提示保持同一阈值。
 * 按产品契约（README、docs/02）末页 2/3 属于「警告」而非「退回风险」，
 * 因此这里只提供阈值给界面提示复用，不作为导出阻断条件。
 */
export function minimumLastPageLines(linesPerPage: number): number {
  return Math.ceil((linesPerPage * 2) / 3);
}

export function assertExportableSelection(selection: ExportableSelection): void {
  if (selection.pages.length === 0 || selection.totalLines === 0 || selection.pickedLines === 0) {
    throw new Error('没有可导出的代码内容，请调整文件选择或清洗规则后重试');
  }
}
