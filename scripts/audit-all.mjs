#!/usr/bin/env node
/**
 * 全量依赖审计（生产 + 开发）。
 *
 * 存在两条无法在不引入破坏性变更的前提下消除的告警：
 *
 *   1. braces <= 3.0.3  →  micromatch  →  fast-glob
 *      公告 GHSA-vfj7-8cjw-p6xm：深度嵌套 glob 模式可导致栈溢出（DoS）
 *      上游没有任何已修复版本（npm audit 报 No fix available）。
 *      该模式串只来自用户本机填写的排除规则，应用完全离线，不构成远程可利用面。
 *
 *   2. sprintf-js → roarr → global-agent → @electron/get → app-builder-lib → electron-builder
 *      公告 GHSA-hp3w-g68c-fv3c：无界精度修饰符可导致 DoS。
 *      整条链只在 electron-builder 打包阶段使用，不进应用运行时。
 *
 * 豁免必须显式登记，且脚本会校验实际告警是否**超出**清单——
 * 一旦引入新的高危依赖会立即失败，避免豁免演变成无限制放宽。
 */
import { execFileSync } from 'node:child_process';

const ALLOWED = new Set([
  // braces 传递链（生产依赖，无修复）
  'braces', 'micromatch', 'fast-glob',
  // electron-builder 打包链（仅构建期）
  'sprintf-js', 'roarr', 'global-agent', '@electron/get',
  'app-builder-lib', 'dmg-builder', 'electron-builder', 'electron-builder-squirrel-windows',
]);

function auditJson() {
  try {
    // 非 0 退出码在有漏洞时是预期行为，需要读取 stdout 而不是当作失败。
    return execFileSync('npm', ['audit', '--json'], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
      maxBuffer: 32 * 1024 * 1024,
    });
  } catch (error) {
    if (typeof error.stdout === 'string' && error.stdout.trim().startsWith('{')) return error.stdout;
    throw error;
  }
}

const report = JSON.parse(auditJson());
const advisories = Object.values(report.vulnerabilities ?? {});

const unexpected = advisories.filter((item) => !ALLOWED.has(item.name));
const stale = [...ALLOWED].filter((name) => !advisories.some((item) => item.name === name));

for (const name of stale) {
  console.log(`ℹ️  豁免项已不再告警，可从清单移除：${name}`);
}

if (unexpected.length > 0) {
  console.error('❌ 发现未登记的依赖漏洞：');
  for (const item of unexpected) {
    const titles = item.via
      .map((v) => (typeof v === 'string' ? v : v.title))
      .join('; ');
    console.error(`   - ${item.name}（${item.severity}）：${titles}`);
  }
  process.exit(1);
}

console.log(`✓ 依赖审计通过：${advisories.length} 条已知告警，全部在豁免清单内`);
