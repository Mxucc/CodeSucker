#!/usr/bin/env node
/**
 * 生产依赖审计。
 *
 * 存在一条无法通过升级消除的告警：
 *   braces <= 3.0.3（链：fast-glob -> micromatch -> braces）
 *   公告 GHSA-vfj7-8cjw-p6xm：深度嵌套 glob 模式可导致栈溢出（DoS）
 *   上游至今没有任何已修复版本（npm audit 报 No fix available）。
 *
 * 风险判断：该模式串只来自用户在本机填写的排除规则，不来自网络或第三方输入，
 * 且应用完全离线运行，因此不构成远程可利用面。但告警本身不能被静默忽略，
 * 必须显式登记在白名单里，并校验「实际告警是否超出白名单」——
 * 一旦出现新的高危依赖，此脚本会失败，避免豁免演变成无限制放宽。
 */
import { execFileSync } from 'node:child_process';

const ALLOWED = new Set(['braces', 'micromatch', 'fast-glob']);

function auditJson() {
  try {
    // 非 0 退出码在有漏洞时是预期行为，需要读取 stdout 而不是当作失败。
    return execFileSync('npm', ['audit', '--omit=dev', '--json'], {
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
const advisories = Object.values(report.vulnerabilities ?? {})
  .filter((item) => item.severity === 'high' || item.severity === 'critical');

const unexpected = advisories.filter((item) => !ALLOWED.has(item.name));
const allowed = advisories.filter((item) => ALLOWED.has(item.name));

for (const item of allowed) {
  console.log(`⚠️  已登记豁免：${item.name}（${item.severity}）— 见 scripts/audit-runtime.mjs 注释`);
}

if (unexpected.length > 0) {
  console.error('❌ 发现未登记的生产依赖高危漏洞：');
  for (const item of unexpected) {
    console.error(`   - ${item.name}（${item.severity}）：${item.via?.map((v) => (typeof v === 'string' ? v : v.title)).join('; ')}`);
  }
  process.exit(1);
}

console.log(`✓ 生产依赖审计通过：${advisories.length} 条已知告警，全部在豁免清单内`);
