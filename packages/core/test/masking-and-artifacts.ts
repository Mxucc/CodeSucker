import assert from 'node:assert/strict';
import { annotate, DEFAULT_EXCLUDES, defaultCleanOptions, discover, uniqueOutputPath } from '../src/index.ts';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

const opts = { ...defaultCleanOptions(), removeComments: false, removeBlankLines: false, wrapLongLines: false };

function mask(line: string, ext = 'java'): string {
  return annotate(line, ext, opts).map((l) => l.out.join('')).join('');
}

// —— 脱敏：曾经漏掉的形态 ——
const mustMask: Array<[string, RegExp]> = [
  ['password: hunter2value', /hunter2value/],
  ['DB_PASSWORD=s3cretvalue', /s3cretvalue/],
  ['jdbc:mysql://root:p4ssw0rd@10.20.30.40:3306/db', /p4ssw0rd/],
  ['AKIAIOSFODNN7EXAMPLE', /AKIAIOSFODNN7EXAMPLE/],
  ['sk-proj-abcdefghijklmnop', /sk-proj-abcdefghijklmnop/],
  ['private_key = "abcdef123456789"', /abcdef123456789/],
  ['api_key: abcd1234efgh', /abcd1234efgh/],
  ['idCard = "110101199003071234"', /110101199003071234/],
  ['contact: zhangsan@company.com', /zhangsan@company.com/],
];
for (const [line, secret] of mustMask) {
  assert.doesNotMatch(mask(line), secret, `必须脱敏：${line}`);
}

// —— 脱敏：不得误伤正常代码 ——
const mustKeep = [
  'const sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";',
  'private static final long serialVersionUID = 1L;',
  'const base64 = "SGVsbG8gV29ybGQhIFRoaXMgaXMgYSB0ZXN0IHBheWxvYWQ=";',
  'public class InternationalizationConfigurationFactoryBean {}',
  'import org.springframework.web.servlet.DispatcherServlet;',
  'const url = "https://api.example.com/v1/users";',
  'log.info("User authenticated successfully, proceeding");',
];
for (const line of mustKeep) {
  assert.strictEqual(mask(line), line, `不得改动正常代码：${line}`);
}

// —— 多条规则同时命中时不得丢字符 ——
const mixed = 'user=admin@corp.com password={{SECRET_9pn2kxqw}} host=192.168.5.9';
assert.doesNotMatch(mask(mixed), /zhangsan@corp\.com|pass@corp\.com|secretvalue|192\.168\.5\.9/);

// —— 扫描必须排除本工具自己的产物 ——
assert.ok(DEFAULT_EXCLUDES.includes('软著申报'), '默认排除必须包含导出目录');
assert.ok(DEFAULT_EXCLUDES.includes('.codedoc.json'), '默认排除必须包含项目配置文件');

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'codedoc-artifacts-'));
try {
  fs.mkdirSync(path.join(tmp, 'src'), { recursive: true });
  fs.mkdirSync(path.join(tmp, '软著申报'), { recursive: true });
  fs.writeFileSync(path.join(tmp, 'src', 'A.java'), 'class A {}\n');
  fs.writeFileSync(path.join(tmp, '软著申报', 'exported.js'), 'var x = 1;\n');
  fs.writeFileSync(path.join(tmp, '.codedoc.json'), '{"title":"x"}\n');
  const found = discover(tmp, ['java', 'js'], DEFAULT_EXCLUDES).map((f) => f.relPath);
  assert.deepStrictEqual(found, ['src/A.java'], `导出目录不得被重新扫描收录，实际：${found.join(',')}`);
} finally {
  fs.rmSync(tmp, { recursive: true, force: true });
}

// —— 重复导出不得静默覆盖 ——
const outDir = fs.mkdtempSync(path.join(os.tmpdir(), 'codedoc-unique-'));
try {
  const first = uniqueOutputPath(outDir, '源程序_测试V1.0', '.docx');
  fs.writeFileSync(first, 'v1');
  const second = uniqueOutputPath(outDir, '源程序_测试V1.0', '.docx');
  fs.writeFileSync(second, 'v2');
  const third = uniqueOutputPath(outDir, '源程序_测试V1.0', '.docx');
  assert.notStrictEqual(first, second, '第二次导出必须换名');
  assert.notStrictEqual(second, third, '第三次导出必须换名');
  assert.strictEqual(fs.readFileSync(first, 'utf8'), 'v1', '第一次导出的内容不得被覆盖');
  assert.strictEqual(path.basename(second), '源程序_测试V1.0_2.docx');
} finally {
  fs.rmSync(outDir, { recursive: true, force: true });
}

void fileURLToPath;
console.log('✅ 脱敏与产物命名回归全部通过');
