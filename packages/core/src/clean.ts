import type {
  AnnotatedLine, AttributionEvidence, AttributionKind, CleanOptions, CleanedFile, FileEntry,
} from './types.ts';

interface CommentSyntax {
  line: string[];
  block: Array<[string, string]>;
  /** 字符串引号字符 */
  quotes: string[];
  /** 三引号（python docstring 按块注释处理，但仅在行首时删除） */
  triple?: string[];
}

const C_LIKE: CommentSyntax = { line: ['//'], block: [['/*', '*/']], quotes: ['"', "'", '`'] };
const SYNTAX_BY_EXT: Record<string, CommentSyntax> = {
  java: C_LIKE, kt: C_LIKE, kts: C_LIKE, js: C_LIKE, jsx: C_LIKE, ts: C_LIKE,
  tsx: C_LIKE, go: C_LIKE, rs: C_LIKE, c: C_LIKE, h: C_LIKE, cpp: C_LIKE,
  hpp: C_LIKE, cc: C_LIKE, cs: C_LIKE, swift: C_LIKE, m: C_LIKE, mm: C_LIKE,
  dart: C_LIKE, scala: C_LIKE,
  py: { line: ['#'], block: [], quotes: ['"', "'"], triple: ['"""', "'''"] },
  rb: { line: ['#'], block: [['=begin', '=end']], quotes: ['"', "'"] },
  sh: { line: ['#'], block: [], quotes: ['"', "'"] },
  php: { line: ['//', '#'], block: [['/*', '*/']], quotes: ['"', "'"] },
  lua: { line: ['--'], block: [['--[[', ']]']], quotes: ['"', "'"] },
  sql: { line: ['--'], block: [['/*', '*/']], quotes: ["'"] },
  html: { line: [], block: [['<!--', '-->']], quotes: ['"', "'"] },
  htm: { line: [], block: [['<!--', '-->']], quotes: ['"', "'"] },
  xml: { line: [], block: [['<!--', '-->']], quotes: ['"', "'"] },
  vue: { line: ['//'], block: [['<!--', '-->'], ['/*', '*/']], quotes: ['"', "'", '`'] },
  css: { line: [], block: [['/*', '*/']], quotes: ['"', "'"] },
  scss: { line: ['//'], block: [['/*', '*/']], quotes: ['"', "'"] },
  less: { line: ['//'], block: [['/*', '*/']], quotes: ['"', "'"] },
};

const MASK_RULES: Array<{ re: RegExp; replace: (m: RegExpExecArray) => string }> = [
  {
    // key = "value" 形式的密钥/口令。用显式前缀词表覆盖 private_key / appSecret / db_passwd 等命名；
    // 不能用 [A-Za-z0-9]+[_-] 这类泛化前缀，否则「private_key」会被拆成 private_ + key 后整体不匹配。
    re: /((?:(?:private|public|secret|access|api|app|db|master|admin|client)[_-]?)?(?:api[_-]?key|key|secret|token|passwd|password|credential)s?\s*[:=]\s*["'])([^"']{4,})(["'])/gi,
    replace: (m) => m[1] + m[2].slice(0, 2) + '****' + m[3],
  },
  {
    // 连接串内嵌密码：scheme://user:password@host。必须排在通用赋值规则之前，
    // 否则 password@host 会先被当成 key:value 吃掉，真正的密码段反而漏脱敏。
    re: /(\b[a-z][a-z0-9+.-]*:\/\/[^\s:/@]+:)([^\s@/]{3,})(@)/gi,
    replace: (m) => m[1] + m[2].slice(0, 2) + '****' + m[3],
  },
  {
    // 未加引号的赋值：YAML「password: xxx」、.env「DB_PASSWORD=xxx」、配置对象「token: xxx」。
    // 只吃单行 token，遇到空白/逗号/分号/右括号即停，避免把后续代码一起吞掉；允许 { } [ ] 包裹。
    re: /((?:api[_-]?key|secret|token|passwd|password|access[_-]?key)[A-Za-z0-9_.-]*\s*[:=]\s*[{\[]?\s*)(?!["'\s])([^\s,;)}\]]{4,})/gi,
    replace: (m) => m[1] + m[2].slice(0, 2) + '****',
  },
  {
    // sk-/ghp_/glpat- 等带分隔符的平台密钥前缀
    re: /\b((?:sk|pk|ghp|gho|glpat)[-_][A-Za-z0-9_-]{8,})\b/g,
    replace: (m) => m[1].slice(0, 5) + '****',
  },
  {
    // AWS AccessKey ID：AKIA/ASIA 后直接跟 16 位大写字母数字，中间没有分隔符，
    // 旧规则要求「AKIA[-_]...」导致真实 Key ID 永远匹配不上。
    re: /\b((?:AKIA|ASIA)[A-Z0-9]{16})\b/g,
    replace: (m) => m[1].slice(0, 4) + '****',
  },
  {
    // 云厂商长密钥：AWS Secret、阿里云/腾讯云 AccessKey Secret。
    // 不能「见到长串就脱敏」——那会误伤 SHA-256 哈希、Base64 常量和长标识符，
    // 所以要求「密钥语境（前缀含 KEY/SECRET/TOKEN/PASSWORD 等词）+ 高熵（字母与数字混合）」。
    re: /((?:KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL|PRIVATE)[A-Z0-9_]*\s*[:=]\s*["']?)(?=[A-Za-z0-9/+]*\d)(?=[A-Za-z0-9/+]*[A-Za-z])[A-Za-z0-9/+]{32,}={0,2}/gi,
    replace: (m) => m[1] + m[0].slice(m[1].length, m[1].length + 4) + '****',
  },
  {
    // 内网 IP
    re: /\b(?:10|192\.168|172\.(?:1[6-9]|2\d|3[01]))(?:\.\d{1,3}){2,3}\b/g,
    replace: () => '10.0.*.*',
  },
  {
    // 大陆身份证号（18 位，末位可为 X）
    re: /\b\d{6}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx]\b/g,
    replace: (m) => m[0].slice(0, 6) + '********' + m[0].slice(14),
  },
  {
    // 大陆手机号
    re: /\b1[3-9]\d{9}\b/g,
    replace: (m) => m[0].slice(0, 3) + '********',
  },
  {
    // 邮箱
    re: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g,
    replace: (m) => m[0][0] + '****@' + (m[0].split('@')[1] ?? ''),
  },
];

const ATTRIBUTION_PATTERNS: Array<{ kind: AttributionKind; re: RegExp }> = [
  { kind: 'author', re: /@author\b\s*[:：]?\s*([^*\r\n]+)/gi },
  {
    kind: 'copyright',
    re: /\bcopyright\b\s*(?:\(c\)|©)?\s*(?:\d{4}(?:\s*[-–—,]\s*\d{2,4})?\s*)?([^*\r\n]+)/gi,
  },
  {
    kind: 'copyright',
    re: /©\s*(?:\d{4}(?:\s*[-–—,]\s*\d{2,4})?\s*)?([^*\r\n]+)/g,
  },
];

function cleanAttributionSubject(value: string): string {
  return value
    .replace(/\s+@(?:since|version|see|param|return|throws?)\b.*$/i, '')
    .replace(/\ball\s+rights\s+reserved\.?\s*$/i, '')
    .replace(/(?:-->|\*\/|\*|#|\/\/)+\s*$/g, '')
    .replace(/^[\s:：,，;；-]+|[\s:：,，;；-]+$/g, '')
    .trim();
}

interface CommentFragment {
  line: number;
  text: string;
  rawLine: string;
}

/**
 * 只返回真正位于注释语法中的片段。署名关键字可能出现在字符串、HTML 文案或
 * 测试数据里；直接扫描整行会把这些普通内容误判为源码署名。
 */
function extractCommentFragments(rawText: string, ext: string): CommentFragment[] {
  const syntax = SYNTAX_BY_EXT[ext.toLowerCase()] ?? C_LIKE;
  const rawLines = rawText.split(/\r\n|\r|\n/);
  const fragments: CommentFragment[] = [];
  let blockClose: string | null = null;
  let tripleClose: string | null = null;
  let multilineStringClose: string | null = null;

  rawLines.forEach((rawLine, lineIndex) => {
    let index = 0;
    let codeBefore = '';
    let inString: string | null = multilineStringClose;

    while (index < rawLine.length) {
      if (blockClose) {
        const closeIndex = rawLine.indexOf(blockClose, index);
        const end = closeIndex === -1 ? rawLine.length : closeIndex + blockClose.length;
        fragments.push({ line: lineIndex + 1, text: rawLine.slice(index, end), rawLine });
        if (closeIndex === -1) return;
        index = end;
        blockClose = null;
        continue;
      }

      if (tripleClose) {
        const closeIndex = rawLine.indexOf(tripleClose, index);
        const end = closeIndex === -1 ? rawLine.length : closeIndex + tripleClose.length;
        fragments.push({ line: lineIndex + 1, text: rawLine.slice(index, end), rawLine });
        if (closeIndex === -1) return;
        index = end;
        tripleClose = null;
        continue;
      }

      const char = rawLine[index];
      if (inString) {
        if (inString.length > 1) {
          if (rawLine.startsWith(inString, index)) {
            index += inString.length;
            inString = null;
            multilineStringClose = null;
          } else {
            index++;
          }
          continue;
        }
        if (char === '\\') {
          index += Math.min(2, rawLine.length - index);
          continue;
        }
        if (char === inString) {
          inString = null;
          multilineStringClose = null;
        }
        index++;
        continue;
      }

      if (syntax.triple) {
        const triple = syntax.triple.find((token) => rawLine.startsWith(token, index));
        if (triple) {
          if (codeBefore.trim() === '') {
            const closeIndex = rawLine.indexOf(triple, index + triple.length);
            const end = closeIndex === -1 ? rawLine.length : closeIndex + triple.length;
            fragments.push({ line: lineIndex + 1, text: rawLine.slice(index, end), rawLine });
            if (closeIndex === -1) {
              tripleClose = triple;
              return;
            }
            index = end;
          } else {
            inString = triple;
            multilineStringClose = triple;
            index += triple.length;
          }
          continue;
        }
      }

      const block = syntax.block.find(([open]) => rawLine.startsWith(open, index));
      if (block) {
        const [open, close] = block;
        const closeIndex = rawLine.indexOf(close, index + open.length);
        const end = closeIndex === -1 ? rawLine.length : closeIndex + close.length;
        fragments.push({ line: lineIndex + 1, text: rawLine.slice(index, end), rawLine });
        if (closeIndex === -1) {
          blockClose = close;
          return;
        }
        index = end;
        continue;
      }

      const lineMarker = syntax.line.find((marker) => rawLine.startsWith(marker, index));
      if (lineMarker) {
        fragments.push({ line: lineIndex + 1, text: rawLine.slice(index), rawLine });
        return;
      }

      if (syntax.quotes.includes(char)) {
        inString = char;
        if (char === '`') multilineStringClose = char;
      }
      codeBefore += char;
      index++;
    }

    if (inString === '`' || (inString && syntax.triple?.includes(inString))) {
      multilineStringClose = inString;
    }
  });

  return fragments;
}

/**
 * 在任何清洗发生前提取署名证据。这里保留原始行与行号，
 * 后续审计再根据最终分页涉及的文件决定证据是否进入报告。
 */
export function extractAttributions(rawText: string, relPath: string, ext = relPath.split('.').pop() ?? ''): AttributionEvidence[] {
  const evidence: AttributionEvidence[] = [];
  const seen = new Set<string>();

  extractCommentFragments(rawText, ext).forEach((fragment) => {
    for (const pattern of ATTRIBUTION_PATTERNS) {
      pattern.re.lastIndex = 0;
      let match: RegExpExecArray | null;
      while ((match = pattern.re.exec(fragment.text)) !== null) {
        const subject = cleanAttributionSubject(match[1] ?? '');
        if (subject && !/^\d{2,4}$/.test(subject)) {
          const key = `${pattern.kind}\0${fragment.line}\0${normalizeEvidenceSubject(subject)}`;
          if (!seen.has(key)) {
            seen.add(key);
            evidence.push({
              kind: pattern.kind,
              subject,
              file: relPath,
              line: fragment.line,
              text: fragment.rawLine,
            });
          }
        }
        if (match[0].length === 0) pattern.re.lastIndex++;
      }
    }
  });

  return evidence;
}

function normalizeEvidenceSubject(value: string): string {
  return value.normalize('NFKC').toLocaleLowerCase().replace(/[\s\p{P}\p{S}]+/gu, '');
}

function maskLine(line: string): { text: string; masked: boolean } {
  let out = line;
  let masked = false;
  for (const rule of MASK_RULES) {
    rule.re.lastIndex = 0;
    let m: RegExpExecArray | null;
    let result = '';
    let last = 0;
    let ruleHit = false;
    while ((m = rule.re.exec(out)) !== null) {
      ruleHit = true;
      result += out.slice(last, m.index) + rule.replace(m);
      last = m.index + m[0].length;
    }
    // 必须按「本条规则是否命中」决定是否重建字符串：
    // 若沿用跨规则的 masked 标志，前一条规则命中会让后续未命中的规则也走重建分支，
    // 用空的 result 拼上 out.slice(0) 虽然当前等价，但一旦 last 语义变化就会静默丢字符。
    if (ruleHit) {
      out = result + out.slice(last);
      masked = true;
    }
  }
  return { text: out, masked };
}

/** 半角宽度折行：CJK 字符按 2 计 */
export function wrapLine(line: string, maxWidth: number): string[] {
  const out: string[] = [];
  let cur = '';
  let w = 0;
  for (const ch of line) {
    const cw = ch.charCodeAt(0) > 0x2e7f ? 2 : 1;
    if (w + cw > maxWidth && cur !== '') {
      out.push(cur);
      cur = '';
      w = 0;
    }
    cur += ch;
    w += cw;
  }
  if (cur !== '' || out.length === 0) out.push(cur);
  return out;
}

/**
 * 逐行清洗：带字符串状态机的注释剥离。
 * 关键点：字符串字面量内的注释符号（如 "https://..."）不会被误删。
 */
export function annotate(rawText: string, ext: string, opts: CleanOptions): AnnotatedLine[] {
  const syntax = SYNTAX_BY_EXT[ext.toLowerCase()] ?? C_LIKE;
  const rawLines = rawText.split(/\r\n|\r|\n/);
  const result: AnnotatedLine[] = [];

  let blockClose: string | null = null; // 处于块注释中时的结束符
  let tripleClose: string | null = null; // python 三引号 docstring
  let multilineStringClose: string | null = null; // 模板字符串或作为值的 python 三引号字符串

  for (const raw of rawLines) {
    const expanded = raw.replace(/\t/g, ' '.repeat(opts.tabWidth));
    let code = '';
    let hadComment = false;
    let i = 0;
    const line = expanded;
    let inString: string | null = multilineStringClose;
    let hadStringContent = multilineStringClose !== null;

    if (tripleClose) {
      const idx = line.indexOf(tripleClose);
      if (idx === -1) {
        result.push({ text: raw, kind: 'comment', masked: false, out: [] });
        continue;
      }
      i = idx + tripleClose.length;
      tripleClose = null;
      hadComment = true;
    }

    scan: while (i < line.length) {
      if (blockClose) {
        const idx = line.indexOf(blockClose, i);
        hadComment = true;
        if (idx === -1) { i = line.length; break; }
        i = idx + blockClose.length;
        blockClose = null;
        continue;
      }
      const ch = line[i];
      if (inString) {
        hadStringContent = true;
        if (inString.length > 1) {
          if (line.startsWith(inString, i)) {
            code += inString;
            i += inString.length;
            inString = null;
            multilineStringClose = null;
          } else {
            code += ch;
            i++;
          }
          continue;
        }
        code += ch;
        if (ch === '\\') {
          if (i + 1 < line.length) { code += line[i + 1]; i += 2; continue; }
        } else if (ch === inString) {
          inString = null;
          multilineStringClose = null;
        }
        i++;
        continue;
      }
      // 三引号开头（python）：行首空白后出现视为 docstring，否则视为字符串
      if (syntax.triple) {
        for (const t of syntax.triple) {
          if (line.startsWith(t, i)) {
            const isDocstring = code.trim() === '';
            const closeIdx = line.indexOf(t, i + t.length);
            if (isDocstring && opts.removeComments) {
              hadComment = true;
              if (closeIdx === -1) { tripleClose = t; i = line.length; } else { i = closeIdx + t.length; }
            } else {
              // 作为普通字符串保留，并把词法状态带到后续行。
              code += t;
              i += t.length;
              inString = t;
              multilineStringClose = t;
              hadStringContent = true;
            }
            continue scan;
          }
        }
      }
      for (const [open, close] of syntax.block) {
        if (line.startsWith(open, i)) {
          hadComment = true;
          const closeIdx = line.indexOf(close, i + open.length);
          if (closeIdx === -1) { blockClose = close; i = line.length; } else { i = closeIdx + close.length; }
          continue scan;
        }
      }
      for (const lc of syntax.line) {
        if (line.startsWith(lc, i)) {
          hadComment = true;
          i = line.length;
          continue scan;
        }
      }
      if (syntax.quotes.includes(ch)) {
        inString = ch;
        if (ch === '`') multilineStringClose = ch;
        hadStringContent = true;
      }
      code += ch;
      i++;
    }

    if (inString === '`' || (inString && syntax.triple?.includes(inString))) {
      multilineStringClose = inString;
    }

    if (!opts.removeComments && hadComment) {
      // 不删注释：原样保留
      const kept = expanded.trimEnd();
      const { text, masked } = opts.maskSensitive ? maskLine(kept) : { text: kept, masked: false };
      const outLines = opts.wrapLongLines ? wrapLine(text, opts.maxLineWidth) : [text];
      result.push({ text: raw, kind: 'code', masked, out: outLines });
      continue;
    }

    const trimmed = code.trimEnd();
    if (trimmed.trim() === '' && !hadStringContent) {
      if (hadComment) {
        result.push({ text: raw, kind: 'comment', masked: false, out: [] });
      } else {
        result.push({
          text: raw, kind: 'blank', masked: false,
          out: opts.removeBlankLines ? [] : [''],
        });
      }
      continue;
    }
    const { text, masked } = opts.maskSensitive ? maskLine(trimmed) : { text: trimmed, masked: false };
    const outLines = opts.wrapLongLines ? wrapLine(text, opts.maxLineWidth) : [text];
    result.push({ text: raw, kind: 'code', masked, out: outLines });
  }
  return result;
}

export function cleanFile(entry: FileEntry, rawText: string, opts: CleanOptions): CleanedFile {
  const attributions = extractAttributions(rawText, entry.relPath, entry.ext);
  const annotated = annotate(rawText, entry.ext, opts);
  const lines: string[] = [];
  let removedComments = 0;
  let removedBlanks = 0;
  let maskedCount = 0;
  for (const a of annotated) {
    if (a.kind === 'comment') removedComments++;
    else if (a.kind === 'blank' && a.out.length === 0) removedBlanks++;
    if (a.masked) maskedCount++;
    lines.push(...a.out);
  }
  return { entry, lines, attributions, removedComments, removedBlanks, maskedCount };
}
