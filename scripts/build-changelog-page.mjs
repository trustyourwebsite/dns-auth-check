#!/usr/bin/env node
// Deterministic GitLab Pages changelog + quickstart builder.
// Zero dependencies — Node 22 built-ins only. Parses CHANGELOG.md and
// README.md with plain line regexes (no markdown library) and emits
// public/index.html. Exits 1 if CHANGELOG.md yields zero versions.
import { readFileSync, mkdirSync, writeFileSync } from 'node:fs';

const read = (p) => readFileSync(new URL(`./${p}`, `file://${process.cwd()}/`), 'utf8');

// --- inputs -----------------------------------------------------------------
const pkg = JSON.parse(read('package.json'));
const fullName = pkg.name;                       // @trustyourwebsite/<slug>
const slug = fullName.split('/')[1] || fullName; // <slug>
const version = pkg.version;
const description = pkg.description || '';
const installCmd = `npm install -g ${fullName}`;

const canonical = `https://trustyourwebsite.gitlab.io/${slug}/`;
const githubUrl = `https://github.com/trustyourwebsite/${slug}`;
const npmUrl = `https://www.npmjs.com/package/${fullName}`;

// --- helpers ----------------------------------------------------------------
function escapeHtml(s) {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

// Minimal inline markdown: escape first, then code / links / bold.
function inline(s) {
  let out = escapeHtml(s);
  out = out.replace(/`([^`]+)`/g, (_, c) => `<code>${c}</code>`);
  out = out.replace(/\[([^\]]+)\]\((https?:\/\/[^)]+)\)/g, (_, t, u) => `<a href="${u}">${t}</a>`);
  out = out.replace(/\*\*([^*]+)\*\*/g, (_, b) => `<strong>${b}</strong>`);
  return out;
}

function cmpVer(a, b) {
  const pa = a.split('.').map(Number);
  const pb = b.split('.').map(Number);
  for (let i = 0; i < 3; i++) {
    if ((pa[i] || 0) !== (pb[i] || 0)) return (pb[i] || 0) - (pa[i] || 0);
  }
  return 0;
}

// Parse `## [x.y.z] - date` sections into ordered blocks (subheads, bullets, prose).
function parseChangelog(md) {
  const lines = md.split(/\r?\n/);
  const versions = [];
  let cur = null;
  const headRe = /^##\s+\[?(\d+\.\d+\.\d+)\]?\s*[—–-]\s*(\d{4}-\d{2}-\d{2})/;
  for (const line of lines) {
    const m = line.match(headRe);
    if (m) {
      cur = { version: m[1], date: m[2], blocks: [] };
      versions.push(cur);
      continue;
    }
    if (!cur) continue;
    const sub = line.match(/^###\s+(.+?)\s*$/);
    if (sub) { cur.blocks.push({ type: 'group', text: sub[1] }); continue; }
    const bullet = line.match(/^[-*]\s+(.+?)\s*$/);
    if (bullet) { cur.blocks.push({ type: 'item', text: bullet[1] }); continue; }
    const text = line.trim();
    if (text) cur.blocks.push({ type: 'para', text });
  }
  versions.sort((a, b) => cmpVer(a.version, b.version));
  return versions;
}

function renderBlocks(blocks) {
  let html = '';
  let inList = false;
  const closeList = () => { if (inList) { html += '      </ul>\n'; inList = false; } };
  for (const b of blocks) {
    if (b.type === 'group') { closeList(); html += `      <h3>${escapeHtml(b.text)}</h3>\n`; }
    else if (b.type === 'item') {
      if (!inList) { html += '      <ul>\n'; inList = true; }
      html += `        <li>${inline(b.text)}</li>\n`;
    } else if (b.type === 'para') { closeList(); html += `      <p class="note">${inline(b.text)}</p>\n`; }
  }
  closeList();
  return html;
}

// First fenced code block after an Install / Usage / Quick Start heading.
function extractQuickstart(md) {
  const lines = md.split(/\r?\n/);
  let capture = false, inFence = false, lang = '', buf = [];
  for (const line of lines) {
    const h = line.match(/^##\s+(.+)/);
    if (h) { capture = /install|usage|quick\s*start/i.test(h[1]); continue; }
    if (!capture) continue;
    const f = line.match(/^```(\w*)/);
    if (f && !inFence) { inFence = true; lang = f[1] || ''; buf = []; continue; }
    if (inFence && /^```/.test(line)) return { lang, code: buf.join('\n') };
    if (inFence) buf.push(line);
  }
  return null;
}

// --- build ------------------------------------------------------------------
const versions = parseChangelog(read('CHANGELOG.md'));
if (versions.length === 0) {
  console.error('build-changelog-page: CHANGELOG.md yielded zero versions — refusing to ship an empty page.');
  process.exit(1);
}
const latest = versions[0].version;
const quickstart = extractQuickstart(read('README.md'));

const changelogHtml = versions.map((v) => `    <section class="release">
      <h2 id="v${v.version}">${escapeHtml(v.version)} <span class="date">${escapeHtml(v.date)}</span></h2>
${renderBlocks(v.blocks)}    </section>`).join('\n');

const quickstartCode = quickstart
  ? `${installCmd}\n\n${quickstart.code}`
  : installCmd;

const title = `${slug} changelog — all releases`;
const metaDesc = `Release history and quickstart for ${fullName} (latest v${latest}). ${description}`.slice(0, 158);

const html = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${escapeHtml(title)}</title>
  <meta name="description" content="${escapeHtml(metaDesc)}">
  <meta name="robots" content="index, follow">
  <link rel="canonical" href="${canonical}">
  <style>
    :root {
      --bg: #0b1020; --panel: #131a33; --ink: #e7ecf7; --muted: #98a2c2;
      --accent: #6ee7b7; --accent-ink: #052e1a; --border: #232b4a; --code-bg: #0a0f23;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0; background: var(--bg); color: var(--ink);
      font: 16px/1.6 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
    }
    .wrap { max-width: 760px; margin: 0 auto; padding: 48px 20px 80px; }
    a { color: var(--accent); }
    header h1 { font-size: 1.9rem; margin: 0 0 .4rem; letter-spacing: -.01em; }
    .intro { color: var(--muted); margin: 0 0 1.4rem; }
    .meta-links { margin: 0 0 2rem; font-size: .95rem; }
    .meta-links a { margin-right: 1rem; }
    h2 { font-size: 1.25rem; margin: 2rem 0 .6rem; border-bottom: 1px solid var(--border); padding-bottom: .35rem; }
    h2 .date { color: var(--muted); font-size: .85rem; font-weight: 400; margin-left: .5rem; }
    h3 { font-size: .8rem; text-transform: uppercase; letter-spacing: .06em; color: var(--accent); margin: 1rem 0 .3rem; }
    ul { margin: .3rem 0 .8rem; padding-left: 1.2rem; }
    li { margin: .25rem 0; }
    p.note { color: var(--muted); font-size: .95rem; }
    code { background: var(--code-bg); border: 1px solid var(--border); border-radius: 4px; padding: .1rem .35rem; font: .85em ui-monospace, SFMono-Regular, Menlo, monospace; }
    pre { background: var(--code-bg); border: 1px solid var(--border); border-radius: 8px; padding: 1rem; overflow-x: auto; }
    pre code { background: none; border: 0; padding: 0; }
    .panel { background: var(--panel); border: 1px solid var(--border); border-radius: 10px; padding: 1.2rem 1.4rem; margin: 0 0 2rem; }
    footer { margin-top: 3rem; padding-top: 1.4rem; border-top: 1px solid var(--border); color: var(--muted); font-size: .9rem; }
  </style>
</head>
<body>
  <div class="wrap">
    <header>
      <h1>${escapeHtml(fullName)}</h1>
      <p class="intro">Release history for ${escapeHtml(fullName)}, maintained by <a href="https://trustyourwebsite.com">TrustYourWebsite</a>.</p>
      <p class="meta-links">
        <a href="${githubUrl}">GitHub repository</a>
        <a href="${npmUrl}">npm package</a>
      </p>
    </header>

    <section class="panel">
      <h2 style="border:0;margin-top:0">Quickstart</h2>
      <pre><code>${escapeHtml(quickstartCode)}</code></pre>
    </section>

    <h2 style="border:0">Changelog</h2>
${changelogHtml}

    <footer>
      Maintained by <a href="https://trustyourwebsite.com">trustyourwebsite.com</a>.
    </footer>
  </div>
</body>
</html>
`;

mkdirSync(new URL('./public/', `file://${process.cwd()}/`), { recursive: true });
writeFileSync(new URL('./public/index.html', `file://${process.cwd()}/`), html);
console.log(`build-changelog-page: wrote public/index.html for ${fullName} v${latest} (${versions.length} releases).`);
