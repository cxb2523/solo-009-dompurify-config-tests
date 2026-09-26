/* jshint node: true, esnext: true */
/* global QUnit */
'use strict';

// Fine-grained regression tests for DOMPurify configuration options,
// running under Node.js + jsdom only (no browser required).
//
// Self-contained runner: the jsdom assembly mirrors test/jsdom-node.js and
// the TAP reporting mirrors test/jsdom-node-runner.js, so this file can be
// executed directly with `node test/jsdom-node-config`.

global.QUnit = require('qunit');

const qunitTap = require('qunit-tap');
const argument = process.argv[2];

qunitTap(QUnit, (line) => {
  if (/^not ok/.test(line)) {
    process.exitCode = 1;
    return console.log('\n', line);
  }

  if (argument === '--dot') {
    return process.stdout.write('.');
  }

  console.log(line);
});

const createDOMPurify = require(
  process.env.DOMPURIFY_COV ? '../dist/purify.cov.cjs' : '../dist/purify.cjs'
);
const jsdom = require('jsdom');
const { JSDOM, VirtualConsole } = jsdom;
const virtualConsole = new VirtualConsole();
const { window } = new JSDOM(
  `<html><head></head><body><div id="qunit-fixture"></div></body></html>`,
  { runScripts: 'dangerously', virtualConsole }
);

// Every test builds its own DOMPurify instance so that per-instance state
// (hooks, persisted config) can never leak between tests, regardless of the
// order QUnit happens to run them in.
const purify = () => createDOMPurify(window);

QUnit.config.autostart = false;

QUnit.module('DOMPurify config - ALLOWED_TAGS / ALLOWED_ATTR');

QUnit.test('ALLOWED_TAGS keeps only whitelisted tags', (assert) => {
  const DOMPurify = purify();
  const dirty =
    '<div><b>bold</b><script>alert(1)</script><span>text</span></div>';
  const config = { ALLOWED_TAGS: ['b'] };
  // <div>/<span> are unwrapped (children kept), <script> is dropped with its
  // contents because it is in the default FORBID_CONTENTS set.
  const expected = '<b>bold</b>text';
  assert.strictEqual(
    DOMPurify.sanitize(dirty, config),
    expected,
    `ALLOWED_TAGS whitelist -> input: ${dirty} | config: ${JSON.stringify(
      config
    )} | expected: ${expected}`
  );
});

QUnit.test('ALLOWED_ATTR keeps only whitelisted attributes', (assert) => {
  const DOMPurify = purify();
  const dirty = '<p title="t" class="c" id="i">x</p>';
  const config = { ALLOWED_ATTR: ['title'] };
  const expected = '<p title="t">x</p>';
  assert.strictEqual(
    DOMPurify.sanitize(dirty, config),
    expected,
    `ALLOWED_ATTR whitelist -> input: ${dirty} | config: ${JSON.stringify(
      config
    )} | expected: ${expected}`
  );
});

QUnit.module('DOMPurify config - FORBID_* vs ALLOWED_* overlap');

QUnit.test('FORBID_TAGS wins over ALLOWED_TAGS on overlap', (assert) => {
  const DOMPurify = purify();
  const dirty = '<b>1</b><i>2</i>';
  const config = { ALLOWED_TAGS: ['b', 'i'], FORBID_TAGS: ['b'] };
  // Actual implementation behavior: when a tag is listed in both ALLOWED_TAGS
  // and FORBID_TAGS, FORBID_TAGS takes precedence and the tag is removed
  // (src/purify.ts removes elements matching
  // `!ALLOWED_TAGS[tagName] || FORBID_TAGS[tagName]`).
  const expected = '1<i>2</i>';
  assert.strictEqual(
    DOMPurify.sanitize(dirty, config),
    expected,
    `FORBID_TAGS beats ALLOWED_TAGS -> input: ${dirty} | config: ${JSON.stringify(
      config
    )} | expected: ${expected}`
  );
});

QUnit.test('FORBID_ATTR wins over ALLOWED_ATTR on overlap', (assert) => {
  const DOMPurify = purify();
  const dirty = '<p title="t" class="c">x</p>';
  const config = { ALLOWED_ATTR: ['title', 'class'], FORBID_ATTR: ['class'] };
  // Same precedence rule as for tags: FORBID_ATTR overrides ALLOWED_ATTR.
  const expected = '<p title="t">x</p>';
  assert.strictEqual(
    DOMPurify.sanitize(dirty, config),
    expected,
    `FORBID_ATTR beats ALLOWED_ATTR -> input: ${dirty} | config: ${JSON.stringify(
      config
    )} | expected: ${expected}`
  );
});

QUnit.module('DOMPurify config - ALLOW_DATA_ATTR / ALLOW_ARIA_ATTR');

QUnit.test('data-* and aria-* are allowed by default', (assert) => {
  const DOMPurify = purify();
  const dirty = '<p data-x="1" aria-label="a">x</p>';
  // Both ALLOW_DATA_ATTR and ALLOW_ARIA_ATTR default to true.
  const expected = '<p data-x="1" aria-label="a">x</p>';
  assert.strictEqual(
    DOMPurify.sanitize(dirty),
    expected,
    `defaults -> input: ${dirty} | config: {} | expected: ${expected}`
  );
});

QUnit.test('ALLOW_DATA_ATTR: false strips data-* but keeps aria-*', (assert) => {
  const DOMPurify = purify();
  const dirty = '<p data-x="1" aria-label="a">x</p>';
  const config = { ALLOW_DATA_ATTR: false };
  const expected = '<p aria-label="a">x</p>';
  assert.strictEqual(
    DOMPurify.sanitize(dirty, config),
    expected,
    `ALLOW_DATA_ATTR off -> input: ${dirty} | config: ${JSON.stringify(
      config
    )} | expected: ${expected}`
  );
});

QUnit.test('ALLOW_ARIA_ATTR: false strips aria-* but keeps data-*', (assert) => {
  const DOMPurify = purify();
  const dirty = '<p data-x="1" aria-label="a">x</p>';
  const config = { ALLOW_ARIA_ATTR: false };
  const expected = '<p data-x="1">x</p>';
  assert.strictEqual(
    DOMPurify.sanitize(dirty, config),
    expected,
    `ALLOW_ARIA_ATTR off -> input: ${dirty} | config: ${JSON.stringify(
      config
    )} | expected: ${expected}`
  );
});

QUnit.module('DOMPurify config - SANITIZE_DOM / SANITIZE_NAMED_PROPS');

QUnit.test('SANITIZE_DOM (default) drops id/name that clobber DOM', (assert) => {
  const DOMPurify = purify();
  const dirty = '<a id="getElementById" name="plain">x</a>';
  // SANITIZE_DOM defaults to true: an id/name whose value exists on
  // `document` (here `getElementById`) is removed; harmless values stay.
  const expected = '<a name="plain">x</a>';
  assert.strictEqual(
    DOMPurify.sanitize(dirty),
    expected,
    `SANITIZE_DOM default -> input: ${dirty} | config: {} | expected: ${expected}`
  );
});

QUnit.test('SANITIZE_DOM: false keeps clobbering id/name', (assert) => {
  const DOMPurify = purify();
  const dirty = '<a id="getElementById" name="plain">x</a>';
  const config = { SANITIZE_DOM: false };
  const expected = '<a id="getElementById" name="plain">x</a>';
  assert.strictEqual(
    DOMPurify.sanitize(dirty, config),
    expected,
    `SANITIZE_DOM off -> input: ${dirty} | config: ${JSON.stringify(
      config
    )} | expected: ${expected}`
  );
});

QUnit.test('SANITIZE_NAMED_PROPS prefixes id/name with user-content-', (assert) => {
  const DOMPurify = purify();
  const dirty = '<p id="foo">x</p><a name="bar">y</a>';
  const config = { SANITIZE_NAMED_PROPS: true };
  const expected =
    '<p id="user-content-foo">x</p><a name="user-content-bar">y</a>';
  assert.strictEqual(
    DOMPurify.sanitize(dirty, config),
    expected,
    `SANITIZE_NAMED_PROPS on -> input: ${dirty} | config: ${JSON.stringify(
      config
    )} | expected: ${expected}`
  );
});

QUnit.test('SANITIZE_NAMED_PROPS defaults to off (id/name untouched)', (assert) => {
  const DOMPurify = purify();
  const dirty = '<p id="foo">x</p><a name="bar">y</a>';
  const expected = '<p id="foo">x</p><a name="bar">y</a>';
  assert.strictEqual(
    DOMPurify.sanitize(dirty),
    expected,
    `SANITIZE_NAMED_PROPS default -> input: ${dirty} | config: {} | expected: ${expected}`
  );
});

QUnit.module('DOMPurify config - RETURN_DOM / RETURN_TRUSTED_TYPE');

QUnit.test('RETURN_DOM returns the sanitized <body> element node', (assert) => {
  const DOMPurify = purify();
  const dirty = '<b>x</b><script>alert(1)</script>';
  const config = { RETURN_DOM: true };
  const result = DOMPurify.sanitize(dirty, config);
  // Actual implementation behavior: RETURN_DOM does NOT return a
  // DocumentFragment. It returns the <body> element (nodeType 1) of the
  // separate inert document DOMPurify parses into (src/purify.ts:
  // `returnNode = body`). A real DocumentFragment is only produced by
  // RETURN_DOM_FRAGMENT.
  assert.strictEqual(
    result.nodeType,
    1,
    `RETURN_DOM nodeType -> input: ${dirty} | config: ${JSON.stringify(
      config
    )} | expected: 1 (Element: the <body> wrapper, not a DocumentFragment)`
  );
  assert.strictEqual(
    result.nodeName,
    'BODY',
    `RETURN_DOM nodeName -> input: ${dirty} | expected: BODY`
  );
  assert.notStrictEqual(
    result.ownerDocument,
    window.document,
    'RETURN_DOM node belongs to a separate inert document, not the jsdom window document'
  );
  assert.strictEqual(
    result.innerHTML,
    '<b>x</b>',
    `RETURN_DOM content -> input: ${dirty} | expected innerHTML: <b>x</b>`
  );
});

QUnit.test('RETURN_TRUSTED_TYPE falls back to string without Trusted Types', (assert) => {
  const DOMPurify = purify();
  const dirty = '<b>x</b>';
  const config = { RETURN_TRUSTED_TYPE: true };
  // Actual implementation behavior: jsdom does not implement the Trusted
  // Types API, so no internal policy can be created and DOMPurify falls back
  // to returning a plain string (src/purify.ts:
  // `trustedTypesPolicy && RETURN_TRUSTED_TYPE ? ... : serializedHTML`).
  const result = DOMPurify.sanitize(dirty, config);
  assert.strictEqual(
    typeof result,
    'string',
    `RETURN_TRUSTED_TYPE type in jsdom -> input: ${dirty} | config: ${JSON.stringify(
      config
    )} | expected: string (Trusted Types unsupported, string fallback)`
  );
  assert.strictEqual(
    result,
    '<b>x</b>',
    `RETURN_TRUSTED_TYPE value -> input: ${dirty} | expected: <b>x</b>`
  );
});

QUnit.module('DOMPurify config - USE_PROFILES');

QUnit.test('USE_PROFILES html keeps HTML but strips SVG/MathML', (assert) => {
  const DOMPurify = purify();
  const dirty = '<div><svg><circle></circle></svg><math></math><p>x</p></div>';
  const config = { USE_PROFILES: { html: true } };
  const expected = '<div><p>x</p></div>';
  assert.strictEqual(
    DOMPurify.sanitize(dirty, config),
    expected,
    `USE_PROFILES html -> input: ${dirty} | config: ${JSON.stringify(
      config
    )} | expected: ${expected}`
  );
});

QUnit.test('addHook still fires when sanitize uses USE_PROFILES', (assert) => {
  const DOMPurify = purify();
  const dirty = '<p>x</p><svg></svg>';
  const config = { USE_PROFILES: { html: true } };
  let hookCalls = 0;
  DOMPurify.addHook('afterSanitizeAttributes', (node) => {
    hookCalls++;
    if (node.tagName === 'P') {
      node.setAttribute('data-hooked', 'yes');
    }
  });
  const result = DOMPurify.sanitize(dirty, config);
  const expected = '<p data-hooked="yes">x</p>';
  assert.ok(
    hookCalls > 0,
    `addHook fired under USE_PROFILES -> hook calls: ${hookCalls} | expected: > 0`
  );
  assert.strictEqual(
    result,
    expected,
    `USE_PROFILES + addHook -> input: ${dirty} | config: ${JSON.stringify(
      config
    )} + afterSanitizeAttributes hook | expected: ${expected}`
  );
});

QUnit.module('DOMPurify config - per-call config isolation');

QUnit.test('per-call config does not leak into the next sanitize call', (assert) => {
  const DOMPurify = purify();
  const dirty = '<b>1</b><i>2</i>';
  const first = DOMPurify.sanitize(dirty, { ALLOWED_TAGS: ['b'] });
  assert.strictEqual(
    first,
    '<b>1</b>2',
    `first call with ALLOWED_TAGS -> input: ${dirty} | config: {"ALLOWED_TAGS":["b"]} | expected: <b>1</b>2`
  );
  // A config object passed to sanitize() is not persisted: the next call
  // without config must fall back to defaults (both <b> and <i> allowed).
  const second = DOMPurify.sanitize(dirty);
  assert.strictEqual(
    second,
    '<b>1</b><i>2</i>',
    `second call without config -> input: ${dirty} | config: {} | expected: <b>1</b><i>2</i> (defaults restored)`
  );
});

QUnit.start();
