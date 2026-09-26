/* jshint node: true, esnext: true */
/* global QUnit */
'use strict';

// Fine-grained, jsdom-only regression coverage for DOMPurify's configuration
// options. The full suite (test/test-suite.js via test:jsdom) mixes these
// concerns across ~1250 browser-parity tests; this file isolates the config
// surface so it can run without installing a browser:
//
//   ALLOWED_TAGS / ALLOWED_ATTR .......... allowlist replacement semantics
//   FORBID_TAGS .......................... precedence when tags overlap
//   ALLOW_DATA_ATTR / ALLOW_ARIA_ATTR .... data-*/aria-* toggles
//   SANITIZE_DOM / SANITIZE_NAMED_PROPS .. id/name clobbering handling
//   RETURN_DOM / RETURN_TRUSTED_TYPE ..... return-shape behaviour
//   USE_PROFILES + addHook ............... profiles, addHook interplay
//
// The jsdom setup mirrors test/jsdom-node.js exactly (same JSDOM document and
// runScripts option); only jQuery, the XSS fixtures and QUnit autostart
// wiring differ, because config tests need none of them.
//
// Every assertion message spells out the input markup, the exact config
// literal and the expected output, so a failing line identifies the option
// at a glance. Tests are order-independent: the outer module removes all
// hooks and clears persistent config around every single test, and each
// test passes its config inline on the sanitize() call (per-call config is
// not sticky in DOMPurify).

global.QUnit = require('qunit');

const qunitTap = require('qunit-tap');
qunitTap(QUnit, (line) => {
  if (/^not ok/.test(line)) {
    process.exitCode = 1;
  }

  console.log(line);
});

const createDOMPurify = require(
  process.env.DOMPURIFY_COV ? '../dist/purify.cov.cjs' : '../dist/purify.cjs'
);
const { JSDOM, VirtualConsole } = require('jsdom');
const virtualConsole = new VirtualConsole();
const { window } = new JSDOM(
  `<html><head></head><body><div id="qunit-fixture"></div></body></html>`,
  { runScripts: 'dangerously', virtualConsole }
);

const DOMPurify = createDOMPurify(window);

if (!DOMPurify.isSupported) {
  console.error(
    'Unexpected error returned by jsdom JSDOM(): ' +
      'DOMPurify reports isSupported === false'
  );
  process.exit(1);
}

QUnit.config.autostart = false;

// Assert that sanitize(dirty, config) serialises to `expected`.
// The message always carries input + config + expectation, e.g.:
//   sanitize("<b>x</b>", {"FORBID_TAGS":["b"]}) === "x"
// Renders functions too: JSON.stringify drops them, and some configs
// (TRUSTED_TYPES_POLICY) are made entirely of functions.
function renderConfig(value) {
  return JSON.stringify(value, (key, item) =>
    typeof item === 'function'
      ? `[Function: ${item.name || 'anonymous'}]`
      : item
  );
}

function expectClean(assert, dirty, config, expected, note) {
  const message =
    `sanitize(${JSON.stringify(dirty)}, ${renderConfig(config)}) ` +
    `=== ${JSON.stringify(expected)}` +
    (note ? ` — ${note}` : '');
  assert.equal(DOMPurify.sanitize(dirty, config), expected, message);
}

QUnit.module(
  'DOMPurify config options (jsdom)',
  {
    beforeEach() {
      // A hook installed by one test must never be observable by another.
      DOMPurify.removeAllHooks();
    },
    afterEach() {
      DOMPurify.removeAllHooks();
      // A caller-supplied Trusted Types policy is intentionally sticky until
      // clearConfig() (see src/purify.ts _parseConfig), so reset it
      // explicitly to keep tests independent of execution order.
      DOMPurify.clearConfig();
    },
  },
  () => {
    // =======================================================================
    // ALLOWED_TAGS / ALLOWED_ATTR
    // =======================================================================
    QUnit.module('ALLOWED_TAGS / ALLOWED_ATTR allowlists', () => {
      QUnit.test(
        'ALLOWED_TAGS replaces the default tag allowlist',
        (assert) => {
          // Input mixes listed tags (<p>, <b>) with a default-safe tag (<i>)
          // and a <script>. Expected: <p>/<b> survive; <i> is removed but its
          // text is hoisted (KEEP_CONTENT defaults to true); <script> and its
          // contents disappear wholesale because script is a FORBID_CONTENTS
          // element, so its text node is not hoisted.
          expectClean(
            assert,
            '<p class="x">hi</p><i>y</i><b>z</b><script>alert(1)</script>',
            { ALLOWED_TAGS: ['p', 'b'] },
            '<p class="x">hi</p>y<b>z</b>',
            'ALLOWED_TAGS is a replacement allowlist; removed tags keep ' +
              'their text except FORBID_CONTENTS tags like <script>'
          );
        }
      );

      QUnit.test(
        'ALLOWED_TAGS does not narrow the default attribute allowlist',
        (assert) => {
          expectClean(
            assert,
            '<p class="x" title="t">hi</p>',
            { ALLOWED_TAGS: ['p'] },
            '<p class="x" title="t">hi</p>',
            'restricting tags leaves default-safe attributes untouched'
          );
        }
      );

      QUnit.test('ALLOWED_ATTR keeps only the listed attributes', (assert) => {
        expectClean(
          assert,
          '<a href="#" title="t" class="c">x</a>',
          { ALLOWED_ATTR: ['href'] },
          '<a href="#">x</a>',
          'title/class are dropped because ALLOWED_ATTR replaces, rather ' +
            'than extends, the defaults'
        );
      });

      QUnit.test(
        'ALLOWED_ATTR: [] removes ordinary attributes but leaves text',
        (assert) => {
          // Note: data-*/aria-* have their own switches and are asserted in
          // their own module; this expectation covers ordinary attributes.
          expectClean(
            assert,
            '<div id="x" class="c" title="t">y</div>',
            { ALLOWED_ATTR: [] },
            '<div>y</div>',
            'an empty ALLOWED_ATTR drops id/class/title even though they ' +
              'are default-safe'
          );
        }
      );

      QUnit.test('ALLOWED_ATTR does not remove tags', (assert) => {
        expectClean(
          assert,
          '<p>x</p><b>y</b>',
          { ALLOWED_ATTR: ['href'] },
          '<p>x</p><b>y</b>',
          'attribute restrictions never affect which elements survive'
        );
      });
    });

    // =======================================================================
    // FORBID_TAGS precedence
    // =======================================================================
    QUnit.module('FORBID_TAGS precedence', () => {
      QUnit.test(
        'FORBID_TAGS wins when a tag is also in ALLOWED_TAGS',
        (assert) => {
          expectClean(
            assert,
            '<p><b>keep</b><i>drop</i></p>',
            { ALLOWED_TAGS: ['p', 'b', 'i'], FORBID_TAGS: ['b'] },
            '<p>keep<i>drop</i></p>',
            'src/purify.ts checks FORBID_TAGS[tagName] first, so the ' +
              'blocklist overrides ALLOWED_TAGS'
          );
        }
      );

      QUnit.test('FORBID_TAGS also removes default-allowed tags', (assert) => {
        expectClean(
          assert,
          '<b>x</b><i>y</i>',
          { FORBID_TAGS: ['b'] },
          'x<i>y</i>',
          'forbidden <b> is removed even without an ALLOWED_TAGS ' +
            'override; its text is kept'
        );
      });

      QUnit.test(
        'a per-call FORBID_TAGS config does not leak into later calls',
        (assert) => {
          // Guards the "tests must run independently" requirement from
          // inside the suite: inline config is per-call, not sticky.
          expectClean(
            assert,
            '<p>x</p><b>y</b>',
            { FORBID_TAGS: ['p'] },
            'x<b>y</b>',
            'first call drops <p>'
          );
          expectClean(
            assert,
            '<p>x</p><b>y</b>',
            {},
            '<p>x</p><b>y</b>',
            'follow-up call without FORBID_TAGS keeps <p> again'
          );
        }
      );
    });

    // =======================================================================
    // RETURN_DOM / RETURN_DOM_FRAGMENT
    // =======================================================================
    QUnit.module('RETURN_DOM return shape', () => {
      QUnit.test(
        'RETURN_DOM returns a BODY element holding sanitized nodes',
        (assert) => {
          const dirty = '<p>ok</p><script>alert(1)</script>';
          const config = { RETURN_DOM: true };
          const node = DOMPurify.sanitize(dirty, config);

          // The string path parses input into a synthetic <body>; with
          // RETURN_DOM that body element itself is returned (the <script>
          // subtree is gone, not serialised away).
          assert.strictEqual(
            node && node.nodeName,
            'BODY',
            `sanitize(${JSON.stringify(dirty)}, ${JSON.stringify(config)}).nodeName === "BODY"`
          );
          assert.strictEqual(
            node && node.innerHTML,
            '<p>ok</p>',
            `sanitize(${JSON.stringify(dirty)}, ${JSON.stringify(config)}).innerHTML === "<p>ok</p>" — <script> must not be present in the returned DOM`
          );
          assert.strictEqual(
            typeof (node && node.innerHTML),
            'string',
            'RETURN_DOM yields a live DOM node, not a string'
          );
        }
      );

      QUnit.test(
        'RETURN_DOM_FRAGMENT returns a DocumentFragment with all children',
        (assert) => {
          const dirty = '<p>a</p><b>b</b>';
          const config = { RETURN_DOM_FRAGMENT: true };
          const fragment = DOMPurify.sanitize(dirty, config);

          // Actual implementation behaviour: RETURN_DOM_FRAGMENT implies
          // RETURN_DOM internally, but the returned node is a
          // DocumentFragment (nodeType 11) whose children are the sanitized
          // top-level nodes, rather than a <body> wrapper.
          assert.strictEqual(
            fragment && fragment.nodeType,
            11,
            `sanitize(${JSON.stringify(dirty)}, ${JSON.stringify(config)}).nodeType === 11 (DocumentFragment)`
          );
          assert.strictEqual(
            fragment && fragment.childNodes.length,
            2,
            `sanitize(${JSON.stringify(dirty)}, ${JSON.stringify(config)}).childNodes.length === 2`
          );
        }
      );

      QUnit.test(
        'RETURN_DOM output is still governed by the tag allowlist',
        (assert) => {
          const node = DOMPurify.sanitize(
            '<p>a</p><b>b</b><script>x</script>',
            {
              RETURN_DOM: true,
              ALLOWED_TAGS: ['p'],
            }
          );

          assert.strictEqual(
            node && node.innerHTML,
            '<p>a</p>b',
            'RETURN_DOM does not bypass ALLOWED_TAGS: <p> kept, <script> subtree dropped, <b> text hoisted'
          );
        }
      );
    });

    // =======================================================================
    // RETURN_TRUSTED_TYPE
    // =======================================================================
    QUnit.module('RETURN_TRUSTED_TYPE return shape', () => {
      QUnit.test(
        'default and RETURN_TRUSTED_TYPE: false both return a string',
        (assert) => {
          const dirty = '<b>hello</b>';
          assert.strictEqual(
            typeof DOMPurify.sanitize(dirty),
            'string',
            `typeof sanitize(${JSON.stringify(dirty)}) === "string"`
          );
          assert.strictEqual(
            typeof DOMPurify.sanitize(dirty, { RETURN_TRUSTED_TYPE: false }),
            'string',
            `typeof sanitize(${JSON.stringify(dirty)}, {"RETURN_TRUSTED_TYPE":false}) === "string"`
          );
          assert.strictEqual(
            DOMPurify.sanitize(dirty, { RETURN_TRUSTED_TYPE: false }),
            '<b>hello</b>',
            'sanitized content is returned verbatim as a string in jsdom'
          );
        }
      );

      QUnit.test(
        'RETURN_TRUSTED_TYPE: true falls back to a plain string under jsdom',
        (assert) => {
          // Actual implementation behaviour: jsdom does not implement
          // window.trustedTypes, so DOMPurify cannot create a TrustedHTML
          // policy. With RETURN_TRUSTED_TYPE: true it therefore returns a
          // plain string instead of throwing; the assertion pins that
          // jsdom-specific fallback (a TrustedHTML-aware browser would return
          // a TrustedHTML object instead).
          const dirty = '<b>hello goodbye</b>';
          const config = { RETURN_TRUSTED_TYPE: true };
          const clean = DOMPurify.sanitize(dirty, config);

          assert.strictEqual(
            typeof clean,
            'string',
            `typeof sanitize(${JSON.stringify(dirty)}, ${JSON.stringify(config)}) === "string" — jsdom has no trustedTypes, TrustedHTML cannot be produced`
          );
          assert.strictEqual(
            clean,
            '<b>hello goodbye</b>',
            'the string fallback still carries the sanitized markup'
          );
          assert.strictEqual(
            typeof window.trustedTypes,
            'undefined',
            'documents the environment assumption: window.trustedTypes is absent under jsdom'
          );
        }
      );

      QUnit.test(
        'a supplied TRUSTED_TYPES_POLICY signs the RETURN_TRUSTED_TYPE result',
        (assert) => {
          // A caller-supplied policy requires both createHTML and
          // createScriptURL (src/purify.ts throws otherwise). Actual
          // implementation behaviour under jsdom: because jsdom has no native
          // Trusted Types, the dirty markup is signed once while the
          // internally parsed document is initialised and again when the
          // serialized result is returned, so a pass-through createHTML sees
          // the prefix twice. Assert the observed output rather than a
          // single-prefix ideal; a TrustedHTML-aware browser returns an
          // opaque object and never hits this string path.
          const dirty = '<b>x</b>';
          const config = {
            RETURN_TRUSTED_TYPE: true,
            TRUSTED_TYPES_POLICY: {
              createHTML(html) {
                return `POLICY:${html}`;
              },
              createScriptURL(scriptUrl) {
                return scriptUrl;
              },
            },
          };

          assert.strictEqual(
            DOMPurify.sanitize(dirty, config),
            'POLICY:POLICY:<b>x</b>',
            `sanitize(${JSON.stringify(dirty)}, ${renderConfig(config)}) ` +
              `=== "POLICY:POLICY:<b>x</b>" — pass-through policy is ` +
              `applied to the parsed input and again to the serialized ` +
              `result when no native Trusted Types exist`
          );
        }
      );
    });

    // =======================================================================
    // USE_PROFILES + addHook
    // =======================================================================
    QUnit.module('USE_PROFILES profiles and addHook', () => {
      QUnit.test(
        'USE_PROFILES: { html: false } allows only text-profile nodes',
        (assert) => {
          expectClean(
            assert,
            '<h1>HI</h1><p>P</p>',
            { USE_PROFILES: { html: false } },
            'HIP',
            'with html off the profile allowlist starts from TAGS.text, so HTML elements are removed while their text is hoisted'
          );
        }
      );

      QUnit.test(
        'USE_PROFILES: { html: true } keeps HTML profile tags',
        (assert) => {
          expectClean(
            assert,
            '<h1>HELLO</h1>',
            { USE_PROFILES: { html: true } },
            '<h1>HELLO</h1>',
            'the html profile restores the HTML tag/attribute sets'
          );
        }
      );

      QUnit.test(
        'USE_PROFILES: { svg: true } keeps SVG elements and drops HTML elements',
        (assert) => {
          // The SVG <circle> is inside <svg> (a standalone <circle> parsed in
          // HTML mode is removed for namespace reasons regardless of the
          // profile); <h1> is not in the svg-only tag set and is hoisted to
          // text.
          expectClean(
            assert,
            '<h1>HI</h1><svg><circle r="1"></circle></svg>',
            { USE_PROFILES: { svg: true } },
            'HI<svg><circle r="1"></circle></svg>',
            'svg profile admits the SVG subtree but does not include <h1>'
          );
        }
      );

      QUnit.test(
        'an unknown profile flag behaves like the empty profile',
        (assert) => {
          expectClean(
            assert,
            '<h1>HI</h1>',
            { USE_PROFILES: { bogus: true } },
            'HI',
            'only html/svg/svgFilters/mathMl are read, so an unknown flag leaves the text-only base profile'
          );
        }
      );

      QUnit.test(
        'USE_PROFILES overrides ALLOWED_TAGS even when both are given',
        (assert) => {
          expectClean(
            assert,
            '<h1>HI</h1><p>P</p>',
            { USE_PROFILES: { html: false }, ALLOWED_TAGS: ['h1'] },
            'HIP',
            'src/purify.ts rebuilds ALLOWED_TAGS from the profile sets and documents that USE_PROFILES wins over ALLOWED_TAGS'
          );
          expectClean(
            assert,
            '<h1>HI</h1><svg><circle r="1"></circle></svg>',
            { USE_PROFILES: { svg: true }, ALLOWED_TAGS: ['h1'] },
            'HI<svg><circle r="1"></circle></svg>',
            'ALLOWED_TAGS ["h1"] cannot re-admit <h1> while the svg profile is active'
          );
        }
      );

      QUnit.test(
        'an uponSanitizeElement hook can widen the active profile tag set',
        (assert) => {
          DOMPurify.addHook('uponSanitizeElement', (node, data) => {
            if (node.nodeName === 'MY-TAG') {
              data.allowedTags['my-tag'] = true;
            }
          });

          expectClean(
            assert,
            '<h1>HI</h1><my-tag>custom</my-tag>',
            { USE_PROFILES: { html: true } },
            '<h1>HI</h1><my-tag>custom</my-tag>',
            'the hook receives the profile-derived allowedTags and can add tags for this call'
          );
        }
      );

      QUnit.test(
        'an uponSanitizeAttribute hook can widen the active profile attribute set',
        (assert) => {
          DOMPurify.addHook('uponSanitizeAttribute', (node, data) => {
            if (data.attrName === 'myattr') {
              data.allowedAttributes.myattr = true;
            }
          });

          // myattr is neither an svg profile attribute nor a data-*
          // attribute; without the hook it is stripped. data-custom is shown
          // for contrast: it survives without any hook because
          // ALLOW_DATA_ATTR defaults to true.
          expectClean(
            assert,
            '<svg><circle data-custom="1" myattr="v" r="2"></circle></svg>',
            { USE_PROFILES: { svg: true } },
            '<svg><circle data-custom="1" myattr="v" r="2"></circle></svg>',
            'the hook adds myattr to the profile-derived allowedAttributes; data-custom is admitted by ALLOW_DATA_ATTR independently'
          );
        }
      );

      QUnit.test(
        'an uponSanitizeElement hook can remove an element under a profile',
        (assert) => {
          DOMPurify.addHook('uponSanitizeElement', (node) => {
            if (node.tagName === 'EM') {
              node.remove();
            }
          });

          expectClean(
            assert,
            '<p>a<em>b</em>c</p>',
            { USE_PROFILES: { html: true } },
            '<p>ac</p>',
            'hook-detached nodes leave the profile-sanitized output entirely'
          );
        }
      );

      QUnit.test(
        'hooks added in one test do not affect profile sanitization in another',
        (assert) => {
          // Order-independence guard: no hook is installed here, so the
          // custom tag added by the previous hook test must be stripped
          // again. The outer module's afterEach removes hooks between tests.
          expectClean(
            assert,
            '<h1>HI</h1><my-tag>custom</my-tag>',
            { USE_PROFILES: { html: true } },
            '<h1>HI</h1>custom',
            '<my-tag> is outside the html profile; with no hook installed it is removed and its text hoisted'
          );
          expectClean(
            assert,
            '<svg><circle myattr="v" r="2"></circle></svg>',
            { USE_PROFILES: { svg: true } },
            '<svg><circle r="2"></circle></svg>',
            'myattr from the earlier attribute-hook test is gone once the hook is removed'
          );
        }
      );
    });

    // =======================================================================
    // ALLOW_DATA_ATTR / ALLOW_ARIA_ATTR
    // =======================================================================
    QUnit.module('ALLOW_DATA_ATTR / ALLOW_ARIA_ATTR switches', () => {
      QUnit.test(
        'valid data-* attributes survive an empty ALLOWED_ATTR by default',
        (assert) => {
          // data-x matches the DATA_ATTR grammar; data_foo (underscore)
          // does not and is removed; title is removed because
          // ALLOWED_ATTR is empty.
          expectClean(
            assert,
            '<div data-x="1" data_foo="2" title="t">x</div>',
            { ALLOWED_ATTR: [] },
            '<div data-x="1">x</div>',
            'ALLOW_DATA_ATTR defaults to true and admits data-* ' +
              'independently of ALLOWED_ATTR'
          );
        }
      );

      QUnit.test(
        'ALLOW_DATA_ATTR: false strips data-* attributes',
        (assert) => {
          expectClean(
            assert,
            '<div data-x="1">y</div>',
            { ALLOW_DATA_ATTR: false },
            '<div>y</div>',
            'turning the switch off removes data-x even with the ' +
              'default attribute allowlist'
          );
        }
      );

      QUnit.test('valid aria-* and role survive by default', (assert) => {
        expectClean(
          assert,
          '<div aria-label="1" role="r" aria2="z">x</div>',
          {},
          '<div aria-label="1" role="r">x</div>',
          'aria-label passes the ARIA_ATTR grammar; role is ' +
            'default-safe; aria2 is not an aria-* attribute'
        );
      });

      QUnit.test(
        'ALLOW_ARIA_ATTR: false strips aria-* but keeps role',
        (assert) => {
          expectClean(
            assert,
            '<div aria-label="1" role="r">x</div>',
            { ALLOW_ARIA_ATTR: false },
            '<div role="r">x</div>',
            'the switch gates only the aria-* grammar; role comes ' +
              'from the ordinary attribute allowlist'
          );
        }
      );

      QUnit.test(
        'ALLOW_ARIA_ATTR: false strips aria-* even when ALLOWED_ATTR is empty',
        (assert) => {
          expectClean(
            assert,
            '<div aria-label="1">x</div>',
            { ALLOW_ARIA_ATTR: false, ALLOWED_ATTR: [] },
            '<div>x</div>',
            'an aria attribute cannot sneak back in via the empty ' +
              'allowlist when the switch is off'
          );
        }
      );
    });

    // =======================================================================
    // SANITIZE_DOM
    // =======================================================================
    QUnit.module('SANITIZE_DOM clobbering protection', () => {
      QUnit.test(
        'id colliding with a document property is removed by default',
        (assert) => {
          expectClean(
            assert,
            '<div id="body">x</div>',
            {},
            '<div>x</div>',
            '"body" resolves on document, so SANITIZE_DOM (default ' +
              'true) drops the id'
          );
        }
      );

      QUnit.test(
        'name colliding with a document property is removed by default',
        (assert) => {
          expectClean(
            assert,
            '<a name="forms">x</a>',
            {},
            '<a>x</a>',
            'document.forms is a named property, so the name ' +
              'attribute is dropped'
          );
        }
      );

      QUnit.test('a non-colliding id is kept by default', (assert) => {
        expectClean(
          assert,
          '<div id="ok">x</div>',
          {},
          '<div id="ok">x</div>',
          '"ok" is not a document property, so the id survives untouched'
        );
      });

      QUnit.test(
        'SANITIZE_DOM: false keeps colliding id and name',
        (assert) => {
          expectClean(
            assert,
            '<div id="body"><a name="forms">x</a></div>',
            { SANITIZE_DOM: false },
            '<div id="body"><a name="forms">x</a></div>',
            'switching the protection off preserves clobbering-prone ' +
              'values verbatim'
          );
        }
      );
    });

    // =======================================================================
    // SANITIZE_NAMED_PROPS
    // =======================================================================
    QUnit.module('SANITIZE_NAMED_PROPS namespace isolation', () => {
      QUnit.test('id and name are prefixed with user-content-', (assert) => {
        expectClean(
          assert,
          '<div id="foo"><a name="bar">x</a></div>',
          { SANITIZE_NAMED_PROPS: true },
          '<div id="user-content-foo"><a name="user-content-bar">x</a></div>',
          'both named-property attributes get the isolation prefix; ' +
            'other markup is unchanged'
        );
      });

      QUnit.test(
        'already-prefixed values are not prefixed twice (idempotent)',
        (assert) => {
          const config = { SANITIZE_NAMED_PROPS: true };
          expectClean(
            assert,
            '<div id="user-content-foo"><a name="user-content-bar">x</a></div>',
            config,
            '<div id="user-content-foo"><a name="user-content-bar">x</a></div>',
            'the remove-and-recreate path only runs when the value ' +
              'does not already start with user-content-'
          );
          expectClean(
            assert,
            '<div id="user-content-foo">x</div>',
            config,
            '<div id="user-content-foo">x</div>',
            'reusing the same config object on already-prefixed markup ' +
              'stays stable'
          );
        }
      );

      QUnit.test('prefixing leaves non-id/name attributes alone', (assert) => {
        // Actual implementation behaviour: the id is removed and
        // re-created with the prefixed value, which appends it at
        // the end of the attribute list during serialization. The
        // reordering is harmless (attribute order is not
        // semantically significant), so it is pinned rather than
        // "fixed" in the expectation.
        expectClean(
          assert,
          '<div id="a" class="c" title="t">x</div>',
          { SANITIZE_NAMED_PROPS: true },
          '<div class="c" title="t" id="user-content-a">x</div>',
          'only id/name are prefixed; the remove-and-recreate moves ' +
            'the id to the end of the attribute list in jsdom ' +
            'serialization'
        );
      });

      QUnit.test(
        'prefix neutralises a clobbering value even with SANITIZE_DOM on',
        (assert) => {
          // Actual implementation behaviour: with SANITIZE_NAMED_PROPS
          // on, a clobbering value such as id="body" is rewritten to
          // id="user-content-" + value rather than removed, even
          // though SANITIZE_DOM stays at its default of true; the
          // attributes are walked backwards, so name is recreated
          // first and id second, giving name-then-id serialization
          // order.
          expectClean(
            assert,
            '<a id="body" name="forms">x</a>',
            { SANITIZE_NAMED_PROPS: true },
            '<a name="user-content-forms" id="user-content-body">x</a>',
            'SANITIZE_NAMED_PROPS acts on the original value and thus ' +
              'wins over the SANITIZE_DOM rejection for these names; ' +
              'the recreate step also reorders them'
          );
        }
      );
    });
  }
);

QUnit.start();
