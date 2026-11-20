# Drupal Security Scanner (Psalm plugin)

A [Psalm](https://psalm.dev) plugin that teaches Psalm's taint analysis about
Drupal, so it can trace untrusted input across functions and files and find
real data-flow vulnerabilities in modules, themes and custom code:

- **XSS** — request and entity data reaching `#markup`, `Markup::create()`,
  render output and other HTML sinks
- **SQL injection** — untrusted data reaching raw database queries
- **SSRF** — untrusted URLs reaching the HTTP client
- **Path traversal** — untrusted paths reaching PHP file functions and Drupal's
  file-system service
- **Open redirect** — untrusted URLs in a redirect, reported as a tainted
  header (Psalm has no redirect kind; a redirect sets the `Location` header)
- **Command injection / RCE** — shell sinks and callables built from input
- **Insecure deserialization** — untrusted data reaching `unserialize()`

It ships a Drupal taint model as stubs (input sources, sinks and sanitizers,
including the file-system API), plus hooks that read Drupal's own metadata:

- **URL route parameters are input.** A controller argument filled from the
  route path (`path: '/hello/{name}'` → `hello(string $name)`) is tainted.
- **Services are typed.** `\Drupal::service('id')` and `$container->get('id')`
  return the class from `*.services.yml`, so taint flows through services.
- **Render arrays are understood.** Keys Drupal escapes (`#title`,
  `#description`, …) are not sinks; `#markup` and anything unknown are.
- **Field and form-element values are input.** PHP's own functions (`exec`,
`unserialize`, `file_get_contents`, …) are left to Psalm, which already models
them. It self-registers, so you don't edit `psalm.xml` by hand.

> This is a community project. It is **not** an official Drupal Security Team
> tool, and a clean result does not prove code is secure.

## Requirements

- PHP 8.2+
- Psalm 6.16 or later 6.x (`vimeo/psalm` ^6.16 — installed automatically)

## Installation

```bash
composer require --dev drupal-security/scanner
vendor/bin/psalm-plugin enable drupal-security/scanner
```

## Usage

Run Psalm's taint analysis over your code:

```bash
vendor/bin/psalm --taint-analysis
```

Findings are reported as Psalm `Tainted*` issues — for example `TaintedHtml`,
`TaintedSql` or `TaintedSSRF` — with the full source-to-sink path.

### With the Security Scan Drupal module

The [Security Scan](https://www.drupal.org/project/security_scan) module
(`drush security:scan`) detects this package automatically and uses it for its
optional **deep taint pass**, alongside its fast deterministic checks:

```bash
composer require --dev drupal-security/scanner
drush security:scan my_module
```

## Known limits

- **Hardened `unserialize()` is still reported.** Psalm cannot make a sink
  depend on another argument, so `unserialize($x, ['allowed_classes' => FALSE])`
  is flagged; drop it at the report layer (the Security Scan module does).
- **`$build['#title'] = $x` is reported** even though `#title` is escaped:
  Psalm only lets a plugin clear taint on array literals (`['#title' => $x]`).
- **Psalm reports one path per sink.** When two flows reach the same sink and
  one goes through a helper function, Psalm may report only the direct one.
- **Controllers declared as services** (`_controller: 'service.id:method'`)
  are not resolved, so their URL arguments are not treated as input.
- A clean result does not prove code is secure.

## Development

```bash
composer install
composer test
```

`composer test` runs `tests/check.php`, which analyses `tests/fixtures` and
checks every `// expect:` annotation (the issue types a line must report, or
`none`), fails on any unannotated finding, and checks that every built-in sink
plain Psalm reports is still reported with the plugin. CI runs it on PHP 8.2,
8.3 and 8.4, with both the oldest supported Psalm (6.16) and the latest.

## License

GPL-2.0-or-later. See [LICENSE](LICENSE).
