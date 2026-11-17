# Drupal Security Scanner (Psalm plugin)

A [Psalm](https://psalm.dev) plugin that teaches Psalm's taint analysis about
Drupal, so it can trace untrusted input across functions and files and find
real data-flow vulnerabilities in modules, themes and custom code:

- **XSS** — request and entity data reaching `#markup`, `Markup::create()`,
  render output and other HTML sinks
- **SQL injection** — untrusted data reaching raw database queries
- **SSRF** — untrusted URLs reaching the HTTP client
- **Command injection / RCE** — shell sinks and callables built from input
- **Insecure deserialization** — untrusted data reaching `unserialize()`

It ships a Drupal taint model (99 input sources plus sinks and sanitizers) as
stubs, and a hook that suppresses the render-array false-positive class while
keeping the dangerous keys. It self-registers, so you don't edit `psalm.xml`
by hand. It is intended as a maintained replacement for
`mortenson/psalm-plugin-drupal`.

> This is a community project. It is **not** an official Drupal Security Team
> tool, and a clean result does not prove code is secure.

## Requirements

- PHP 8.1+
- Psalm 6 (`vimeo/psalm` ^6.0 — installed automatically)

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

## Development

```bash
composer install
vendor/bin/psalm --taint-analysis
```

`psalm.xml` analyses the deliberately vulnerable code in `tests/fixtures`; each
fixture should produce its expected `Tainted*` findings.

## License

GPL-2.0-or-later. See [LICENSE](LICENSE).
