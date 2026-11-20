# Changelog

All notable changes to `drupal-security/scanner` are recorded here. The format
is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the
project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.1] - 2026-11-19

A correctness release. **Upgrade from 1.0.0**: it missed command injection
entirely and reported several safe Drupal APIs as vulnerabilities.

### Fixed

- **Restored every PHP built-in sink.** The stubs redeclared PHP functions such
  as `exec()`, `system()`, `proc_open()`, `readfile()`, `copy()` and
  `printf()`. A stub replaces Psalm's own definition, so these redeclarations
  deleted 10 of the 21 built-in sinks plain Psalm reports — including every
  shell-execution sink. Built-ins are no longer redeclared, and the tests now
  fail if the plugin reports less than plain Psalm on any built-in.
- **Removed sinks that are not sinks** (each checked against Drupal 11):
  `Messenger::addMessage()` and friends (messages are autoescaped),
  `Select::orderBy()` (the field is escaped when the query is compiled),
  `Url::fromUri()`, `Url::fromUserInput()` and `Link::fromTextAndUrl()` (core
  rejects `javascript:`, `data:` and similar schemes), `JsonResponse::setData()`,
  plugin `createInstance()`, query-builder `execute()`, and Twig's escape filter
  (now a sanitizer).
- **Removed sources that are not attacker-controlled:** entity and account IDs,
  bundles, created/changed timestamps, URLs and links Drupal generates, an
  upload's server-side temp path, and the preferred-language code.
- **Added missing request sources:** `Request::get()`, `getPathInfo()` and
  `getQueryString()`.
- **Fixed 12 annotations Psalm silently ignored** because they named no
  parameter or a parameter the function does not have — including the real
  sinks `Update::expression()` and `PluralTranslatableMarkup` (singular and
  plural format strings).
- Removed dead stubs: a `Drupal\Core` class that never matched the global
  `\Drupal` class, Drupal 7 functions, and a non-existent namespaced function.

### Changed

- **`RenderArrayTainter` is a new implementation.** 1.0.0 shipped a version
  ported from `mortenson/psalm-plugin-drupal`, whose license (LGPL 2.1 with the
  Commons Clause) is not compatible with this package's GPL-2.0-or-later. The
  new class is written independently and differs in design: it clears HTML
  taint only for an allowlist of render keys Drupal escapes, so an unknown key
  keeps its taint, and it uses no Psalm-internal API.
- Requires PHP 8.2+ and Psalm `^6.16` (the oldest version tested).

### Added

- A test suite (`composer test`): fixtures annotated with the issues each line
  must or must not report, a built-in sink parity check against plain Psalm,
  and CI on PHP 8.2–8.4 with both the oldest supported Psalm and the latest.

## [1.0.0] - 2026-11-17

Initial release.

[1.0.1]: https://github.com/mayankguptadotcom/drupal-security-scanner/compare/1.0.0...1.0.1
[1.0.0]: https://github.com/mayankguptadotcom/drupal-security-scanner/releases/tag/1.0.0
