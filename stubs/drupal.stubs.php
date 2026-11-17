<?php
/**
 * Drupal Stubs for Psalm Taint Analysis
 *
 * These stubs provide type information for Drupal APIs so Psalm can track
 * taint through function calls across files. This enables interprocedural
 * analysis that Semgrep cannot perform.
 *
 * Sources, sinks, and sanitizers are mapped to Psalm's taint analysis model:
 * - @psalm-taint-source: Entry points for untrusted data
 * - @psalm-taint-sink: Dangerous output locations
 * - @psalm-taint-escape: Functions that neutralize taint
 *
 * Based on analysis of Drupal.org security advisories and mortenson/psalm-plugin-drupal patterns.
 */

// =============================================================================
// Drupal Core Static Access
// =============================================================================
namespace Drupal {
    class Core {
        /**
         * @psalm-taint-source input
         */
        public static function request(): \Symfony\Component\HttpFoundation\Request {}

        /**
         * @psalm-taint-source input
         */
        public static function currentUser(): \Drupal\Core\Session\AccountInterface {}

        /**
         * @psalm-taint-source input
         */
        public static function config($name): \Drupal\Core\Config\ImmutableConfig {}

        /**
         * @psalm-taint-source input
         */
        public static function database(): \Drupal\Core\Database\Connection {}

        /**
         * @psalm-taint-source input
         */
        public static function state(): \Drupal\Core\State\StateInterface {}

        /**
         * Returns logger channel — individual log methods are sinks
         */
        public static function logger($channel): \Psr\Log\LoggerInterface {}

        /**
         * Service locator — returns whatever service is registered.
         * Not an escape function; taint passes through.
         */
        public static function service($id): mixed {}

        /**
         * @psalm-taint-source input
         */
        public static function urlGenerator(): \Drupal\Core\Utility\UrlGenerator {}
    }
}

// =============================================================================
// Configuration API
// =============================================================================
namespace Drupal\Core\Config {
    class ImmutableConfig {
        /**
         * @psalm-taint-source input
         * Config values can be attacker-controlled via admin UI.
         */
        public function get($key, $default = null): mixed {}

        /**
         * @psalm-taint-source input
         * Raw unescaped config data — higher risk than get().
         */
        public function getRawData(): mixed {}
    }

    class Config extends ImmutableConfig {
        public function set($key, $value): self {}
        public function save(): self {}
    }

    class ConfigFactory {
        /**
         * @psalm-taint-source input
         */
        public function get($name): ImmutableConfig {}

        /**
         * @psalm-taint-source input
         */
        public function getEditable($name): Config {}
    }
}

namespace Drupal\Core\State {
    class State {
        /**
         * @psalm-taint-source input
         */
        public function get($key, $default = null): mixed {}

        public function set($key, $value): void {}
    }

    class StateInterface {
        /**
         * @psalm-taint-source input
         */
        public function get($key, $default = null): mixed {}

        public function set($key, $value): void {}
    }
}

// =============================================================================
// Database API
// =============================================================================
namespace Drupal\Core\Database {
    /**
     * Database query results — STORED data (whatever was written to the DB,
     * often originally user-entered). The #1 stored-XSS source: e.g.
     * `$db->query(...)->fetchField()` rendered without escaping.
     */
    interface StatementInterface {
        /** @psalm-taint-source input */
        public function fetch($mode = null, $cursor_orientation = null, $cursor_offset = null): mixed {}
        /** @psalm-taint-source input */
        public function fetchField($index = 0): mixed {}
        /** @psalm-taint-source input */
        public function fetchObject(?string $class_name = null, array $constructor_arguments = []): mixed {}
        /** @psalm-taint-source input */
        public function fetchAssoc(): mixed {}
        /** @psalm-taint-source input */
        public function fetchAll($mode = null, $column_index = null, array $constructor_arguments = []): array {}
        /** @psalm-taint-source input */
        public function fetchCol($index = 0): array {}
        /** @psalm-taint-source input */
        public function fetchAllKeyed($key_index = 0, $value_index = 1): array {}
        /** @psalm-taint-source input */
        public function fetchAllAssoc($key, $fetch = null): array {}
    }

    class Connection {
        /**
         * @psalm-taint-sink sql $query
         */
        public function query(string $query, array $args = [], array $options = []): \Drupal\Core\Database\StatementInterface {}

        /**
         * @psalm-taint-sink sql $query
         */
        public function queryRange(string $query, $from, $count, array $args = [], array $options = []): \Drupal\Core\Database\StatementInterface {}

        /**
         * @psalm-taint-sink sql $query
         */
        public function queryTemporary(string $query, array $args = [], array $options = []): string {}

        public function select(string $table, ?string $alias = null, array $options = []): SelectQuery {}
        public function insert(string $table, array $options = []): Insert {}
        public function update(string $table, array $options = []): Update {}
        public function delete(string $table, array $options = []): Delete {}
        public function merge(string $table, array $options = []): Merge {}

        /**
         * @psalm-taint-escape sql
         */
        public function escapeLike(string $string): string {}

        /**
         * @psalm-taint-escape sql
         */
        public function escapeTable(string $table): string {}

        /**
         * @psalm-taint-escape sql
         */
        public function escapeField(string $field): string {}
    }

    class SelectQuery {
        /**
         * Safe parameterized condition
         */
        public function condition($field, $value = null, $operator = null): self {}

        /**
         * @psalm-taint-sink sql $snippet
         */
        public function where(string $snippet, $args = []): self {}

        /**
         * @psalm-taint-sink sql $snippet
         */
        public function having(string $snippet, $args = []): self {}

        /**
         * @psalm-taint-sink sql $field
         */
        public function orderBy(string $field, string $direction = 'ASC'): self {}

        /**
         * @psalm-taint-sink sql $expression
         */
        public function addExpression(string $expression, ?string $alias = null, array $arguments = []): string {}

        /**
         * @psalm-taint-sink sql $snippet
         */
        public function groupBy(string $snippet): self {}

        /**
         * @psalm-taint-sink sql $condition
         */
        public function join(string $table, ?string $alias = null, string $condition = null, array $arguments = []): self {}

        /**
         * @psalm-taint-sink sql $condition
         */
        public function leftJoin(string $table, ?string $alias = null, string $condition = null, array $arguments = []): self {}

        /**
         * @psalm-taint-sink sql $condition
         */
        public function innerJoin(string $table, ?string $alias = null, string $condition = null, array $arguments = []): self {}

        /**
         * @psalm-taint-sink sql $condition
         */
        public function addJoin(string $type, string $table, ?string $alias = null, string $condition = null, array $arguments = []): string {}
    }

    class Insert {
        public function fields(array $fields): self {}
        public function values(array $values): self {}

        /**
         * @psalm-taint-sink sql
         */
        public function execute(): mixed {}
    }

    class Update extends Insert {
        /**
         * @psalm-taint-sink sql $snippet
         */
        public function expression($field, $expression, array $arguments = []): self {}
    }

    class Delete {
        public function condition($field, $value = null, $operator = null): self {}

        /**
         * @psalm-taint-sink sql
         */
        public function execute(): mixed {}
    }

    class Merge {
        public function key(array $key): self {}
        public function insertFields(array $fields): self {}
        public function updateFields(array $fields): self {}

        /**
         * @psalm-taint-sink sql
         */
        public function execute(): mixed {}
    }
}

namespace {
    /**
     * @psalm-taint-sink sql
     */
    function db_query($query, array $args = [], array $options = []): mixed {}

    /**
     * @psalm-taint-sink sql
     */
    function db_select($table, ?string $alias = null, array $options = []): \Drupal\Core\Database\SelectQuery {}

    /**
     * @psalm-taint-escape sql
     */
    function db_like($string): string {}
}

// =============================================================================
// Form API
// =============================================================================
namespace Drupal\Core\Form {
    class FormState {
        /**
         * @psalm-taint-source input
         */
        public function getValue($key, $default = null): mixed {}

        /**
         * @psalm-taint-source input
         */
        public function getValues(): array {}

        /**
         * @psalm-taint-source input
         * Bypasses validation — raw user input.
         */
        public function getUserInput(): array {}

        /**
         * @psalm-taint-source input
         */
        public function getSubmitValues(): array {}

        /**
         * @psalm-taint-source input
         */
        public function getValueArray($key): array {}

        public function setValue($key, $value): self {}
        public function set($key, $value): self {}
        public function setError($element, $message): self {}
    }

    interface FormStateInterface {
        /**
         * @psalm-taint-source input
         */
        public function getValue($key, $default = null): mixed {}

        /**
         * @psalm-taint-source input
         */
        public function getValues(): array {}

        /**
         * @psalm-taint-source input
         */
        public function getUserInput(): array {}

        /**
         * @psalm-taint-source input
         */
        public function getSubmitValues(): array {}

        /**
         * @psalm-taint-source input
         */
        public function getValueArray($key): array {}
    }
}

// =============================================================================
// Routing
// =============================================================================
namespace Drupal\Core\Routing {
    class RouteMatch {
        /**
         * @psalm-taint-source input
         */
        public function getParameter($parameter_name): mixed {}

        /**
         * @psalm-taint-source input
         * Raw unprocessed parameter — higher risk.
         */
        public function getRawParameter($name): string {}

        public function getRouteName(): ?string {}
        public function getRouteObject(): ?\Symfony\Component\Routing\Route {}
    }

    interface RouteMatchInterface {
        /**
         * @psalm-taint-source input
         */
        public function getParameter($parameter_name): mixed {}

        /**
         * @psalm-taint-source input
         */
        public function getRawParameter($name): string {}
    }
}

// =============================================================================
// Entity API
// =============================================================================
namespace Drupal\Core\Entity {
    class Entity {
        /**
         * @psalm-taint-source input
         * Returns a field item list whose values are stored (user-controlled)
         * data — the canonical stored-XSS source. Typed so `->value`/`->getString()`
         * chains stay tainted (a `mixed` return drops the taint).
         */
        public function get($name): \Drupal\Core\Field\FieldItemListInterface {}

        /**
         * @psalm-taint-source input
         */
        public function label(): string {}

        /**
         * @psalm-taint-source input
         */
        public function id(): mixed {}

        /**
         * @psalm-taint-source input
         */
        public function bundle(): string {}

        /**
         * @psalm-taint-sink ssrf
         */
        public function toLink($text = null, $rel = 'canonical', array $options = []): \Drupal\Core\Link {}

        public function access($operation, ?\Drupal\Core\Session\AccountInterface $account = null, $return_as_object = false): bool {}
        public function save(): int {}
        public function delete(): void {}
    }

    interface EntityInterface {
        /**
         * @psalm-taint-source input
         * Real `get()` lives on FieldableEntityInterface, but code type-hints
         * EntityInterface everywhere; model it here so `$entity->get('f')->value`
         * (stored data) is tracked. Returns a field item list (not mixed).
         */
        public function get($name): \Drupal\Core\Field\FieldItemListInterface {}

        /**
         * @psalm-taint-source input
         */
        public function label(): string {}

        /**
         * @psalm-taint-source input
         */
        public function id(): mixed {}

        /**
         * @psalm-taint-source input
         */
        public function bundle(): string {}
    }

    interface FieldableEntityInterface extends EntityInterface {
        /**
         * @psalm-taint-source input
         */
        public function get($field_name): \Drupal\Core\Field\FieldItemListInterface {}
    }

    class ContentEntityBase extends Entity {
        /**
         * @psalm-taint-source input
         * Stored field data — the canonical stored-XSS source. Annotated on the
         * REAL implementer so concrete entities (Node, ...) inherit it; the
         * phantom `Entity` base above never reaches real entities.
         */
        public function get($field_name): \Drupal\Core\Field\FieldItemListInterface {}
    }

    class ConfigEntityBase extends Entity {}
}

namespace Drupal\Core\Field {
    class FieldItemList {
        /**
         * @psalm-taint-source input
         */
        public function __get($property_name): mixed {}

        /**
         * @psalm-taint-source input
         */
        public function getValue(): array {}

        /**
         * @psalm-taint-source input
         */
        public function getString(): ?string {}
    }

    interface FieldItemListInterface {
        /**
         * @psalm-taint-source input
         */
        public function __get($property_name): mixed {}

        /**
         * @psalm-taint-source input
         */
        public function getValue(): array {}

        /**
         * @psalm-taint-source input
         */
        public function getString(): ?string {}
    }

    class FieldItem {
        /**
         * @psalm-taint-source input
         */
        public function get($property_name): mixed {}
    }
}

namespace Drupal\node\Entity {
    class Node extends \Drupal\Core\Entity\ContentEntityBase {
        /**
         * @psalm-taint-source input
         */
        public function getTitle(): string {}

        /**
         * @psalm-taint-source input
         */
        public function getCreatedTime(): int {}

        /**
         * @psalm-taint-source input
         */
        public function getChangedTime(): int {}
    }
}

// =============================================================================
// Render API — CRITICAL: This is where Drupal's unique RCE vectors live
// =============================================================================
namespace Drupal\Core\Render {
    /**
     * Renderer class — the final output sink for render arrays.
     * Tainted data flowing into #markup, #template, or #children = XSS.
     * Tainted data flowing into #pre_render, #lazy_builder, #access_callback, etc. = RCE.
     */
    class Renderer {
        /**
         * @psalm-taint-sink html $elements
         * Renders a render array into HTML output.
         */
        public function render(array &$elements, $is_root_call = false): \Drupal\Core\Markup\MarkupInterface {}

        /**
         * @psalm-taint-sink html $elements
         */
        public function renderRoot(array &$elements): \Drupal\Core\Markup\MarkupInterface {}

        /**
         * @psalm-taint-sink html $elements
         */
        public function renderPlain(array &$elements): \Drupal\Core\Markup\MarkupInterface {}

        /**
         * @psalm-taint-sink html $elements
         */
        public function renderPlaceholder(string $placeholder, array $elements): \Drupal\Core\Markup\MarkupInterface {}
    }

    interface RendererInterface {
        /**
         * @psalm-taint-sink html $elements
         */
        public function render(array &$elements, $is_root_call = false): \Drupal\Core\Markup\MarkupInterface {}

        /**
         * @psalm-taint-sink html $elements
         */
        public function renderRoot(array &$elements): \Drupal\Core\Markup\MarkupInterface {}

        /**
         * @psalm-taint-sink html $elements
         */
        public function renderPlain(array &$elements): \Drupal\Core\Markup\MarkupInterface {}
    }

    /**
     * RenderContext manages render array state during rendering.
     */
    class RenderContext {
        public function getOutput(): ?\Drupal\Core\Markup\MarkupInterface {}
        public function setOutput($output): void {}
    }

    /**
     * BubbleableMetadata tracks cache contexts, tags, and max-age.
     */
    class BubbleableMetadata {
        public function addCacheableDependency($cacheable_dependency): self {}
        public function addCacheContexts(array $cache_contexts): self {}
        public function addCacheTags(array $cache_tags): self {}
    }
}

namespace Drupal\Component\Render {
    /**
     * MarkupInterface — represents safe HTML markup.
     * Real namespace is Drupal\Component\Render (NOT Drupal\Core\Markup).
     */
    interface MarkupInterface extends \JsonSerializable, \Stringable {}
}

namespace Drupal\Core\Render {
    /**
     * Markup class — creates trusted markup from strings.
     * Real namespace is Drupal\Core\Render (NOT Drupal\Core\Markup), so the
     * previous stub left Markup::create() — a primary XSS sink — unbound/dead.
     * WARNING: Does NOT escape input; treats it as safe HTML.
     */
    class Markup implements \Drupal\Component\Render\MarkupInterface {
        /**
         * @psalm-taint-sink html $string
         * Trusts the input as safe HTML — major XSS vector if tainted data reaches here.
         */
        public static function create($string): Markup {}
    }
}

namespace Drupal\Core\Template {
    /**
     * Twig extensions and template-related sinks.
     */
    class Extension {
        /**
         * @psalm-taint-sink html $string
         */
        public static function twig_drupal_escape_filter($env, $string, $strategy = 'html', $charset = null, $autoescape = true): string {}
    }
}

// =============================================================================
// String Translation API
// =============================================================================
namespace Drupal\Component\Render {
    /**
     * FormattableMarkup — replacement for t() with placeholders.
     * Real namespace is Drupal\Component\Render (NOT StringTranslation).
     * WARNING: !placeholder and @placeholder behave differently — ! does NOT escape;
     * and any user data concatenated into the format string is raw HTML.
     */
    class FormattableMarkup {
        /**
         * @psalm-taint-sink html $string
         * The format string and arguments can contain XSS if user input flows here.
         */
        public function __construct(string $string, array $args = []) {}

        public function __toString(): string {}
        public function jsonSerialize(): string {}
    }
}

namespace Drupal\Core\StringTranslation {
    /**
     * TranslatableMarkup — t() function return type.
     * WARNING: Does NOT escape by default; relies on Twig auto-escaping at render time.
     */
    class TranslatableMarkup extends \Drupal\Component\Render\FormattableMarkup {
        /**
         * @psalm-taint-sink html $string
         */
        public function __construct(string $string, array $args = [], array $options = [], $string_translation = null) {}
    }

    /**
     * PluralTranslatableMarkup — format_plural() return type.
     * Same escaping considerations as TranslatableMarkup.
     */
    class PluralTranslatableMarkup extends TranslatableMarkup {
        /**
         * @psalm-taint-sink html $string
         */
        public function __construct($count, string $singular, string $plural, array $args = [], array $options = []) {}
    }

    /**
     * @psalm-taint-sink html $string
     */
    function t(string $string, array $args = [], array $options = []): TranslatableMarkup {}

    /**
     * @psalm-taint-sink html $string
     */
    function format_plural($count, string $singular, string $plural, array $args = [], array $options = []): PluralTranslatableMarkup {}
}

// =============================================================================
// Messenger API
// =============================================================================
namespace Drupal\Core\Messenger {
    class Messenger {
        /**
         * @psalm-taint-sink html $message
         */
        public function addMessage($message, string $type = 'status', bool $repeat = true): Messenger {}

        /**
         * @psalm-taint-sink html $message
         */
        public function addStatus($message): Messenger {}

        /**
         * @psalm-taint-sink html $message
         */
        public function addWarning($message): Messenger {}

        /**
         * @psalm-taint-sink html $message
         */
        public function addError($message): Messenger {}

        /**
         * @psalm-taint-sink html
         */
        public function all(): array {}
    }

    interface MessengerInterface {
        /**
 * @psalm-taint-sink html $message
         */
        public function addMessage($message, string $type = 'status', bool $repeat = true): MessengerInterface {}
    }
}

// =============================================================================
// Logger API
// =============================================================================
namespace Psr\Log {
    interface LoggerInterface {
        /**
         * @psalm-taint-sink html $message
         * Log injection — user input in log messages can enable log forging.
         */
        public function emergency($message, array $context = []): void {}

        /**
         * @psalm-taint-sink html $message
         */
        public function alert($message, array $context = []): void {}

        /**
         * @psalm-taint-sink html $message
         */
        public function critical($message, array $context = []): void {}

        /**
         * @psalm-taint-sink html $message
         */
        public function error($message, array $context = []): void {}

        /**
         * @psalm-taint-sink html $message
         */
        public function warning($message, array $context = []): void {}

        /**
         * @psalm-taint-sink html $message
         */
        public function notice($message, array $context = []): void {}

        /**
         * @psalm-taint-sink html $message
         */
        public function info($message, array $context = []): void {}

        /**
         * @psalm-taint-sink html $message
         */
        public function debug($message, array $context = []): void {}

        /**
         * @psalm-taint-sink html $message
         */
        public function log($level, $message, array $context = []): void {}
    }
}

namespace Drupal\Core\Logger {
    class LoggerChannel implements \Psr\Log\LoggerInterface {
        /**
         * @psalm-taint-sink html $message
         */
        public function emergency($message, array $context = []): void {}

        /**
         * @psalm-taint-sink html $message
         */
        public function alert($message, array $context = []): void {}

        /**
         * @psalm-taint-sink html $message
         */
        public function critical($message, array $context = []): void {}

        /**
         * @psalm-taint-sink html $message
         */
        public function error($message, array $context = []): void {}

        /**
         * @psalm-taint-sink html $message
         */
        public function warning($message, array $context = []): void {}

        /**
         * @psalm-taint-sink html $message
         */
        public function notice($message, array $context = []): void {}

        /**
         * @psalm-taint-sink html $message
         */
        public function info($message, array $context = []): void {}

        /**
         * @psalm-taint-sink html $message
         */
        public function debug($message, array $context = []): void {}
    }
}

// =============================================================================
// Utility Classes
// =============================================================================
namespace Drupal\Component\Utility {
    class Html {
        /**
         * @psalm-taint-escape html
         */
        public static function escape($text): string {}

        // NOT sanitizers — intentionally NOT stubbed here so Psalm analyses the
        // REAL core methods and propagates taint correctly:
        //   decodeEntities() UN-escapes (opposite of safe — must not look like an
        //   escape); normalize()/getId()/serialize() transform without neutralising
        //   XSS; cleanCssIdentifier() sanitises only for CSS-id context (and there
        //   is no valid `css` taint kind).
    }

    class Xss {
        /**
         * @psalm-taint-escape html
         */
        public static function filter($string, array $allowed_tags = []): string {}

        /**
         * @psalm-taint-escape html
         */
        public static function filterAdmin($string): string {}

        /**
         * Returns allowed tags list for admin users.
         */
        public static function getAdminTagList(): string {}
    }

    class UrlHelper {
        /**
         * @psalm-taint-escape ssrf
         */
        public static function isExternal($url): bool {}

        /**
         * @psalm-taint-escape ssrf
         */
        public static function stripDangerousProtocols($url): string {}

        /**
         * @psalm-taint-escape ssrf
         * Real method name is filterBadProtocol (singular).
         */
        public static function filterBadProtocol($url): string {}

        /**
         * @psalm-taint-escape ssrf
         */
        public static function isValid($url): bool {}

        /**
         * @psalm-taint-escape ssrf
         */
        public static function externalIsLocal($url, $base): bool {}
    }

    class NestedArray {
        public static function getValue(array $array, array $parents, &$key_exists = null): mixed {}
        public static function setValue(array &$array, array $parents, $value, $force = false): void {}
        public static function mergeDeep(array ...$arrays): array {}
    }
}

// =============================================================================
// URL API
// =============================================================================
namespace Drupal\Core\Url {
    /**
     * @psalm-taint-sink ssrf $uri
     */
    function fromUri($uri, array $options = []): \Drupal\Core\Url {}
}

namespace Drupal\Core {
    class Url {
        /**
         * @psalm-taint-sink ssrf $uri
         */
        public static function fromUri($uri, array $options = []): self {}

        /**
         * @psalm-taint-sink ssrf $user_input
         * Builds a URL directly from raw user input — open redirect / SSRF if
         * the value isn't validated (e.g. a `javascript:`/external URL).
         */
        public static function fromUserInput($user_input, array $options = []): self {}

        /**
         * @psalm-taint-source input
         */
        public function toString(): string {}

        /**
         * @psalm-taint-source input
         */
        public function getUri(): string {}

        /**
         * @psalm-taint-source input
         */
        public function getRouteName(): ?string {}
    }

    class Link {
        /**
         * @psalm-taint-sink ssrf $uri
         */
        public static function fromTextAndUrl($text, Url $url): self {}

        /**
         * @psalm-taint-source input
         */
        public function toString(): string {}

        /**
         * @psalm-taint-source input
         */
        public function toRenderable(): array {}
    }
}

// =============================================================================
// File API
// =============================================================================
namespace Symfony\Component\HttpFoundation {
    class FileBag {
        /**
         * @psalm-taint-source input
         */
        public function get(string $key): ?UploadedFile {}

        /**
         * @psalm-taint-source input
         */
        public function all(): array {}
    }

    class UploadedFile extends \SplFileInfo {
        /**
         * @psalm-taint-source input
         */
        public function getClientOriginalName(): string {}

        /**
         * @psalm-taint-source input
         */
        public function getClientMimeType(): string {}

        /**
         * @psalm-taint-source input
         */
        public function getFilename(): string {}

        /**
         * @psalm-taint-source input
         */
        public function getRealPath(): string {}

        /**
         * @psalm-taint-sink html $name
         */
        public function move(string $directory, ?string $name = null): self {}
    }
}

// =============================================================================
// Session API
// =============================================================================
namespace Drupal\Core\Session {
    class AccountInterface {
        /**
         * @psalm-taint-source input
         */
        public function id(): int {}

        /**
         * @psalm-taint-source input
         */
        public function getAccountName(): ?string {}

        /**
         * @psalm-taint-source input
         */
        public function getEmail(): string {}

        public function hasPermission($permission): bool {}
        public function getRoles(): array {}
    }

    class AccountProxy implements AccountInterface {
        /**
         * @psalm-taint-source input
         */
        public function getPreferredLangcode($fallback_to_default = true): string {}
    }
}

// =============================================================================
// Symfony HTTP Foundation (Request/Response)
// =============================================================================
namespace Symfony\Component\HttpFoundation {
    class Request {
        public ParameterBag $query;
        public ParameterBag $request;
        public ParameterBag $cookies;
        public ServerBag $server;
        public HeaderBag $headers;
        public FileBag $files;

        /**
         * @psalm-taint-source input
         */
        public function getContent($asResource = false): string {}

        /**
         * @psalm-taint-source input
         */
        public function getMethod(): string {}

        /**
         * @psalm-taint-source input
         */
        public function getRequestUri(): string {}

        /**
         * @psalm-taint-source input
         */
        public function getUri(): string {}

        /**
         * @psalm-taint-source input
         */
        public function getScheme(): string {}

        /**
         * @psalm-taint-source input
         */
        public function getHost(): string {}

        /**
         * @psalm-taint-source input
         */
        public function getPort(): int {}

        public function isXmlHttpRequest(): bool {}
    }

    class ParameterBag {
        /**
         * @psalm-taint-source input
         */
        public function get(string $key, mixed $default = null): mixed {}

        /**
         * @psalm-taint-source input
         */
        public function all(): array {}

        public function set(string $key, mixed $value): void {}
        public function has(string $key): bool {}
    }

    class ServerBag {
        /**
         * @psalm-taint-source input
         * Server variables (HTTP headers, etc.) can be attacker-controlled.
         */
        public function get(string $key, mixed $default = null): mixed {}

        /**
         * @psalm-taint-source input
         */
        public function all(): array {}
    }

    class HeaderBag {
        /**
         * @psalm-taint-source input
         */
        public function get(string $key, mixed $default = null): mixed {}

        /**
         * @psalm-taint-source input
         */
        public function all(): array {}

        /**
         * @psalm-taint-sink header $values
         * @psalm-taint-sink header $key
         * Setting a response header from user input = header injection / response splitting.
         */
        public function set(string $key, $values, bool $replace = true): void {}
    }

    class ResponseHeaderBag extends HeaderBag {}

    class RedirectResponse extends Response {
        /**
         * @psalm-taint-sink ssrf $url
         */
        public function __construct(string $url, int $status = 302, array $headers = []) {}

        /**
         * @psalm-taint-sink ssrf $url
         */
        public function setTargetUrl(string $url): void {}
    }

    class Response {
        /**
         * @psalm-taint-sink html $content
         */
        public function setContent(?string $content): self {}

        /**
         * @psalm-taint-sink html $content
         */
        public function sendContent(): self {}
    }

    class JsonResponse extends Response {
        /**
         * @psalm-taint-sink html $data
         */
        public function setData($data): self {}
    }
}

// =============================================================================
// Drupal redirect (open redirect) + Token (source)
// =============================================================================
namespace Drupal\Core\Routing {
    class TrustedRedirectResponse extends \Symfony\Component\HttpFoundation\RedirectResponse {
        /**
         * @psalm-taint-sink ssrf $url
         * Drupal redirect subclass — annotate explicitly (taint sink doesn't
         * inherit through the stub class graph from Symfony's RedirectResponse).
         */
        public function __construct($url, int $status = 302, array $headers = []) {}
    }
}

namespace Drupal\Core\Utility {
    class Token {
        /**
         * @psalm-taint-source input
         * Token replacement expands to user/entity data and is frequently
         * rendered raw — classic token-XSS source.
         */
        public function replace($text, array $data = [], array $options = [], $bubbleable_metadata = null): string {}

        /**
         * @psalm-taint-source input
         */
        public function replacePlain(string $plain, array $data = [], array $options = [], $bubbleable_metadata = null): string {}
    }
}

namespace Symfony\Component\HttpFoundation\RequestStack {
    class RequestStack {
        /**
         * @psalm-taint-source input
         */
        public function getCurrentRequest(): ?\Symfony\Component\HttpFoundation\Request {}

        /**
         * @psalm-taint-source input
         */
        public function getMainRequest(): ?\Symfony\Component\HttpFoundation\Request {}
    }
}

// =============================================================================
// Symfony Process (Command Injection)
// =============================================================================
namespace Symfony\Component\Process {
    class Process {
        /**
         * @psalm-taint-sink shell $command
         */
        public function __construct(array $command, ?string $cwd = null, ?array $env = null, mixed $input = null, ?float $timeout = 60) {}

        /**
         * @psalm-taint-sink shell $command
         */
        public function setCommandLine(array $command): self {}

        public function run(?callable $callback = null): int {}
        public function mustRun(?callable $callback = null): self {}
        public function getOutput(): string {}
        public function getErrorOutput(): string {}
    }
}

// =============================================================================
// Guzzle HTTP client (SSRF) — the HTTP client in Drupal (\Drupal::httpClient()).
// A user-controlled URL reaching request()/get()/post()/... is SSRF.
// =============================================================================
namespace GuzzleHttp {
    interface ClientInterface {
        /**
         * @psalm-taint-sink ssrf $uri
         */
        public function request(string $method, $uri = '', array $options = []): \Psr\Http\Message\ResponseInterface {}

        /**
         * @psalm-taint-sink ssrf $uri
         */
        public function requestAsync(string $method, $uri = '', array $options = []): mixed {}
    }

    class Client implements ClientInterface {
        /**
         * @psalm-taint-sink ssrf $uri
         */
        public function request(string $method, $uri = '', array $options = []): \Psr\Http\Message\ResponseInterface {}

        /**
         * @psalm-taint-sink ssrf $uri
         */
        public function requestAsync(string $method, $uri = '', array $options = []): mixed {}

        /**
         * @psalm-taint-sink ssrf $uri
         * __call-style shortcuts: get($uri), post($uri), put($uri), delete($uri), head($uri), patch($uri).
         */
        public function get($uri = '', array $options = []): \Psr\Http\Message\ResponseInterface {}

        /** @psalm-taint-sink ssrf $uri */
        public function post($uri = '', array $options = []): \Psr\Http\Message\ResponseInterface {}

        /** @psalm-taint-sink ssrf $uri */
        public function put($uri = '', array $options = []): \Psr\Http\Message\ResponseInterface {}

        /** @psalm-taint-sink ssrf $uri */
        public function patch($uri = '', array $options = []): \Psr\Http\Message\ResponseInterface {}

        /** @psalm-taint-sink ssrf $uri */
        public function delete($uri = '', array $options = []): \Psr\Http\Message\ResponseInterface {}

        /** @psalm-taint-sink ssrf $uri */
        public function head($uri = '', array $options = []): \Psr\Http\Message\ResponseInterface {}
    }
}

// =============================================================================
// Twig — Server-Side Template Injection (user data in a template string = RCE)
// =============================================================================
namespace Twig {
    class Environment {
        /**
         * @psalm-taint-sink html $template
         * Compiling a user-controlled template string is template injection (RCE).
         */
        public function createTemplate(string $template, ?string $name = null): mixed {}
    }
}

namespace Drupal\Core\Template {
    class TwigEnvironment extends \Twig\Environment {
        /**
         * @psalm-taint-sink html $template_string
         * Renders an inline template string — SSTI if user-controlled.
         */
        public function renderInline(string $template_string, array $context = []): \Drupal\Component\Render\MarkupInterface {}
    }
}

// =============================================================================
// Plugin / hook / callback injection — a user-controlled plugin id, hook, or
// callback name selects arbitrary code to run (RCE). Kind: callable.
// =============================================================================
namespace Drupal\Component\Plugin\Factory {
    interface FactoryInterface {
        /**
         * @psalm-taint-sink callable $plugin_id
         */
        public function createInstance($plugin_id, array $configuration = []): mixed {}
    }
}

namespace Drupal\Core\Plugin {
    class DefaultPluginManager {
        /**
         * @psalm-taint-sink callable $plugin_id
         */
        public function createInstance($plugin_id, array $configuration = []): mixed {}
    }
}

namespace Drupal\Core\Extension {
    interface ModuleHandlerInterface {
        /**
         * @psalm-taint-sink callable $hook
         * Builds and calls "{$module}_{$hook}" — user-controlled hook/module = RCE.
         */
        public function invoke($module, $hook, array $args = []): mixed {}

        /**
         * @psalm-taint-sink callable $hook
         */
        public function invokeAll($hook, array $args = []): array {}
    }

    class ModuleHandler implements ModuleHandlerInterface {
        /**
         * @psalm-taint-sink callable $hook
         */
        public function invoke($module, $hook, array $args = []): mixed {}

        /**
         * @psalm-taint-sink callable $hook
         */
        public function invokeAll($hook, array $args = []): array {}
    }
}

// =============================================================================
// PHP Built-in Sources (re-taint data from external formats)
// =============================================================================
namespace {
    /**
     * @psalm-taint-source input
     */
    function json_decode(string $json, ?bool $associative = null, int $depth = 512, int $flags = 0): mixed {}

    /**
     * @psalm-taint-source input
     */
    function base64_decode(string $string, bool $strict = false): string {}

    /**
     * @psalm-taint-source input
     */
    function simplexml_load_string(string $data, string $class_name = \SimpleXMLElement::class, int $options = 0, string $ns = "", bool $is_prefix = false): \SimpleXMLElement {}

    /**
     * Insecure deserialization sink.
     * 
     * @psalm-taint-sink unserialize $data
     * 
     * Note: When called with ['allowed_classes' => FALSE], this is considered safe
     * and should not be flagged. Psalm's taint analysis currently doesn't support
     * conditional sinks based on argument values, so we mark all calls as sinks.
     * 
     * TODO: Create a custom Psalm plugin to detect safe usage patterns.
     */
    function unserialize(string $data, array $options = []): mixed {}

    // Global superglobals as sources
    /** @psalm-taint-source input */
    // $_GET — covered by Request->query
    /** @psalm-taint-source input */
    // $_POST — covered by Request->request
    /** @psalm-taint-source input */
    // $_COOKIE — not covered by Request in Drupal
    /** @psalm-taint-source input */
    // $_SERVER — covered by ServerBag
    /** @psalm-taint-source input */
    // $_SESSION — covered by AccountInterface
    /** @psalm-taint-source input */
    // $_FILES — covered by FileBag
}

// =============================================================================
// PHP Built-in Sources (insecure randomness)
// =============================================================================
namespace {
    /**
     * Insecure random number generators - predictable output.
     * @psalm-taint-source insecure_random
     */
    function uniqid(string $prefix = "", bool $more_entropy = false): string {}

    /**
     * @psalm-taint-source insecure_random
     */
    function mt_rand(int $min = 0, int $max = null): int {}

    /**
     * @psalm-taint-source insecure_random
     */
    function rand(int $min = 0, int $max = null): int {}

    /**
     * Secure random functions - cryptographically strong.
     * @psalm-taint-escape insecure_random
     */
    function random_int(int $min, int $max): int {}

    /**
     * @psalm-taint-escape insecure_random
     */
    function random_bytes(int $length): string {}
}

// =============================================================================
// DOM API (for XSS via HTML attributes)
// =============================================================================
namespace {
    class DOMElement extends DOMNode {
        /**
         * @psalm-taint-sink html $value
         */
        public function setAttribute(string $name, string $value): bool {}

        /**
         * @psalm-taint-sink html $attr
         */
        public function setAttributeNode(\DOMAttr $attr): \DOMAttr|false {}
    }

    class DOMAttr extends DOMNode {
        public string $name;
        public string $value;
    }

    class DOMNode {}
}

// =============================================================================
// PHP Built-in Sinks (dangerous operations)
// =============================================================================
namespace {
    // Note: eval/echo/print/include/require are language constructs, not
    // functions — they cannot be declared as `function ...` (invalid PHP) and
    // Psalm has built-in taint handling for them, so they are intentionally
    // omitted here.

    /**
     * @psalm-taint-sink html
     */
    function printf(string $format, mixed ...$values): int {}

    /**
     * @psalm-taint-sink sql
     */
    function mysql_query(string $query, $link_identifier = null): mixed {}

    /**
     * @psalm-taint-sink shell
     */
    function exec(string $command, &$output = null, &$return_var = null): string {}

    /**
     * @psalm-taint-sink shell
     */
    function system(string $command, &$return_var = null): string {}

    /**
     * @psalm-taint-sink shell
     */
    function passthru(string $command, &$return_var = null): void {}

    /**
     * @psalm-taint-sink shell
     */
    function shell_exec(string $command): string {}

    /**
     * @psalm-taint-sink shell
     */
    function proc_open(string $cmd, array $descriptorspec, &$pipes, ?string $cwd = null, ?array $env_vars = null, ?array $other_options = null): mixed {}

    /**
     * @psalm-taint-sink shell
     */
    function popen(string $command, string $mode): mixed {}

    /**
     * @psalm-taint-sink shell
     */
    function pcntl_exec(string $path, array $args = [], array $envs = []): void {}

    /**
     * @psalm-taint-sink html
     */
    function file_get_contents(string $filename, bool $use_include_path = false, $context = null, int $offset = 0, int $length = null): string {}

    /**
     * @psalm-taint-sink html
     */
    function fopen(string $filename, string $mode, bool $use_include_path = false, $context = null): mixed {}

    /**
     * @psalm-taint-sink html
     */
    function copy(string $source, string $destination, $context = null): bool {}

    /**
     * @psalm-taint-sink html
     */
    function rename(string $from, string $to, $context = null): bool {}

    /**
     * @psalm-taint-sink html
     */
    function readfile(string $filename, bool $use_include_path = false, $context = null): int {}

    /**
     * @psalm-taint-sink ssrf
     */
    function curl_exec($handle): mixed {}

    /**
     * @psalm-taint-source input
     */
    function get_headers(string $url, bool $associative = false): array {}
}

// =============================================================================
// Legacy Drupal 7 Functions
// =============================================================================
namespace {
    /**
     * @psalm-taint-source input
     */
    function arg($index = null, ?string $path = null): mixed {}

    /**
     * @psalm-taint-source input
     */
    function drupal_get_form($form_id): array {}

    /**
     * @psalm-taint-sink html
     */
    function drupal_set_message($message = null, string $type = 'status', bool $repeat = true): array {}

    /**
     * @psalm-taint-escape html
     */
    function check_plain($text): string {}

    /**
     * @psalm-taint-escape html
     */
    function filter_xss($string, array $allowed_tags = []): string {}

    /**
     * @psalm-taint-escape html
     */
    function filter_xss_admin($string): string {}

    /**
     * @psalm-taint-escape sql
     */
    function db_like($string): string {}

    /**
     * @psalm-taint-sink sql
     */
    function db_query($query, array $args = [], array $options = []): mixed {}

    /**
     * @psalm-taint-source input
     */
    function drupal_get_destination(): string {}
}
