<?php

declare(strict_types=1);

namespace DrupalSecurityPsalm;

use PhpParser\Node\Expr\Variable;
use Psalm\Plugin\EventHandler\AddTaintsInterface;
use Psalm\Plugin\EventHandler\Event\AddRemoveTaintsEvent;
use Psalm\Type\TaintKindGroup;

/**
 * Marks controller arguments filled from the URL as untrusted input.
 *
 * A route like `path: '/hello/{name}'` with `_controller: '…::hello'` passes the
 * path segment straight into `hello(string $name)`. To Psalm that is an
 * ordinary parameter, so `print $name` went unreported. This reads every
 * *.routing.yml of the modules under analysis and taints those arguments.
 *
 * Only text is tainted: an argument whose type is an object (an entity Drupal
 * loaded by ID) or a number cannot carry an attacker's markup or SQL, and
 * tainting it would only produce false positives.
 */
final class RouteParameterSource implements AddTaintsInterface
{
    /** @var array<string, array<string, true>>|null "class::method" (lowercase) => path parameter names */
    private static ?array $parameters = null;

    /**
     * @return list<string>
     */
    public static function addTaints(AddRemoveTaintsEvent $event): array
    {
        $expr = $event->getExpr();
        $method = $event->getContext()->calling_method_id;
        if (!$expr instanceof Variable || !is_string($expr->name) || $method === null) {
            return [];
        }
        if (!isset(self::parameters()[strtolower($method)][$expr->name])) {
            return [];
        }
        $type = $event->getContext()->vars_in_scope['$' . $expr->name] ?? null;
        if ($type !== null && !$type->hasString() && !$type->hasMixed()) {
            return [];
        }
        return TaintKindGroup::ALL_INPUT;
    }

    /**
     * @return array<string, array<string, true>>
     */
    private static function parameters(): array
    {
        if (self::$parameters !== null) {
            return self::$parameters;
        }
        $map = [];
        foreach (DrupalProject::moduleDirs() as $dir) {
            foreach (glob($dir . '/*.routing.yml') ?: [] as $file) {
                foreach (DrupalProject::yaml($file) as $route) {
                    if (!is_array($route) || !is_string($route['path'] ?? null)) {
                        continue;
                    }
                    preg_match_all('/\{(\w+)\}/', $route['path'], $m);
                    $names = array_filter($m[1], static fn (string $n): bool => $n[0] !== '_');
                    if ($names === []) {
                        continue;
                    }
                    foreach (self::callables($route['defaults'] ?? []) as $callable) {
                        foreach ($names as $name) {
                            $map[$callable][$name] = true;
                        }
                    }
                }
            }
        }
        return self::$parameters = $map;
    }

    /**
     * The "class::method" ids (lowercase) a route's defaults dispatch to.
     *
     * @return list<string>
     */
    private static function callables(mixed $defaults): array
    {
        if (!is_array($defaults)) {
            return [];
        }
        $out = [];
        foreach (['_controller', '_title_callback'] as $key) {
            // "Class::method"; the "service.id:method" form is not resolved.
            if (is_string($defaults[$key] ?? null) && str_contains($defaults[$key], '::')) {
                $out[] = strtolower(ltrim($defaults[$key], '\\'));
            }
        }
        if (is_string($defaults['_form'] ?? null)) {
            // Route parameters are passed to buildForm() as extra arguments.
            $out[] = strtolower(ltrim($defaults['_form'], '\\')) . '::buildform';
        }
        return $out;
    }
}
