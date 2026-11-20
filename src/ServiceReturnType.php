<?php

declare(strict_types=1);

namespace DrupalSecurityPsalm;

use PhpParser\Node\Scalar\String_;
use Psalm\Plugin\EventHandler\Event\MethodReturnTypeProviderEvent;
use Psalm\Plugin\EventHandler\MethodReturnTypeProviderInterface;
use Psalm\Type\Atomic\TNamedObject;
use Psalm\Type\Union;

/**
 * Types `\Drupal::service('id')` and `$container->get('id')` as the service.
 *
 * Both return `mixed` to Psalm, so a call like
 * `\Drupal::service('file_system')->deleteRecursive($input)` lost the taint at
 * the service boundary. The service map is read from Drupal core's
 * *.services.yml files, the site's other modules, and the modules under
 * analysis; an id it cannot resolve keeps Psalm's default (mixed).
 */
final class ServiceReturnType implements MethodReturnTypeProviderInterface
{
    /** @var array<string, string>|null service id => class */
    private static ?array $services = null;

    /**
     * @return list<string>
     */
    public static function getClassLikeNames(): array
    {
        return [
            'Drupal',
            'Symfony\Component\DependencyInjection\ContainerInterface',
            'Drupal\Component\DependencyInjection\Container',
            'Drupal\Core\DependencyInjection\ContainerBuilder',
        ];
    }

    public static function getMethodReturnType(MethodReturnTypeProviderEvent $event): ?Union
    {
        $wanted = strtolower($event->getFqClasslikeName()) === 'drupal' ? 'service' : 'get';
        if ($event->getMethodNameLowercase() !== $wanted) {
            return null;
        }
        $args = $event->getCallArgs();
        if (!isset($args[0]) || !$args[0]->value instanceof String_) {
            return null;
        }
        $class = self::services()[$args[0]->value->value] ?? null;
        return $class !== null ? new Union([new TNamedObject($class)]) : null;
    }

    /**
     * @return array<string, string>
     */
    private static function services(): array
    {
        if (self::$services !== null) {
            return self::$services;
        }
        $files = [];
        $core = DrupalProject::coreDir();
        if ($core !== null) {
            $files[] = $core . '/core.services.yml';
            // Core modules, then the site's contrib and custom modules.
            $files = [...$files, ...DrupalProject::findFiles($core . '/modules', '.services.yml', 2)];
            $files = [...$files, ...DrupalProject::findFiles(dirname($core) . '/modules', '.services.yml', 4)];
        }
        foreach (DrupalProject::moduleDirs() as $dir) {
            $files = [...$files, ...(glob($dir . '/*.services.yml') ?: [])];
        }

        $classes = [];
        $aliases = [];
        foreach (array_unique($files) as $file) {
            $services = DrupalProject::yaml($file)['services'] ?? null;
            if (!is_array($services)) {
                continue;
            }
            foreach ($services as $id => $definition) {
                if (!is_string($id) || $id === '' || $id[0] === '_') {
                    continue;
                }
                if (is_string($definition) && str_starts_with($definition, '@')) {
                    $aliases[$id] = substr($definition, 1);
                } elseif (is_array($definition) && is_string($definition['alias'] ?? null)) {
                    $aliases[$id] = $definition['alias'];
                } elseif (is_array($definition) && is_string($definition['class'] ?? null)) {
                    $classes[$id] = ltrim($definition['class'], '\\');
                } elseif (str_contains($id, '\\')) {
                    // A service registered under its class name.
                    $classes[$id] = ltrim($id, '\\');
                }
            }
        }
        foreach ($aliases as $id => $target) {
            if (isset($classes[$target]) && !isset($classes[$id])) {
                $classes[$id] = $classes[$target];
            }
        }
        return self::$services = $classes;
    }
}
