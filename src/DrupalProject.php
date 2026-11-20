<?php

declare(strict_types=1);

namespace DrupalSecurityPsalm;

use Composer\InstalledVersions;
use Psalm\Config;
use Symfony\Component\Yaml\Yaml;

/**
 * Finds the Drupal modules under analysis and reads their YAML.
 *
 * Shared by the hooks that need Drupal's own metadata: routes (which controller
 * arguments come from the URL) and services (what `\Drupal::service('id')`
 * returns). Everything is read once per analysis and cached.
 *
 * The YAML belongs to the code under review, so it is treated as untrusted:
 * parsed without PHP-object or constant support, and files over 1 MB are skipped.
 */
final class DrupalProject
{
    private const MAX_YAML_BYTES = 1_048_576;

    /** @var list<string>|null */
    private static ?array $moduleDirs = null;

    /**
     * Directories of the modules being analysed (each holds a *.info.yml).
     *
     * A project file's module is found by walking up to the nearest directory
     * with an *.info.yml; a project directory is also searched downwards.
     *
     * @return list<string>
     */
    public static function moduleDirs(): array
    {
        if (self::$moduleDirs !== null) {
            return self::$moduleDirs;
        }
        $config = Config::getInstance();
        $dirs = [];
        foreach ($config->getProjectFiles() as $file) {
            $dir = self::enclosingModule(dirname($file));
            if ($dir !== null) {
                $dirs[$dir] = true;
            }
        }
        foreach ($config->getProjectDirectories() as $root) {
            $up = self::enclosingModule($root);
            if ($up !== null) {
                $dirs[$up] = true;
            }
            foreach (self::findFiles($root, '.info.yml', 6) as $info) {
                $dirs[dirname($info)] = true;
            }
        }
        return self::$moduleDirs = array_keys($dirs);
    }

    /**
     * Drupal core's directory, when the analysed site has drupal/core installed.
     */
    public static function coreDir(): ?string
    {
        if (!class_exists(InstalledVersions::class) || !InstalledVersions::isInstalled('drupal/core')) {
            return null;
        }
        $path = InstalledVersions::getInstallPath('drupal/core');
        return $path !== null && is_dir($path) ? (string) realpath($path) : null;
    }

    /**
     * Parses a YAML file into an array, or returns [] if it cannot be read.
     *
     * @return array<mixed>
     */
    public static function yaml(string $file): array
    {
        if (!class_exists(Yaml::class) || !is_file($file) || filesize($file) > self::MAX_YAML_BYTES) {
            return [];
        }
        try {
            // Custom tags (core.services.yml uses !tagged_iterator) are wrapped
            // in an inert TaggedValue; PHP objects and constants stay disabled.
            $data = Yaml::parse((string) file_get_contents($file), Yaml::PARSE_CUSTOM_TAGS);
        } catch (\Throwable) {
            return [];
        }
        return is_array($data) ? $data : [];
    }

    /**
     * Files under $dir ending in $suffix, searched to $depth levels.
     *
     * @return list<string>
     */
    public static function findFiles(string $dir, string $suffix, int $depth): array
    {
        if (!is_dir($dir)) {
            return [];
        }
        $found = [];
        $iterator = new \RecursiveIteratorIterator(
            new \RecursiveCallbackFilterIterator(
                new \RecursiveDirectoryIterator($dir, \FilesystemIterator::SKIP_DOTS),
                static fn (\SplFileInfo $f): bool => !$f->isDir()
                    || !in_array($f->getFilename(), ['vendor', 'node_modules', '.git'], true),
            ),
        );
        $iterator->setMaxDepth($depth);
        foreach ($iterator as $file) {
            if ($file->isFile() && str_ends_with($file->getFilename(), $suffix)) {
                $found[] = $file->getPathname();
            }
        }
        return $found;
    }

    /**
     * The nearest directory at or above $dir that holds an *.info.yml.
     */
    private static function enclosingModule(string $dir): ?string
    {
        for ($i = 0; $i < 8 && $dir !== dirname($dir); $i++, $dir = dirname($dir)) {
            if (glob($dir . '/*.info.yml') !== []) {
                return $dir;
            }
        }
        return null;
    }
}
