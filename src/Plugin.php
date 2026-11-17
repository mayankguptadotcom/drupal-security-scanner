<?php

declare(strict_types=1);

namespace DrupalSecurityPsalm;

use Psalm\Plugin\PluginEntryPointInterface;
use Psalm\Plugin\RegistrationInterface;
use SimpleXMLElement;

/**
 * Entry point for the Drupal Security Psalm plugin.
 *
 * Teaches Psalm's taint engine about Drupal so it can find real data-flow
 * vulnerabilities (XSS, SQLi, RCE via render arrays, insecure deserialization,
 * SSRF) with a low false-positive rate. A self-registering, maintained
 * replacement for mortenson/psalm-plugin-drupal:
 *
 *   - Ships a comprehensive Drupal taint model (sources / sinks / sanitizers)
 *     via stubs/drupal.stubs.php — a strict superset of mortenson's stubs.
 *   - Registers {@see RenderArrayTainter} to suppress the render-array
 *     false-positive class while preserving the dangerous keys.
 *   - Reserves a seam for service-container type resolution (full-site mode),
 *     implemented in a later phase — see below.
 *
 * Distribution: this class is wired via composer.json `extra.psalm.pluginClass`,
 * so consumers only run `composer require --dev` + `psalm-plugin enable`; they do
 * NOT hand-edit psalm.xml stub/plugin entries.
 */
final class Plugin implements PluginEntryPointInterface
{
    public function __invoke(RegistrationInterface $registration, ?SimpleXMLElement $config = null): void
    {
        // The Drupal taint model. Registered here (not via project psalm.xml) so
        // the plugin is a drop-in dependency.
        $registration->addStubFile(dirname(__DIR__) . '/stubs/drupal.stubs.php');

        require_once __DIR__ . '/RenderArrayTainter.php';
        $registration->registerHooksFromClass(RenderArrayTainter::class);

        require_once __DIR__ . '/RenderElementSource.php';
        $registration->registerHooksFromClass(RenderElementSource::class);

        require_once __DIR__ . '/FieldValueSource.php';
        $registration->registerHooksFromClass(FieldValueSource::class);

        // --- Full-site mode seam (modules-first; implemented in a later phase) ---
        //
        // For whole-site scans, taint must flow through `\Drupal::service('x')`
        // and `$container->get('x')` calls, which otherwise return `mixed`. The
        // plan (mirrors mortenson's approach) is a ContainerHandler implementing
        // AfterMethodCallAnalysisInterface that reads a dumped container map and
        // sets the resolved service class as the return type. It is intentionally
        // NOT registered yet: contrib-module scanning — the current target — does
        // not need it, and shipping an unconfigured container hook would only add
        // noise. When enabled it will be gated on a `<containerXml>` config node:
        //
        //     if ($config && isset($config->containerXml)) {
        //         require_once __DIR__ . '/ContainerHandler.php';
        //         ContainerHandler::init(...);
        //         $registration->registerHooksFromClass(ContainerHandler::class);
        //     }
        //
        // The unserialize `allowed_classes => false` false positive is handled at
        // the report layer by filter_findings.py — Psalm has no hook for
        // conditional argument-sink suppression (see that file's header).
        unset($config);
    }
}
