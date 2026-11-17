<?php

declare(strict_types=1);

namespace DrupalSecurityPsalm;

use PhpParser\Node\ArrayItem;
use Psalm\Internal\Analyzer\StatementsAnalyzer;
use Psalm\Plugin\EventHandler\Event\AddRemoveTaintsEvent;
use Psalm\Plugin\EventHandler\RemoveTaintsInterface;

/**
 * Strips `html` taint from *safe* render-array keys while preserving it on the
 * keys that are genuinely dangerous.
 *
 * Drupal render arrays are associative arrays whose `#`-prefixed keys have wildly
 * different security semantics. Values under presentation keys (`#title`,
 * `#description`, `#default_value`, ...) are auto-escaped by Twig at render time,
 * so untrusted data there is NOT an XSS sink. But a handful of keys are raw HTML
 * (`#markup`, `#template`, `#children`) or executable callbacks (`#pre_render`,
 * `#lazy_builder`, `#access_callback`, ...). Without this distinction every
 * tainted render-array value would be reported — the dominant false-positive
 * source in Drupal taint analysis.
 *
 * Behaviour: for a `#`-prefixed key that is NOT in {@see self::DANGEROUS_KEYS}
 * we return `['html']`, telling Psalm to drop the `html` taint from that value.
 * For the dangerous keys (and any non-`#` key) we remove nothing, so taint flows
 * through to the render sink and is reported.
 *
 * Ported and maintained from mortenson/psalm-plugin-drupal's RenderArrayTainter
 * (LGPL-2.1-only, Sam Mortenson) so this project owns the Drupal taint layer
 * without depending on that unmaintained package. Keep DANGEROUS_KEYS in sync
 * with Drupal core's render-array contract.
 */
final class RenderArrayTainter implements RemoveTaintsInterface
{
    /**
     * Render-array keys whose values are raw HTML or executable callbacks.
     * Taint reaching these is a real XSS / RCE sink and must be preserved.
     *
     * @var list<string>
     */
    private const DANGEROUS_KEYS = [
        // Code execution — value is a callable/callback invoked by the renderer.
        '#access_callback',
        '#ajax',
        '#after_build',
        '#element_validate',
        '#lazy_builder',
        '#post_render',
        '#pre_render',
        '#process',
        '#submit',
        '#validate',
        '#value_callback',
        '#file_value_callbacks',
        '#date_date_callbacks',
        '#date_time_callbacks',
        '#captcha_validate',
        // Cross-site scripting — value is emitted as raw, unescaped HTML.
        '#markup',
        '#template',
        '#children',
    ];

    /**
     * @return list<string>
     */
    public static function removeTaints(AddRemoveTaintsEvent $event): array
    {
        $item = $event->getExpr();
        $statements_analyzer = $event->getStatementsSource();
        if (!($item instanceof ArrayItem) || !($statements_analyzer instanceof StatementsAnalyzer)) {
            return [];
        }

        $item_key_value = '';
        if ($item->key) {
            $item_key_type = $statements_analyzer->node_data->getType($item->key);
            if ($item_key_type && $item_key_type->isSingleStringLiteral()) {
                $item_key_value = $item_key_type->getSingleStringLiteral()->value;
            }
        }

        if (
            isset($item_key_value[0])
            && $item_key_value[0] === '#'
            && !in_array($item_key_value, self::DANGEROUS_KEYS, true)
        ) {
            // Safe presentation key — Twig auto-escapes it; drop the html taint.
            return ['html'];
        }

        return [];
    }
}
