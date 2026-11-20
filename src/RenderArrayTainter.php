<?php

declare(strict_types=1);

namespace DrupalSecurityPsalm;

use PhpParser\Node\ArrayItem;
use PhpParser\Node\Expr;
use PhpParser\Node\Scalar\String_;
use Psalm\Plugin\EventHandler\Event\AddRemoveTaintsEvent;
use Psalm\Plugin\EventHandler\RemoveTaintsInterface;

/**
 * Clears HTML taint from render-array values that Drupal escapes on output.
 *
 * A render array reaching the renderer is an HTML sink, but most of its keys
 * are printed through Twig, which escapes them: a user-supplied `#title` or
 * `#description` is not XSS. Only those keys are listed here. Every other key —
 * `#markup`, `#children`, `#prefix`, `#template`, callbacks, and any key a
 * contributed element invents — keeps its taint, so an unknown key errs on the
 * side of reporting rather than hiding a flow.
 *
 * Keys are read from the syntax tree, so this uses no Psalm-internal API. Only
 * the literal form `['#title' => $x]` can be handled: Psalm dispatches no
 * taint-removal event for `$build['#title'] = $x`, so that form is still
 * reported (pinned as a known false positive in tests/fixtures/render_array.php).
 */
final class RenderArrayTainter implements RemoveTaintsInterface
{
    /**
     * Render and form API keys whose values Drupal escapes when rendering.
     *
     * Each is printed by a core template through Twig autoescaping (or, for
     * #attributes, the Attribute class). Keep this list conservative: adding a
     * key that can be output unescaped would hide real XSS.
     */
    private const ESCAPED_KEYS = [
        '#alt',
        '#attributes',
        '#caption',
        '#default_value',
        '#description',
        '#empty',
        '#empty_option',
        '#field_prefix',
        '#field_suffix',
        '#header',
        '#items',
        '#options',
        '#placeholder',
        '#plain_text',
        '#rows',
        '#title',
    ];

    /**
     * @return list<string>
     */
    public static function removeTaints(AddRemoveTaintsEvent $event): array
    {
        $key = self::renderKey($event->getExpr());
        return $key !== null && in_array($key, self::ESCAPED_KEYS, true) ? ['html'] : [];
    }

    /**
     * The literal render-array key an expression writes to, if any.
     */
    private static function renderKey(Expr|ArrayItem $expr): ?string
    {
        if (!$expr instanceof ArrayItem) {
            return null;
        }
        $key = $expr->key;
        return $key instanceof String_ && str_starts_with($key->value, '#') ? $key->value : null;
    }
}
