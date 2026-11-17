<?php

declare(strict_types=1);

namespace DrupalSecurityPsalm;

use PhpParser\Node\Expr\ArrayDimFetch;
use PhpParser\Node\Scalar\String_;
use Psalm\Plugin\EventHandler\AddTaintsInterface;
use Psalm\Plugin\EventHandler\Event\AddRemoveTaintsEvent;
use Psalm\Type\TaintKindGroup;

/**
 * Marks reads of value-bearing render/form-element keys as untrusted input.
 *
 * Drupal's render and Form APIs hand callbacks an `$element` (or `$form`) array
 * whose `#`-prefixed value keys are populated by the framework from field values,
 * config, and user submissions — e.g. a #process / #pre_render / value callback
 * reads `$element['#value']` or `$element['#json']`. From Psalm's view that data
 * "appears from nowhere" (the framework sets it dynamically), so taint analysis
 * never sees it as a source and misses the resulting XSS. This hook adds input
 * taint to those reads so the flow into a sink (#markup, FormattableMarkup, ...)
 * is tracked.
 *
 * Scoped to VALUE keys only (not structural keys like #type/#theme/#attributes)
 * to keep false positives down.
 */
final class RenderElementSource implements AddTaintsInterface
{
    /**
     * Render/form element keys that carry raw, potentially user-controlled values.
     *
     * @var list<string>
     */
    private const VALUE_KEYS = [
        '#value',
        '#text',
        '#json',
        '#default_value',
        '#raw_value',
        '#return_value',
    ];

    /**
     * @return list<string>
     */
    public static function addTaints(AddRemoveTaintsEvent $event): array
    {
        $expr = $event->getExpr();
        if (!($expr instanceof ArrayDimFetch) || !($expr->dim instanceof String_)) {
            return [];
        }
        if (!in_array($expr->dim->value, self::VALUE_KEYS, true)) {
            return [];
        }
        // Treat as user input — taints with the full input group so it reaches
        // every sink kind, exactly like an @psalm-taint-source input.
        return TaintKindGroup::ALL_INPUT;
    }
}
