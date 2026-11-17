<?php

declare(strict_types=1);

namespace DrupalSecurityPsalm;

use PhpParser\Node\Expr\PropertyFetch;
use Psalm\Internal\Analyzer\StatementsAnalyzer;
use Psalm\Plugin\EventHandler\AddTaintsInterface;
use Psalm\Plugin\EventHandler\Event\AddRemoveTaintsEvent;
use Psalm\Type\Atomic\TNamedObject;
use Psalm\Type\TaintKindGroup;

/**
 * Marks reads of Drupal field properties as untrusted input.
 *
 * Field data is read via magic properties — `$entity->get('field')->value`,
 * `->target_id`, `->uri`, `$node->field_foo->value`, etc. Psalm does not route
 * these magic reads through the annotated `__get`, so the stored (user-entered)
 * value loses its taint. Field values are THE most common stored-XSS source in
 * Drupal, so this is high-value.
 *
 * The hook fires on any property READ (`$x->prop`, not method calls) whose
 * object is a Field item / item-list type. It is gated on the object type so we
 * don't taint every `->value` in the codebase (precision).
 */
final class FieldValueSource implements AddTaintsInterface
{
    /**
     * @return list<string>
     */
    public static function addTaints(AddRemoveTaintsEvent $event): array
    {
        $expr = $event->getExpr();
        $statements_analyzer = $event->getStatementsSource();
        if (!($expr instanceof PropertyFetch) || !($statements_analyzer instanceof StatementsAnalyzer)) {
            return [];
        }

        $object_type = $statements_analyzer->node_data->getType($expr->var);
        if ($object_type === null) {
            return [];
        }

        foreach ($object_type->getAtomicTypes() as $atomic) {
            if ($atomic instanceof TNamedObject && self::isFieldType($atomic->value)) {
                // Field property values are user/stored data — taint as input.
                return TaintKindGroup::ALL_INPUT;
            }
        }

        return [];
    }

    /**
     * A field item or item-list type, whose property reads are field values.
     * Matches the interfaces/bases by name (covers FieldItemListInterface,
     * FieldItemList, FieldItemInterface, FieldItem, EntityReferenceFieldItemList,
     * and the *Item concrete types via the "fielditem" stem).
     */
    private static function isFieldType(string $fqcn): bool
    {
        $name = strtolower(ltrim($fqcn, '\\'));
        return str_contains($name, 'fielditem')
            || str_contains($name, 'field\\fielditem')
            || str_ends_with($name, '\\fielditemlist')
            || str_ends_with($name, '\\fielditemlistinterface');
    }
}
