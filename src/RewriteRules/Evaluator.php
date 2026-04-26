<?php

// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Flametrench\Authz\RewriteRules;

use Flametrench\Authz\Exceptions\EvaluationLimitExceededException;

/**
 * Authorization rewrite-rule evaluator — v0.2 reference per ADR 0007.
 *
 * Layered exactly as the ADR prescribes:
 *   1. Direct lookup. If a tuple matches, return it. v0.1 fast path.
 *   2. Rule expansion. If a rule exists for (objectType, relation),
 *      expand its primitives. Each primitive recurses with bounded
 *      depth and tracks a frame stack for cycle detection.
 *   3. Short-circuit on first match. Union semantics; any sub-eval
 *      returning allowed ends the evaluation.
 */
final class Evaluator
{
    public const DEFAULT_MAX_DEPTH = 8;

    public const DEFAULT_MAX_FAN_OUT = 1024;

    /**
     * @param  array<string, array<string, list<RuleNode>>>|null  $rules
     * @param  callable(string, string, string, string, string): ?string  $directLookup
     *   (subjectType, subjectId, relation, objectType, objectId) → tup_id|null
     * @param  callable(string, string, ?string): iterable<array{0: string, 1: string, 2: string}>  $listByObject
     *   (objectType, objectId, relation) → iterable of [subjectType, subjectId, tupId]
     * @return array{allowed: bool, matchedTupleId: ?string}
     */
    public static function evaluate(
        ?array $rules,
        string $subjectType,
        string $subjectId,
        string $relation,
        string $objectType,
        string $objectId,
        callable $directLookup,
        callable $listByObject,
        int $maxDepth = self::DEFAULT_MAX_DEPTH,
        int $maxFanOut = self::DEFAULT_MAX_FAN_OUT,
    ): array {
        $go = function (
            string $relation,
            string $objectType,
            string $objectId,
            array $stack,
            int $depth,
        ) use (
            $rules,
            $subjectType,
            $subjectId,
            $directLookup,
            $listByObject,
            $maxDepth,
            $maxFanOut,
            &$go,
        ): array {
            // 1. Direct lookup.
            $direct = $directLookup($subjectType, $subjectId, $relation, $objectType, $objectId);
            if ($direct !== null) {
                return ['allowed' => true, 'matchedTupleId' => $direct];
            }

            // 2. Rule expansion.
            if ($rules === null) {
                return ['allowed' => false, 'matchedTupleId' => null];
            }
            $rule = $rules[$objectType][$relation] ?? null;
            if ($rule === null) {
                return ['allowed' => false, 'matchedTupleId' => null];
            }

            // Cycle detection.
            $frameKey = "{$relation}|{$objectType}|{$objectId}";
            if (in_array($frameKey, $stack, true)) {
                return ['allowed' => false, 'matchedTupleId' => null];
            }

            // Depth bound.
            if ($depth >= $maxDepth) {
                throw new EvaluationLimitExceededException(
                    "Rule evaluation exceeded depth limit ({$maxDepth}) at {$objectType}.{$relation} for {$objectType}_{$objectId}",
                );
            }

            $newStack = [...$stack, $frameKey];

            foreach ($rule as $node) {
                if ($node instanceof ThisNode) {
                    // Already covered by step 1.
                    continue;
                }
                if ($node instanceof ComputedUserset) {
                    $result = $go($node->relation, $objectType, $objectId, $newStack, $depth + 1);
                    if ($result['allowed']) {
                        return $result;
                    }
                    continue;
                }
                if ($node instanceof TupleToUserset) {
                    $related = [];
                    foreach ($listByObject($objectType, $objectId, $node->tuplesetRelation) as $tuple) {
                        $related[] = $tuple;
                    }
                    if (count($related) > $maxFanOut) {
                        $count = count($related);
                        throw new EvaluationLimitExceededException(
                            "tuple_to_userset fan-out exceeded ({$count} > {$maxFanOut}) at {$objectType}.{$relation} via {$node->tuplesetRelation}",
                        );
                    }
                    foreach ($related as [$relSubType, $relSubId, $_tupId]) {
                        $result = $go(
                            $node->computedUsersetRelation,
                            $relSubType,
                            $relSubId,
                            $newStack,
                            $depth + 1,
                        );
                        if ($result['allowed']) {
                            return $result;
                        }
                    }
                    continue;
                }
                throw new \LogicException('Unknown rule node: '.$node::class);
            }

            return ['allowed' => false, 'matchedTupleId' => null];
        };

        return $go($relation, $objectType, $objectId, [], 0);
    }
}
