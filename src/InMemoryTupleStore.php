<?php

// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Flametrench\Authz;

use Flametrench\Authz\Exceptions\DuplicateTupleException;
use Flametrench\Authz\Exceptions\EmptyRelationSetException;
use Flametrench\Authz\Exceptions\InvalidFormatException;
use Flametrench\Authz\Exceptions\TupleNotFoundException;
use Flametrench\Authz\RewriteRules\Evaluator;
use Flametrench\Ids\Id;

/**
 * Reference in-memory TupleStore. O(1) check() via secondary natural-key
 * index; deterministic for tests.
 *
 * v0.2 adds optional rewrite-rule support. When `$rules` is null
 * (the default), behavior is byte-identical to v0.1 — a direct
 * natural-key lookup is the only check path. When rules are provided,
 * `check()` evaluates them on direct-lookup miss per ADR 0007.
 */
final class InMemoryTupleStore implements TupleStore
{
    /** @var array<string, Tuple> */
    private array $tuples = [];

    /** @var array<string, string> Natural key → tuple id. */
    private array $keyIndex = [];

    /** @var callable(): \DateTimeImmutable */
    private $clock;

    /** @var array<string, array<string, list<\Flametrench\Authz\RewriteRules\RuleNode>>>|null */
    private ?array $rules;

    private int $maxDepth;

    private int $maxFanOut;

    /**
     * @param  array<string, array<string, list<\Flametrench\Authz\RewriteRules\RuleNode>>>|null  $rules
     *   v0.2: optional rewrite rules. With null, the store behaves
     *   byte-identically to v0.1.
     */
    public function __construct(
        ?callable $clock = null,
        ?array $rules = null,
        int $maxDepth = Evaluator::DEFAULT_MAX_DEPTH,
        int $maxFanOut = Evaluator::DEFAULT_MAX_FAN_OUT,
    ) {
        $this->clock = $clock ?? static fn(): \DateTimeImmutable => new \DateTimeImmutable();
        $this->rules = $rules;
        $this->maxDepth = $maxDepth;
        $this->maxFanOut = $maxFanOut;
    }

    private function now(): \DateTimeImmutable
    {
        return ($this->clock)();
    }

    private static function naturalKey(
        string $subjectType,
        string $subjectId,
        string $relation,
        string $objectType,
        string $objectId,
    ): string {
        return "{$subjectType}|{$subjectId}|{$relation}|{$objectType}|{$objectId}";
    }

    private static function validate(string $relation, string $objectType): void
    {
        if (preg_match(Patterns::RELATION_NAME, $relation) !== 1) {
            throw new InvalidFormatException(
                "relation '{$relation}' must match " . Patterns::RELATION_NAME,
                'relation',
            );
        }
        if (preg_match(Patterns::TYPE_PREFIX, $objectType) !== 1) {
            throw new InvalidFormatException(
                "objectType '{$objectType}' must match " . Patterns::TYPE_PREFIX,
                'object_type',
            );
        }
    }

    public function createTuple(
        string $subjectType,
        string $subjectId,
        string $relation,
        string $objectType,
        string $objectId,
        ?string $createdBy = null,
    ): Tuple {
        self::validate($relation, $objectType);
        $key = self::naturalKey($subjectType, $subjectId, $relation, $objectType, $objectId);
        if (isset($this->keyIndex[$key])) {
            throw new DuplicateTupleException(
                'Tuple with identical natural key already exists',
                $this->keyIndex[$key],
            );
        }
        $tup = new Tuple(
            id: Id::generate('tup'),
            subjectType: $subjectType,
            subjectId: $subjectId,
            relation: $relation,
            objectType: $objectType,
            objectId: $objectId,
            createdAt: $this->now(),
            createdBy: $createdBy,
        );
        $this->tuples[$tup->id] = $tup;
        $this->keyIndex[$key] = $tup->id;
        return $tup;
    }

    public function deleteTuple(string $tupleId): void
    {
        if (!isset($this->tuples[$tupleId])) {
            throw new TupleNotFoundException("Tuple {$tupleId} not found");
        }
        $tup = $this->tuples[$tupleId];
        unset($this->tuples[$tupleId]);
        unset($this->keyIndex[self::naturalKey(
            $tup->subjectType,
            $tup->subjectId,
            $tup->relation,
            $tup->objectType,
            $tup->objectId,
        )]);
    }

    public function cascadeRevokeSubject(string $subjectType, string $subjectId): int
    {
        $n = 0;
        foreach ($this->tuples as $id => $tup) {
            if ($tup->subjectType === $subjectType && $tup->subjectId === $subjectId) {
                unset($this->tuples[$id]);
                unset($this->keyIndex[self::naturalKey(
                    $tup->subjectType,
                    $tup->subjectId,
                    $tup->relation,
                    $tup->objectType,
                    $tup->objectId,
                )]);
                $n++;
            }
        }
        return $n;
    }

    public function check(
        string $subjectType,
        string $subjectId,
        string $relation,
        string $objectType,
        string $objectId,
    ): CheckResult {
        // v0.1 fast path: direct natural-key lookup. Returns immediately
        // on a direct hit regardless of whether rules are registered.
        $key = self::naturalKey($subjectType, $subjectId, $relation, $objectType, $objectId);
        $tupId = $this->keyIndex[$key] ?? null;
        if ($tupId !== null) {
            return new CheckResult(allowed: true, matchedTupleId: $tupId);
        }

        // v0.2 path: rule expansion only on direct miss AND rules registered.
        if ($this->rules === null) {
            return new CheckResult(allowed: false, matchedTupleId: null);
        }

        $result = Evaluator::evaluate(
            rules: $this->rules,
            subjectType: $subjectType,
            subjectId: $subjectId,
            relation: $relation,
            objectType: $objectType,
            objectId: $objectId,
            directLookup: $this->directLookup(...),
            listByObject: $this->listByObject(...),
            maxDepth: $this->maxDepth,
            maxFanOut: $this->maxFanOut,
        );
        return new CheckResult(
            allowed: $result['allowed'],
            matchedTupleId: $result['matchedTupleId'],
        );
    }

    /** Direct natural-key lookup callback for the rule evaluator. */
    private function directLookup(
        string $subjectType,
        string $subjectId,
        string $relation,
        string $objectType,
        string $objectId,
    ): ?string {
        return $this->keyIndex[self::naturalKey($subjectType, $subjectId, $relation, $objectType, $objectId)] ?? null;
    }

    /**
     * Enumerate tuples on an object by relation. Used by tuple_to_userset.
     *
     * @return iterable<array{0: string, 1: string, 2: string}>
     */
    private function listByObject(string $objectType, string $objectId, ?string $relation): iterable
    {
        foreach ($this->tuples as $t) {
            if ($t->objectType !== $objectType || $t->objectId !== $objectId) {
                continue;
            }
            if ($relation !== null && $t->relation !== $relation) {
                continue;
            }
            yield [$t->subjectType, $t->subjectId, $t->id];
        }
    }

    public function checkAny(
        string $subjectType,
        string $subjectId,
        array $relations,
        string $objectType,
        string $objectId,
    ): CheckResult {
        if (count($relations) === 0) {
            throw new EmptyRelationSetException();
        }
        foreach ($relations as $relation) {
            // Reuse rule-aware check() so checkAny benefits from rewrites.
            $result = $this->check($subjectType, $subjectId, $relation, $objectType, $objectId);
            if ($result->allowed) {
                return $result;
            }
        }
        return new CheckResult(allowed: false, matchedTupleId: null);
    }

    public function getTuple(string $tupleId): Tuple
    {
        return $this->tuples[$tupleId]
            ?? throw new TupleNotFoundException("Tuple {$tupleId} not found");
    }

    public function listTuplesBySubject(
        string $subjectType,
        string $subjectId,
        ?string $cursor = null,
        int $limit = 50,
    ): Page {
        $matching = array_values(array_filter(
            $this->tuples,
            fn(Tuple $t) => $t->subjectType === $subjectType && $t->subjectId === $subjectId,
        ));
        usort($matching, fn(Tuple $a, Tuple $b) => strcmp($a->id, $b->id));
        return $this->paginate($matching, $cursor, $limit);
    }

    public function listTuplesByObject(
        string $objectType,
        string $objectId,
        ?string $relation = null,
        ?string $cursor = null,
        int $limit = 50,
    ): Page {
        $matching = array_values(array_filter(
            $this->tuples,
            fn(Tuple $t) => $t->objectType === $objectType
                && $t->objectId === $objectId
                && ($relation === null || $t->relation === $relation),
        ));
        usort($matching, fn(Tuple $a, Tuple $b) => strcmp($a->id, $b->id));
        return $this->paginate($matching, $cursor, $limit);
    }

    /**
     * @param list<Tuple> $all
     * @return Page<Tuple>
     */
    private function paginate(array $all, ?string $cursor, int $limit): Page
    {
        if ($cursor !== null) {
            $startIdx = 0;
            foreach ($all as $i => $item) {
                if ($item->id > $cursor) {
                    $startIdx = $i;
                    break;
                }
                $startIdx = $i + 1;
            }
        } else {
            $startIdx = 0;
        }
        $slice = array_slice($all, $startIdx, $limit);
        $next = ($startIdx + $limit) < count($all) && count($slice) > 0
            ? $slice[count($slice) - 1]->id
            : null;
        return new Page(data: $slice, nextCursor: $next);
    }
}
