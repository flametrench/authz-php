<?php

// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Flametrench\Authz;

use Flametrench\Authz\Exceptions\DuplicateTupleException;
use Flametrench\Authz\Exceptions\EmptyRelationSetException;
use Flametrench\Authz\Exceptions\InvalidFormatException;
use Flametrench\Authz\Exceptions\TupleNotFoundException;
use Flametrench\Ids\Id;

/**
 * Reference in-memory TupleStore. O(1) check() via secondary natural-key
 * index; deterministic for tests.
 */
final class InMemoryTupleStore implements TupleStore
{
    /** @var array<string, Tuple> */
    private array $tuples = [];

    /** @var array<string, string> Natural key → tuple id. */
    private array $keyIndex = [];

    /** @var callable(): \DateTimeImmutable */
    private $clock;

    public function __construct(?callable $clock = null)
    {
        $this->clock = $clock ?? static fn(): \DateTimeImmutable => new \DateTimeImmutable();
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
        $key = self::naturalKey($subjectType, $subjectId, $relation, $objectType, $objectId);
        $tupId = $this->keyIndex[$key] ?? null;
        return new CheckResult(allowed: $tupId !== null, matchedTupleId: $tupId);
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
            $key = self::naturalKey($subjectType, $subjectId, $relation, $objectType, $objectId);
            if (isset($this->keyIndex[$key])) {
                return new CheckResult(allowed: true, matchedTupleId: $this->keyIndex[$key]);
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
