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
use PDO;

/**
 * PostgresTupleStore — Postgres-backed implementation of TupleStore.
 *
 * v0.3 (ADR 0017): accepts an optional `rules` parameter in the
 * constructor. When supplied, check() evaluates rewrite rules using
 * the same iterative algorithm as InMemoryTupleStore (ADR 0007), with
 * each tuple lookup issued as a single indexed SELECT against the
 * database. When rules is null (default), check()/checkAny() are
 * exact-match only — byte-identical to v0.2 behavior.
 *
 * PHP has no async, so callbacks are synchronous PDO queries; the
 * existing Evaluator works as-is once the store implements the callbacks.
 *
 * Multi-SDK transaction nesting (ADR 0013): write methods cooperate by
 * using SAVEPOINT/RELEASE when inside an outer transaction.
 */
final class PostgresTupleStore implements TupleStore
{
    /** @var callable(): \DateTimeImmutable */
    private $clock;

    /** @var array<string, array<string, list<\Flametrench\Authz\RewriteRules\RuleNode>>>|null */
    private ?array $rules;

    private int $maxDepth;

    private int $maxFanOut;

    /**
     * @param  array<string, array<string, list<\Flametrench\Authz\RewriteRules\RuleNode>>>|null  $rules
     *   v0.3 (ADR 0017): optional rewrite rules. With null, check()
     *   behaves byte-identically to v0.2 (exact match only).
     */
    public function __construct(
        private readonly PDO $pdo,
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

    /**
     * Run $fn with savepoint shielding when inside an outer transaction, or
     * unwrapped when standalone (zero overhead). See ADR 0013 — wraps
     * single-statement writes so a constraint violation rolls back only
     * the inner statement instead of poisoning the outer transaction
     * (Postgres SQLSTATE 25P02 on subsequent statements until ROLLBACK).
     *
     * @template T
     * @param callable(): T $fn
     * @return T
     */
    private function nested(callable $fn): mixed
    {
        if (!$this->pdo->inTransaction()) {
            return $fn();
        }
        $savepoint = self::savepointName(self::callerName());
        $this->pdo->exec('SAVEPOINT ' . $savepoint);
        try {
            $result = $fn();
            $this->pdo->exec('RELEASE SAVEPOINT ' . $savepoint);
            return $result;
        } catch (\Throwable $e) {
            try {
                $this->pdo->exec('ROLLBACK TO SAVEPOINT ' . $savepoint);
                $this->pdo->exec('RELEASE SAVEPOINT ' . $savepoint);
            } catch (\Throwable) {
                // Surface the original error.
            }
            throw $e;
        }
    }

    /** Read the immediate caller of the function that called this helper. */
    private static function callerName(): string
    {
        $bt = \debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS, 3);
        return (string) ($bt[2]['function'] ?? 'tx');
    }

    /** Build a savepoint name matching ADR 0013: `ft_<method>_<random>`. */
    private static function savepointName(string $method): string
    {
        $method = preg_replace('/[^A-Za-z0-9]/', '', $method) ?? '';
        if ($method === '') {
            $method = 'tx';
        }
        return 'ft_' . $method . '_' . bin2hex(random_bytes(4));
    }

    private static function wireToUuid(string $wireId): string
    {
        return Id::decode($wireId)['uuid'];
    }

    /**
     * Decode an `object_id` to a Postgres-bindable UUID string.
     *
     * `object_type` is application-defined (per spec/docs/authorization.md
     * and ADR 0001), so `object_id` may legitimately arrive as:
     *   1. A wire-format ID with a non-registered prefix (e.g. `proj_<hex>`,
     *      `file_<hex>`) — extract the UUID via `Id::decodeAny` so app-
     *      defined prefixes are accepted in addition to registered types.
     *   2. A raw 32-character hex UUID — accept as-is; Postgres UUID
     *      parsing handles both 32-hex and hyphenated forms.
     *   3. A canonical hyphenated UUID — also accepted as-is.
     *
     * Closes spec#8 (`PostgresTupleStore` previously bound `$objectId`
     * directly into a UUID column, which crashed when adopters passed
     * wire-format IDs with app-defined prefixes).
     */
    private static function objectIdToUuid(string $objectId): string
    {
        if (preg_match('/^[a-z]{2,6}_[0-9a-f]{32}$/', $objectId) === 1) {
            return Id::decodeAny($objectId)['uuid'];
        }
        return $objectId;
    }

    /** @param array<string, mixed> $row */
    private static function rowToTuple(array $row): Tuple
    {
        return new Tuple(
            id: Id::encode('tup', (string) $row['id']),
            subjectType: (string) $row['subject_type'],
            subjectId: Id::encode('usr', (string) $row['subject_id']),
            relation: (string) $row['relation'],
            objectType: (string) $row['object_type'],
            objectId: (string) $row['object_id'],
            createdAt: new \DateTimeImmutable((string) $row['created_at']),
            createdBy: $row['created_by'] !== null
                ? Id::encode('usr', (string) $row['created_by'])
                : null,
        );
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
        return $this->nested(function () use (
            $subjectType,
            $subjectId,
            $relation,
            $objectType,
            $objectId,
            $createdBy,
        ) {
            $id = Id::decode(Id::generate('tup'))['uuid'];
            $subjectUuid = self::wireToUuid($subjectId);
            $objectUuid = self::objectIdToUuid($objectId);
            $createdByUuid = $createdBy !== null ? self::wireToUuid($createdBy) : null;
            $now = $this->now()->format('Y-m-d H:i:s.uP');

            // ON CONFLICT DO NOTHING avoids raising a 23505 inside the
            // outer transaction (ADR 0013 — see class docblock). When the
            // natural-key UNIQUE fires, the INSERT returns no rows; we
            // then read the existing row and raise DuplicateTupleException.
            $stmt = $this->pdo->prepare(
                'INSERT INTO tup (id, subject_type, subject_id, relation, object_type, object_id, created_at, created_by)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                 ON CONFLICT (subject_type, subject_id, relation, object_type, object_id) DO NOTHING
                 RETURNING id, subject_type, subject_id, relation, object_type, object_id, created_at, created_by'
            );
            $stmt->execute([
                $id, $subjectType, $subjectUuid, $relation, $objectType, $objectUuid, $now, $createdByUuid,
            ]);
            $row = $stmt->fetch(PDO::FETCH_ASSOC);
            if ($row !== false) {
                /** @var array<string, mixed> $row */
                return self::rowToTuple($row);
            }
            $sel = $this->pdo->prepare(
                'SELECT id FROM tup
                 WHERE subject_type = ? AND subject_id = ? AND relation = ?
                   AND object_type = ? AND object_id = ?'
            );
            $sel->execute([$subjectType, $subjectUuid, $relation, $objectType, $objectUuid]);
            $existing = $sel->fetch(PDO::FETCH_ASSOC);
            if ($existing === false) {
                // Race: another connection inserted-and-deleted between our
                // INSERT-on-conflict and our SELECT. Surface a generic
                // PDOException-style error so callers can retry.
                throw new \RuntimeException(
                    'Tuple natural-key conflict resolved after insert lost the row; retry.',
                );
            }
            throw new DuplicateTupleException(
                'Tuple with identical natural key already exists',
                Id::encode('tup', (string) $existing['id']),
            );
        });
    }

    public function deleteTuple(string $tupleId): void
    {
        $this->nested(function () use ($tupleId) {
            $stmt = $this->pdo->prepare('DELETE FROM tup WHERE id = ?');
            $stmt->execute([self::wireToUuid($tupleId)]);
            if ($stmt->rowCount() === 0) {
                throw new TupleNotFoundException("Tuple {$tupleId} not found");
            }
            return null;
        });
    }

    public function cascadeRevokeSubject(string $subjectType, string $subjectId): int
    {
        return $this->nested(function () use ($subjectType, $subjectId) {
            $stmt = $this->pdo->prepare(
                'DELETE FROM tup WHERE subject_type = ? AND subject_id = ?'
            );
            $stmt->execute([$subjectType, self::wireToUuid($subjectId)]);
            return $stmt->rowCount();
        });
    }

    /**
     * Direct lookup callback for the Evaluator: returns tup_wire_id|null.
     * Issued as a single indexed SELECT; no rules expansion here.
     */
    private function directLookup(
        string $subjectType,
        string $subjectId,
        string $relation,
        string $objectType,
        string $objectId,
    ): ?string {
        try {
            $subjUuid = self::wireToUuid($subjectId);
            $objUuid = self::objectIdToUuid($objectId);
        } catch (\Throwable) {
            return null;
        }
        $stmt = $this->pdo->prepare(
            'SELECT id FROM tup
             WHERE subject_type = ? AND subject_id = ?
               AND relation = ? AND object_type = ? AND object_id = ?
             LIMIT 1'
        );
        $stmt->execute([$subjectType, $subjUuid, $relation, $objectType, $objUuid]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        return $row !== false ? Id::encode('tup', (string) $row['id']) : null;
    }

    /**
     * ListByObject callback for the Evaluator: returns iterable of
     * [subjectType, subjectId, tupId] for tuple_to_userset expansion.
     *
     * @return list<array{0: string, 1: string, 2: string}>
     */
    private function listByObject(
        string $objectType,
        string $objectId,
        ?string $relation,
    ): array {
        try {
            $objUuid = self::objectIdToUuid($objectId);
        } catch (\Throwable) {
            return [];
        }
        $sql = 'SELECT id, subject_type, subject_id FROM tup WHERE object_type = ? AND object_id = ?';
        $params = [$objectType, $objUuid];
        if ($relation !== null) {
            $sql .= ' AND relation = ?';
            $params[] = $relation;
        }
        $stmt = $this->pdo->prepare($sql);
        $stmt->execute($params);
        $out = [];
        foreach ($stmt->fetchAll(PDO::FETCH_ASSOC) as $row) {
            $subjectType = (string) $row['subject_type'];
            $subjectId = Id::encode($subjectType, (string) $row['subject_id']);
            $out[] = [$subjectType, $subjectId, Id::encode('tup', (string) $row['id'])];
        }
        return $out;
    }

    public function check(
        string $subjectType,
        string $subjectId,
        string $relation,
        string $objectType,
        string $objectId,
    ): CheckResult {
        if ($this->rules === null) {
            return $this->checkAny($subjectType, $subjectId, [$relation], $objectType, $objectId);
        }
        // Rule-aware path (ADR 0017): drive the Evaluator with PDO callbacks.
        $result = Evaluator::evaluate(
            $this->rules,
            $subjectType,
            $subjectId,
            $relation,
            $objectType,
            $objectId,
            fn($st, $si, $rel, $ot, $oi) => $this->directLookup($st, $si, $rel, $ot, $oi),
            fn($ot, $oi, $rel) => $this->listByObject($ot, $oi, $rel),
            $this->maxDepth,
            $this->maxFanOut,
        );
        return new CheckResult(
            allowed: $result['allowed'],
            matchedTupleId: $result['matchedTupleId'],
        );
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
        // Rule-aware path: iterate relations one at a time (ADR 0017).
        if ($this->rules !== null) {
            foreach ($relations as $rel) {
                if (preg_match(Patterns::RELATION_NAME, $rel) !== 1) {
                    throw new InvalidFormatException(
                        "relation '{$rel}' must match " . Patterns::RELATION_NAME,
                        'relation',
                    );
                }
                $r = $this->check($subjectType, $subjectId, $rel, $objectType, $objectId);
                if ($r->allowed) return $r;
            }
            return new CheckResult(allowed: false, matchedTupleId: null);
        }
        // Fast path: no rules — single SQL query with relation = ANY.
        foreach ($relations as $rel) {
            if (preg_match(Patterns::RELATION_NAME, $rel) !== 1) {
                throw new InvalidFormatException(
                    "relation '{$rel}' must match " . Patterns::RELATION_NAME,
                    'relation',
                );
            }
        }
        $stmt = $this->pdo->prepare(
            'SELECT id FROM tup
             WHERE subject_type = ? AND subject_id = ?
               AND relation = ANY(?) AND object_type = ? AND object_id = ?
             LIMIT 1'
        );
        $stmt->execute([
            $subjectType,
            self::wireToUuid($subjectId),
            '{' . implode(',', array_map(fn(string $r) => '"' . $r . '"', $relations)) . '}',
            $objectType,
            self::objectIdToUuid($objectId),
        ]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        if ($row === false) {
            return new CheckResult(allowed: false, matchedTupleId: null);
        }
        return new CheckResult(
            allowed: true,
            matchedTupleId: Id::encode('tup', (string) $row['id']),
        );
    }

    public function getTuple(string $tupleId): Tuple
    {
        $stmt = $this->pdo->prepare(
            'SELECT id, subject_type, subject_id, relation, object_type, object_id, created_at, created_by
             FROM tup WHERE id = ?'
        );
        $stmt->execute([self::wireToUuid($tupleId)]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        if ($row === false) {
            throw new TupleNotFoundException("Tuple {$tupleId} not found");
        }
        return self::rowToTuple($row);
    }

    public function listTuplesBySubject(
        string $subjectType,
        string $subjectId,
        ?string $cursor = null,
        int $limit = 50,
    ): Page {
        $limit = min($limit, 200);
        $params = [$subjectType, self::wireToUuid($subjectId)];
        $sql = 'SELECT id, subject_type, subject_id, relation, object_type, object_id, created_at, created_by
                FROM tup
                WHERE subject_type = ? AND subject_id = ?';
        if ($cursor !== null) {
            $sql .= ' AND id > ?';
            $params[] = self::wireToUuid($cursor);
        }
        $sql .= ' ORDER BY id LIMIT ?';
        $params[] = $limit + 1;
        $stmt = $this->pdo->prepare($sql);
        $stmt->execute($params);
        $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
        return self::paginate($rows, $limit);
    }

    public function listTuplesByObject(
        string $objectType,
        string $objectId,
        ?string $relation = null,
        ?string $cursor = null,
        int $limit = 50,
    ): Page {
        $limit = min($limit, 200);
        $params = [$objectType, self::objectIdToUuid($objectId)];
        $sql = 'SELECT id, subject_type, subject_id, relation, object_type, object_id, created_at, created_by
                FROM tup
                WHERE object_type = ? AND object_id = ?';
        if ($relation !== null) {
            $sql .= ' AND relation = ?';
            $params[] = $relation;
        }
        if ($cursor !== null) {
            $sql .= ' AND id > ?';
            $params[] = self::wireToUuid($cursor);
        }
        $sql .= ' ORDER BY id LIMIT ?';
        $params[] = $limit + 1;
        $stmt = $this->pdo->prepare($sql);
        $stmt->execute($params);
        $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
        return self::paginate($rows, $limit);
    }

    /**
     * @param  array<int, array<string, mixed>>  $rows
     * @return Page<Tuple>
     */
    private static function paginate(array $rows, int $limit): Page
    {
        $page = array_slice($rows, 0, $limit);
        $tuples = array_map(self::rowToTuple(...), $page);
        $next = count($rows) > $limit && count($tuples) > 0
            ? $tuples[count($tuples) - 1]->id
            : null;
        return new Page(data: $tuples, nextCursor: $next);
    }

}
