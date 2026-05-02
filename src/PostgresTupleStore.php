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
use PDO;

/**
 * PostgresTupleStore — Postgres-backed implementation of TupleStore.
 *
 * Mirrors InMemoryTupleStore byte-for-byte at the SDK boundary; the
 * difference is durability and concurrency. Schema lives in
 * spec/reference/postgres.sql (the `tup` table).
 *
 * Design notes:
 *   - All ID columns store native UUID. Wire-format prefixed IDs
 *     (`usr_<hex>`, `tup_<hex>`) are computed at the SDK boundary via
 *     flametrench/ids encode/decode.
 *   - The natural-key UNIQUE constraint
 *     (subject_type, subject_id, relation, object_type, object_id)
 *     drives duplicate detection.
 *   - check() / checkAny() are exact-match only here in v0.2.
 *     Rewrite-rule support (ADR 0007) requires the in-memory store with
 *     the `rules` constructor option; bridging the synchronous evaluator
 *     to PDO is tracked for v0.3.
 *   - Multi-SDK transaction nesting (ADR 0013): when the supplied PDO is
 *     already inside a transaction at call time, write methods cooperate
 *     by using SAVEPOINT/RELEASE so a constraint violation from one SDK
 *     call doesn't poison the outer transaction. Adopters wrapping
 *     several SDK calls in one outer `DB::transaction(...)` MUST
 *     construct every participating store with the same `\PDO` instance.
 */
final class PostgresTupleStore implements TupleStore
{
    /** @var callable(): \DateTimeImmutable */
    private $clock;

    /** @var array<string, array<string, list<\Flametrench\Authz\RewriteRules\RuleNode>>>|null */
    private readonly ?array $rules;
    private readonly int $maxDepth;
    private readonly int $maxFanOut;

    /**
     * @param  array<string, array<string, list<\Flametrench\Authz\RewriteRules\RuleNode>>>|null  $rules
     *   v0.3 (ADR 0017): optional rewrite rules. With null, behavior is
     *   v0.2-identical (exact-match only). With rules, `check()`
     *   evaluates them on direct-lookup miss via iterative expansion
     *   against Postgres — same algorithm as InMemoryTupleStore.
     */
    public function __construct(
        private readonly PDO $pdo,
        ?callable $clock = null,
        ?array $rules = null,
        int $maxDepth = \Flametrench\Authz\RewriteRules\Evaluator::DEFAULT_MAX_DEPTH,
        int $maxFanOut = \Flametrench\Authz\RewriteRules\Evaluator::DEFAULT_MAX_FAN_OUT,
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

    /**
     * v0.3 (ADR 0017) — accept subject ids in any of three shapes:
     * wire format with `usr_` (the v0.1/v0.2 default), wire format with
     * any registered prefix (`org_<hex>` for `tuple_to_userset` parent
     * hops), or bare canonical UUID (passthrough). Mirrors
     * {@see objectIdToUuid}.
     */
    private static function subjectIdToUuid(string $subjectId): string
    {
        if (preg_match('/^[a-z]{2,6}_[0-9a-f]{32}$/', $subjectId) === 1) {
            return Id::decodeAny($subjectId)['uuid'];
        }
        return $subjectId;
    }

    /** UUID `01234567-89ab-...` → bare 32-hex `0123456789ab...`. */
    private static function uuidHyphensToBare(string $hyphenated): string
    {
        return str_replace('-', '', $hyphenated);
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
            $subjectUuid = self::subjectIdToUuid($subjectId);
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
            $stmt->execute([$subjectType, self::subjectIdToUuid($subjectId)]);
            return $stmt->rowCount();
        });
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
        $direct = $this->directLookup($subjectType, $subjectId, $relation, $objectType, $objectId);
        if ($direct !== null) {
            return new CheckResult(allowed: true, matchedTupleId: $direct);
        }
        // ADR 0017 path: rule expansion only on direct miss AND when
        // rules are registered. With rules=null, behavior is byte-
        // identical to v0.2.
        if ($this->rules === null) {
            return new CheckResult(allowed: false, matchedTupleId: null);
        }
        $result = \Flametrench\Authz\RewriteRules\Evaluator::evaluate(
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
        // Security: every element of $relations is interpolated into a
        // Postgres array literal below. We MUST reject any relation
        // name that doesn't match the spec regex BEFORE binding —
        // otherwise a relation containing `","` would be parsed by
        // Postgres as a multi-element array, granting unrequested
        // permissions (security-audit-v0.3.md C1). The regex
        // `^[a-z_]{2,32}$` disallows quote / comma / backslash, which
        // is exactly the safety property we need.
        foreach ($relations as $relation) {
            if (preg_match(Patterns::RELATION_NAME, $relation) !== 1) {
                throw new InvalidFormatException(
                    "relation '{$relation}' must match " . Patterns::RELATION_NAME,
                    'relation',
                );
            }
        }
        // Fast path: when no rules are registered, a single SELECT with
        // `relation = ANY($3)` short-circuits across the whole set in
        // one round trip — preserves v0.2 behavior.
        if ($this->rules === null) {
            $stmt = $this->pdo->prepare(
                'SELECT id FROM tup
                 WHERE subject_type = ? AND subject_id = ?
                   AND relation = ANY(?) AND object_type = ? AND object_id = ?
                 LIMIT 1'
            );
            $stmt->execute([
                $subjectType,
                self::subjectIdToUuid($subjectId),
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
        // With rules, evaluate each relation in turn until first match
        // (or all denied). Per ADR 0017: no union-of-rules optimization.
        foreach ($relations as $relation) {
            $result = $this->check($subjectType, $subjectId, $relation, $objectType, $objectId);
            if ($result->allowed) return $result;
        }
        return new CheckResult(allowed: false, matchedTupleId: null);
    }

    /**
     * Direct natural-key lookup against Postgres. Used by both the
     * `check()` fast path and the rule evaluator's recursion.
     */
    private function directLookup(
        string $subjectType,
        string $subjectId,
        string $relation,
        string $objectType,
        string $objectId,
    ): ?string {
        $stmt = $this->pdo->prepare(
            'SELECT id FROM tup
             WHERE subject_type = ? AND subject_id = ?
               AND relation = ? AND object_type = ? AND object_id = ?
             LIMIT 1'
        );
        $stmt->execute([
            $subjectType,
            self::subjectIdToUuid($subjectId),
            $relation,
            $objectType,
            self::objectIdToUuid($objectId),
        ]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        return $row === false ? null : Id::encode('tup', (string) $row['id']);
    }

    /**
     * Enumerate tuples on (object, relation). Used by tuple_to_userset.
     *
     * Returns an iterable of [subjectType, subjectId, tupId] triples.
     * subjectId is wire-format prefixed with the row's subject_type
     * (e.g. `org_<hex>` for org-subject parent_org tuples), so the
     * evaluator can pass it through as the next-hop objectId, which
     * `objectIdToUuid` then accepts.
     *
     * @return iterable<array{0: string, 1: string, 2: string}>
     */
    private function listByObject(string $objectType, string $objectId, ?string $relation): iterable
    {
        $sql = 'SELECT id, subject_type, subject_id FROM tup
                WHERE object_type = ? AND object_id = ?';
        $params = [$objectType, self::objectIdToUuid($objectId)];
        if ($relation !== null) {
            $sql .= ' AND relation = ?';
            $params[] = $relation;
        }
        $stmt = $this->pdo->prepare($sql);
        $stmt->execute($params);
        while (($row = $stmt->fetch(PDO::FETCH_ASSOC)) !== false) {
            $subType = (string) $row['subject_type'];
            // pg returns UUID columns as canonical hyphenated; the wire
            // format is bare hex.
            $subIdWire = $subType . '_' . self::uuidHyphensToBare((string) $row['subject_id']);
            yield [$subType, $subIdWire, Id::encode('tup', (string) $row['id'])];
        }
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
        $params = [$subjectType, self::subjectIdToUuid($subjectId)];
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
