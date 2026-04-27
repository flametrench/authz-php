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
use PDOException;

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
 */
final class PostgresTupleStore implements TupleStore
{
    /** @var callable(): \DateTimeImmutable */
    private $clock;

    public function __construct(
        private readonly PDO $pdo,
        ?callable $clock = null,
    ) {
        $this->clock = $clock ?? static fn(): \DateTimeImmutable => new \DateTimeImmutable();
    }

    private function now(): \DateTimeImmutable
    {
        return ($this->clock)();
    }

    private static function wireToUuid(string $wireId): string
    {
        return Id::decode($wireId)['uuid'];
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
        $id = Id::decode(Id::generate('tup'))['uuid'];
        $subjectUuid = self::wireToUuid($subjectId);
        $createdByUuid = $createdBy !== null ? self::wireToUuid($createdBy) : null;
        $now = $this->now()->format('Y-m-d H:i:s.uP');
        try {
            $stmt = $this->pdo->prepare(
                'INSERT INTO tup (id, subject_type, subject_id, relation, object_type, object_id, created_at, created_by)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                 RETURNING id, subject_type, subject_id, relation, object_type, object_id, created_at, created_by'
            );
            $stmt->execute([
                $id, $subjectType, $subjectUuid, $relation, $objectType, $objectId, $now, $createdByUuid,
            ]);
            /** @var array<string, mixed> $row */
            $row = $stmt->fetch(PDO::FETCH_ASSOC);
            return self::rowToTuple($row);
        } catch (PDOException $e) {
            if (self::isUniqueViolation($e)) {
                $sel = $this->pdo->prepare(
                    'SELECT id FROM tup
                     WHERE subject_type = ? AND subject_id = ? AND relation = ?
                       AND object_type = ? AND object_id = ?'
                );
                $sel->execute([$subjectType, $subjectUuid, $relation, $objectType, $objectId]);
                $existing = $sel->fetch(PDO::FETCH_ASSOC);
                if ($existing !== false) {
                    throw new DuplicateTupleException(
                        'Tuple with identical natural key already exists',
                        Id::encode('tup', (string) $existing['id']),
                    );
                }
            }
            throw $e;
        }
    }

    public function deleteTuple(string $tupleId): void
    {
        $stmt = $this->pdo->prepare('DELETE FROM tup WHERE id = ?');
        $stmt->execute([self::wireToUuid($tupleId)]);
        if ($stmt->rowCount() === 0) {
            throw new TupleNotFoundException("Tuple {$tupleId} not found");
        }
    }

    public function cascadeRevokeSubject(string $subjectType, string $subjectId): int
    {
        $stmt = $this->pdo->prepare(
            'DELETE FROM tup WHERE subject_type = ? AND subject_id = ?'
        );
        $stmt->execute([$subjectType, self::wireToUuid($subjectId)]);
        return $stmt->rowCount();
    }

    public function check(
        string $subjectType,
        string $subjectId,
        string $relation,
        string $objectType,
        string $objectId,
    ): CheckResult {
        return $this->checkAny($subjectType, $subjectId, [$relation], $objectType, $objectId);
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
            $objectId,
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
        $params = [$objectType, $objectId];
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

    /** Postgres SQLSTATE 23505 = unique_violation. */
    private static function isUniqueViolation(PDOException $e): bool
    {
        return ($e->errorInfo[0] ?? null) === '23505'
            || str_contains($e->getMessage(), 'SQLSTATE[23505]');
    }
}
