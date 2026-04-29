<?php

// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Flametrench\Authz;

use Flametrench\Authz\Exceptions\InvalidFormatException;
use Flametrench\Authz\Exceptions\InvalidShareTokenException;
use Flametrench\Authz\Exceptions\PreconditionException;
use Flametrench\Authz\Exceptions\ShareConsumedException;
use Flametrench\Authz\Exceptions\ShareExpiredException;
use Flametrench\Authz\Exceptions\ShareNotFoundException;
use Flametrench\Authz\Exceptions\ShareRevokedException;
use Flametrench\Ids\Id;
use PDO;

/**
 * PostgresShareStore — Postgres-backed ShareStore. Mirrors
 * InMemoryShareStore byte-for-byte at the SDK boundary.
 *
 * Verification is one round-trip on the lookup index `shr_token_hash_idx`.
 * Single-use consumption uses `UPDATE ... WHERE consumed_at IS NULL
 * RETURNING ...` so concurrent verifies of a single-use token race-
 * correctly to exactly one success.
 *
 * Multi-SDK transaction nesting (ADR 0013): when the supplied PDO is
 * already inside a transaction at call time, this store cooperates by
 * using SAVEPOINT/RELEASE instead of opening its own BEGIN. Adopters
 * wrapping several SDK calls in one outer `DB::transaction(...)` MUST
 * construct every participating store with the same `\PDO` instance.
 */
final class PostgresShareStore implements ShareStore
{
    private const SHR_COLS =
        'id, token_hash, object_type, object_id, relation, created_by, '
        . 'expires_at, single_use, consumed_at, revoked_at, created_at';

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

    /**
     * Run $fn atomically. Opens BEGIN/COMMIT when standalone, or
     * SAVEPOINT/RELEASE when called inside an outer transaction. See ADR 0013.
     *
     * @template T
     * @param callable(): T $fn
     * @return T
     */
    private function tx(callable $fn): mixed
    {
        if ($this->pdo->inTransaction()) {
            return $this->withSavepoint($fn, self::callerName());
        }
        $this->pdo->beginTransaction();
        try {
            $result = $fn();
            $this->pdo->commit();
            return $result;
        } catch (\Throwable $e) {
            try {
                $this->pdo->rollBack();
            } catch (\Throwable) {
                // surface original
            }
            throw $e;
        }
    }

    /**
     * Run $fn shielded by a savepoint when inside an outer transaction, or
     * unwrapped when standalone (zero overhead). For single-statement methods
     * that don't need their own BEGIN/COMMIT but must not poison an outer
     * transaction on a constraint violation. See ADR 0013.
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
        return $this->withSavepoint($fn, self::callerName());
    }

    /**
     * @template T
     * @param callable(): T $fn
     * @return T
     */
    private function withSavepoint(callable $fn, string $caller): mixed
    {
        $savepoint = self::savepointName($caller);
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

    private static function fmt(\DateTimeImmutable $dt): string
    {
        return $dt->format('Y-m-d H:i:s.uP');
    }

    private static function wireToUuid(string $wireId): string
    {
        return Id::decode($wireId)['uuid'];
    }

    /**
     * Decode an `object_id` to a Postgres-bindable UUID string.
     * See PostgresTupleStore::objectIdToUuid for rationale (spec#8).
     */
    private static function objectIdToUuid(string $objectId): string
    {
        if (preg_match('/^[a-z]{2,6}_[0-9a-f]{32}$/', $objectId) === 1) {
            return Id::decodeAny($objectId)['uuid'];
        }
        return $objectId;
    }

    private static function hashTokenBytes(string $token): string
    {
        return hash('sha256', $token, binary: true);
    }

    private static function generateToken(): string
    {
        return rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
    }

    /** @param array<string, mixed> $row */
    private static function rowToShare(array $row): Share
    {
        return new Share(
            id: Id::encode('shr', (string) $row['id']),
            // token_hash (BYTEA) is internal; never copied to the public record.
            objectType: (string) $row['object_type'],
            objectId: (string) $row['object_id'],
            relation: (string) $row['relation'],
            createdBy: Id::encode('usr', (string) $row['created_by']),
            expiresAt: new \DateTimeImmutable((string) $row['expires_at']),
            singleUse: self::pgBool($row['single_use']),
            consumedAt: $row['consumed_at'] !== null
                ? new \DateTimeImmutable((string) $row['consumed_at'])
                : null,
            revokedAt: $row['revoked_at'] !== null
                ? new \DateTimeImmutable((string) $row['revoked_at'])
                : null,
            createdAt: new \DateTimeImmutable((string) $row['created_at']),
        );
    }

    private static function pgBool(mixed $v): bool
    {
        if (is_bool($v)) return $v;
        if (is_string($v)) return $v === 't' || $v === 'true' || $v === '1';
        return (bool) $v;
    }

    private static function validate(string $relation, string $objectType, int $expiresInSeconds): void
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
        if ($expiresInSeconds <= 0) {
            throw new InvalidFormatException(
                "expiresInSeconds must be positive, got {$expiresInSeconds}",
                'expires_in_seconds',
            );
        }
        if ($expiresInSeconds > ShareStore::MAX_TTL_SECONDS) {
            throw new InvalidFormatException(
                'expiresInSeconds exceeds the spec ceiling of '
                . ShareStore::MAX_TTL_SECONDS . ' (365 days)',
                'expires_in_seconds',
            );
        }
    }

    public function createShare(
        string $objectType,
        string $objectId,
        string $relation,
        string $createdBy,
        int $expiresInSeconds,
        bool $singleUse = false,
    ): CreateShareResult {
        self::validate($relation, $objectType, $expiresInSeconds);
        return $this->nested(function () use (
            $objectType,
            $objectId,
            $relation,
            $createdBy,
            $expiresInSeconds,
            $singleUse,
        ) {
            $createdByUuid = self::wireToUuid($createdBy);
            // ADR 0012: created_by MUST resolve to an active user. The DDL
            // FK enforces existence; status is checked here at the SDK
            // layer. Suspended/revoked users with leaked credentials cannot
            // mint shares.
            $check = $this->pdo->prepare('SELECT status FROM usr WHERE id = ?');
            $check->execute([$createdByUuid]);
            $userRow = $check->fetch(PDO::FETCH_ASSOC);
            if ($userRow === false) {
                throw new PreconditionException(
                    "created_by {$createdBy} does not exist",
                    'creator_not_found',
                );
            }
            if ($userRow['status'] !== 'active') {
                throw new PreconditionException(
                    "created_by {$createdBy} is {$userRow['status']}; "
                    . 'only active users can mint shares',
                    'creator_not_active',
                );
            }
            $shareUuid = Id::decode(Id::generate('shr'))['uuid'];
            $token = self::generateToken();
            $tokenHash = self::hashTokenBytes($token);
            $now = $this->now();
            $expiresAt = $now->add(new \DateInterval('PT' . $expiresInSeconds . 'S'));
            $stmt = $this->pdo->prepare(
                'INSERT INTO shr (id, token_hash, object_type, object_id, relation,
                                  created_by, expires_at, single_use, created_at)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                 RETURNING ' . self::SHR_COLS,
            );
            $stmt->bindValue(1, $shareUuid);
            $stmt->bindValue(2, $tokenHash, PDO::PARAM_LOB);
            $stmt->bindValue(3, $objectType);
            $stmt->bindValue(4, self::objectIdToUuid($objectId));
            $stmt->bindValue(5, $relation);
            $stmt->bindValue(6, $createdByUuid);
            $stmt->bindValue(7, self::fmt($expiresAt));
            $stmt->bindValue(8, $singleUse, PDO::PARAM_BOOL);
            $stmt->bindValue(9, self::fmt($now));
            $stmt->execute();
            /** @var array<string, mixed> $row */
            $row = $stmt->fetch(PDO::FETCH_ASSOC);
            return new CreateShareResult(share: self::rowToShare($row), token: $token);
        });
    }

    public function getShare(string $shareId): Share
    {
        $stmt = $this->pdo->prepare(
            'SELECT ' . self::SHR_COLS . ' FROM shr WHERE id = ?',
        );
        $stmt->execute([self::wireToUuid($shareId)]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        if ($row === false) {
            throw new ShareNotFoundException("Share {$shareId} not found");
        }
        return self::rowToShare($row);
    }

    public function verifyShareToken(string $token): VerifiedShare
    {
        $inputHash = self::hashTokenBytes($token);
        return $this->tx(function () use ($inputHash) {
            $stmt = $this->pdo->prepare(
                'SELECT ' . self::SHR_COLS . ' FROM shr
                 WHERE token_hash = ?
                 ORDER BY created_at DESC LIMIT 1
                 FOR UPDATE',
            );
            $stmt->bindValue(1, $inputHash, PDO::PARAM_LOB);
            $stmt->execute();
            $row = $stmt->fetch(PDO::FETCH_ASSOC);
            if ($row === false) {
                throw new InvalidShareTokenException();
            }
            $storedHash = is_resource($row['token_hash'])
                ? stream_get_contents($row['token_hash'])
                : (string) $row['token_hash'];
            if ($storedHash === false || !hash_equals($storedHash, $inputHash)) {
                throw new InvalidShareTokenException();
            }
            // Spec error precedence: revoked > consumed > expired.
            if ($row['revoked_at'] !== null) {
                throw new ShareRevokedException();
            }
            $singleUse = self::pgBool($row['single_use']);
            if ($singleUse && $row['consumed_at'] !== null) {
                throw new ShareConsumedException();
            }
            $now = $this->now();
            $expiresAt = new \DateTimeImmutable((string) $row['expires_at']);
            if ($now >= $expiresAt) {
                throw new ShareExpiredException();
            }
            if ($singleUse) {
                // Atomic consume — concurrent verifies race here. The
                // `WHERE consumed_at IS NULL` is what makes the second loser.
                $upd = $this->pdo->prepare(
                    'UPDATE shr SET consumed_at = ?
                     WHERE id = ? AND consumed_at IS NULL
                     RETURNING id',
                );
                $upd->execute([self::fmt($now), $row['id']]);
                if ($upd->fetch(PDO::FETCH_ASSOC) === false) {
                    throw new ShareConsumedException();
                }
            }
            return new VerifiedShare(
                shareId: Id::encode('shr', (string) $row['id']),
                objectType: (string) $row['object_type'],
                objectId: (string) $row['object_id'],
                relation: (string) $row['relation'],
            );
        });
    }

    public function revokeShare(string $shareId): Share
    {
        return $this->nested(function () use ($shareId) {
            $stmt = $this->pdo->prepare(
                'UPDATE shr SET revoked_at = COALESCE(revoked_at, ?)
                 WHERE id = ?
                 RETURNING ' . self::SHR_COLS,
            );
            $stmt->execute([self::fmt($this->now()), self::wireToUuid($shareId)]);
            $row = $stmt->fetch(PDO::FETCH_ASSOC);
            if ($row === false) {
                throw new ShareNotFoundException("Share {$shareId} not found");
            }
            return self::rowToShare($row);
        });
    }

    public function listSharesForObject(
        string $objectType,
        string $objectId,
        ?string $cursor = null,
        int $limit = 50,
    ): Page {
        $limit = min($limit, 200);
        $params = [$objectType, self::objectIdToUuid($objectId)];
        $sql = 'SELECT ' . self::SHR_COLS
            . ' FROM shr WHERE object_type = ? AND object_id = ?';
        if ($cursor !== null) {
            $sql .= ' AND id > ?';
            $params[] = self::wireToUuid($cursor);
        }
        $sql .= ' ORDER BY id LIMIT ?';
        $params[] = $limit + 1;
        $stmt = $this->pdo->prepare($sql);
        $stmt->execute($params);
        $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
        $page = array_slice($rows, 0, $limit);
        $shares = array_map(self::rowToShare(...), $page);
        $nextCursor = count($rows) > $limit && count($shares) > 0
            ? $shares[count($shares) - 1]->id
            : null;
        return new Page(data: $shares, nextCursor: $nextCursor);
    }
}
