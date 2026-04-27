<?php

// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Flametrench\Authz;

use Flametrench\Authz\Exceptions\InvalidFormatException;
use Flametrench\Authz\Exceptions\InvalidShareTokenException;
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

    private static function fmt(\DateTimeImmutable $dt): string
    {
        return $dt->format('Y-m-d H:i:s.uP');
    }

    private static function wireToUuid(string $wireId): string
    {
        return Id::decode($wireId)['uuid'];
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
        $stmt->bindValue(4, $objectId);
        $stmt->bindValue(5, $relation);
        $stmt->bindValue(6, self::wireToUuid($createdBy));
        $stmt->bindValue(7, self::fmt($expiresAt));
        $stmt->bindValue(8, $singleUse, PDO::PARAM_BOOL);
        $stmt->bindValue(9, self::fmt($now));
        $stmt->execute();
        /** @var array<string, mixed> $row */
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        return new CreateShareResult(share: self::rowToShare($row), token: $token);
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
        $this->pdo->beginTransaction();
        try {
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
            $this->pdo->commit();
            return new VerifiedShare(
                shareId: Id::encode('shr', (string) $row['id']),
                objectType: (string) $row['object_type'],
                objectId: (string) $row['object_id'],
                relation: (string) $row['relation'],
            );
        } catch (\Throwable $e) {
            try {
                $this->pdo->rollBack();
            } catch (\Throwable) {
                // surface original
            }
            throw $e;
        }
    }

    public function revokeShare(string $shareId): Share
    {
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
    }

    public function listSharesForObject(
        string $objectType,
        string $objectId,
        ?string $cursor = null,
        int $limit = 50,
    ): Page {
        $limit = min($limit, 200);
        $params = [$objectType, $objectId];
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
