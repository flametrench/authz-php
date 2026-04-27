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

/**
 * Reference in-memory ShareStore. O(1) verify via secondary token-hash
 * index; deterministic for tests.
 *
 * Token storage matches the Postgres reference (SHA-256 → 32 raw bytes,
 * constant-time compare on verify), so behavior is byte-identical
 * across backends.
 */
final class InMemoryShareStore implements ShareStore
{
    /** @var array<string, Share> */
    private array $shares = [];

    /** @var array<string, string> share_id → raw token hash bytes */
    private array $tokenHashes = [];

    /** @var array<string, string> raw token hash bytes → share_id */
    private array $byTokenHash = [];

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

    private static function hashToken(string $token): string
    {
        return hash('sha256', $token, binary: true);
    }

    private static function generateToken(): string
    {
        return rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
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
        $now = $this->now();
        $expiresAt = $now->add(new \DateInterval('PT' . $expiresInSeconds . 'S'));
        $shareId = Id::generate('shr');
        $token = self::generateToken();
        $tokenHash = self::hashToken($token);
        $share = new Share(
            id: $shareId,
            objectType: $objectType,
            objectId: $objectId,
            relation: $relation,
            createdBy: $createdBy,
            expiresAt: $expiresAt,
            singleUse: $singleUse,
            consumedAt: null,
            revokedAt: null,
            createdAt: $now,
        );
        $this->shares[$shareId] = $share;
        $this->tokenHashes[$shareId] = $tokenHash;
        $this->byTokenHash[$tokenHash] = $shareId;
        return new CreateShareResult(share: $share, token: $token);
    }

    public function getShare(string $shareId): Share
    {
        return $this->shares[$shareId]
            ?? throw new ShareNotFoundException("Share {$shareId} not found");
    }

    public function verifyShareToken(string $token): VerifiedShare
    {
        $inputHash = self::hashToken($token);
        $shareId = $this->byTokenHash[$inputHash] ?? null;
        if ($shareId === null) {
            throw new InvalidShareTokenException();
        }
        $share = $this->shares[$shareId] ?? null;
        $storedHash = $this->tokenHashes[$shareId] ?? null;
        if ($share === null || $storedHash === null) {
            throw new InvalidShareTokenException();
        }
        // Defense-in-depth: constant-time compare even though the index just hit.
        if (!hash_equals($storedHash, $inputHash)) {
            throw new InvalidShareTokenException();
        }
        // Spec error precedence: revoked > consumed > expired.
        if ($share->revokedAt !== null) {
            throw new ShareRevokedException();
        }
        if ($share->singleUse && $share->consumedAt !== null) {
            throw new ShareConsumedException();
        }
        $now = $this->now();
        if ($now >= $share->expiresAt) {
            throw new ShareExpiredException();
        }
        if ($share->singleUse) {
            // Atomic consume — set consumedAt on the public record. We
            // intentionally KEEP the byTokenHash entry so a second verify
            // can find the row and return ShareConsumedException (not
            // InvalidShareTokenException). The Postgres equivalent is
            // UPDATE ... WHERE consumed_at IS NULL RETURNING ...
            $this->shares[$shareId] = new Share(
                id: $share->id,
                objectType: $share->objectType,
                objectId: $share->objectId,
                relation: $share->relation,
                createdBy: $share->createdBy,
                expiresAt: $share->expiresAt,
                singleUse: $share->singleUse,
                consumedAt: $now,
                revokedAt: $share->revokedAt,
                createdAt: $share->createdAt,
            );
        }
        return new VerifiedShare(
            shareId: $shareId,
            objectType: $share->objectType,
            objectId: $share->objectId,
            relation: $share->relation,
        );
    }

    public function revokeShare(string $shareId): Share
    {
        if (!isset($this->shares[$shareId])) {
            throw new ShareNotFoundException("Share {$shareId} not found");
        }
        $share = $this->shares[$shareId];
        if ($share->revokedAt !== null) {
            // Idempotent: return the existing record with the original timestamp.
            return $share;
        }
        $revoked = new Share(
            id: $share->id,
            objectType: $share->objectType,
            objectId: $share->objectId,
            relation: $share->relation,
            createdBy: $share->createdBy,
            expiresAt: $share->expiresAt,
            singleUse: $share->singleUse,
            consumedAt: $share->consumedAt,
            revokedAt: $this->now(),
            createdAt: $share->createdAt,
        );
        $this->shares[$shareId] = $revoked;
        // Don't drop the byTokenHash entry — verify must find the row to
        // return ShareRevokedException, not InvalidShareTokenException.
        return $revoked;
    }

    public function listSharesForObject(
        string $objectType,
        string $objectId,
        ?string $cursor = null,
        int $limit = 50,
    ): Page {
        $limit = min($limit, 200);
        $matching = array_values(array_filter(
            $this->shares,
            fn(Share $s) => $s->objectType === $objectType
                && $s->objectId === $objectId
                && ($cursor === null || $s->id > $cursor),
        ));
        usort($matching, fn(Share $a, Share $b) => strcmp($a->id, $b->id));
        $data = array_slice($matching, 0, $limit);
        $nextCursor = count($matching) > $limit && count($data) > 0
            ? $data[count($data) - 1]->id
            : null;
        return new Page(data: $data, nextCursor: $nextCursor);
    }
}
