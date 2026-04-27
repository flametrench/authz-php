<?php

// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Flametrench\Authz;

/**
 * The public share record.
 *
 * Token storage (SHA-256 → BYTEA) is internal; the plaintext bearer
 * credential is returned ONCE on `ShareStore::createShare` and never
 * persisted nor exposed via this class.
 */
final readonly class Share
{
    public function __construct(
        public string $id,
        public string $objectType,
        public string $objectId,
        public string $relation,
        public string $createdBy,
        public \DateTimeImmutable $expiresAt,
        public bool $singleUse,
        /** Set on first verify when singleUse is true. */
        public ?\DateTimeImmutable $consumedAt,
        /** Soft-delete timestamp. */
        public ?\DateTimeImmutable $revokedAt,
        public \DateTimeImmutable $createdAt,
    ) {}
}
