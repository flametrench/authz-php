<?php

// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Flametrench\Authz;

/**
 * Contract every share-token backend implements.
 *
 * Verification ordering is normative (per ADR 0012):
 *   1. Hash input via SHA-256.
 *   2. Look up by `token_hash`; missing → `InvalidShareTokenException`.
 *   3. Constant-time-compare; mismatch → `InvalidShareTokenException`.
 *   4. revokedAt non-null → `ShareRevokedException`.
 *   5. singleUse && consumedAt non-null → `ShareConsumedException`.
 *   6. expiresAt <= now → `ShareExpiredException`.
 *   7. If singleUse: transactionally set consumedAt = now.
 */
interface ShareStore
{
    public function createShare(
        string $objectType,
        string $objectId,
        string $relation,
        string $createdBy,
        int $expiresInSeconds,
        bool $singleUse = false,
    ): CreateShareResult;

    public function getShare(string $shareId): Share;

    /**
     * @security The returned VerifiedShare->relation is the relation
     * the share was minted with. The adopter MUST gate write paths
     * on this — verifyShareToken only proves the token is valid, not
     * that the bearer is allowed to perform the action. A common
     * footgun (security-audit-v0.3.md C2): minting 'viewer' shares
     * and using them on both read AND write endpoints without
     * checking $verified->relation on the writes — the SDK will not
     * stop a viewer share from posting comments. Mint distinct
     * relations per intent; gate each endpoint accordingly. See
     * spec/docs/shares.md §"Adopter MUST: enforce the relation field".
     */
    public function verifyShareToken(string $token): VerifiedShare;

    /**
     * Idempotent. Calling on an already-revoked share returns the
     * existing record with the original revokedAt; not an error.
     */
    public function revokeShare(string $shareId): Share;

    /**
     * @return Page<Share>
     */
    public function listSharesForObject(
        string $objectType,
        string $objectId,
        ?string $cursor = null,
        int $limit = 50,
    ): Page;

    /** Spec-mandated upper bound on share lifetime: 365 days. */
    public const MAX_TTL_SECONDS = 365 * 24 * 60 * 60;
}
