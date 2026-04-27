<?php

// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Flametrench\Authz;

/**
 * Returned by `ShareStore::verifyShareToken` on success.
 *
 * This is enough information to render the resource at the given relation;
 * it is NOT an authenticated principal and MUST NOT be promoted to a session.
 */
final readonly class VerifiedShare
{
    public function __construct(
        public string $shareId,
        public string $objectType,
        public string $objectId,
        public string $relation,
    ) {}
}
