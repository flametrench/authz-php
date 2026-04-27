<?php

// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Flametrench\Authz;

/**
 * Returned by `ShareStore::createShare`.
 *
 * The plaintext `$token` is observable here ONLY; the SDK persists only
 * its SHA-256 hash. Callers MUST surface the token to the share recipient
 * at this point and never log it.
 */
final readonly class CreateShareResult
{
    public function __construct(
        public Share $share,
        /** Opaque base64url-encoded bearer credential, ≥ 256 bits of entropy. */
        public string $token,
    ) {}
}
