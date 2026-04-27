<?php

// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Flametrench\Authz\Exceptions;

/**
 * A precondition for the requested operation was not met.
 *
 * Used (initially) when share creation is attempted on behalf of a
 * non-active user — `created_by` MUST resolve to a user whose
 * `usr.status` is `'active'` per ADR 0012. The DDL FK enforces
 * existence; the status check runs at the SDK layer because the
 * `usr` table has no partial-active foreign key.
 *
 * Carries an additional `reason` token (e.g. `creator_not_active`)
 * matching the convention used by `PreconditionException` in the
 * identity and tenancy SDKs.
 */
final class PreconditionException extends AuthzException
{
    public function __construct(
        string $message,
        public readonly string $reason,
    ) {
        parent::__construct($message, 'precondition.' . $reason);
    }
}
