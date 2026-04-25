<?php

// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Flametrench\Authz;

/**
 * Format-rule constants matching the Flametrench v0.1 specification.
 */
final class Patterns
{
    /** Relation name regex. Matches /^[a-z_]{2,32}$/. */
    public const RELATION_NAME = '/^[a-z_]{2,32}$/';

    /** Object-type prefix regex. Matches /^[a-z]{2,6}$/. */
    public const TYPE_PREFIX = '/^[a-z]{2,6}$/';

    private function __construct() {}
}
