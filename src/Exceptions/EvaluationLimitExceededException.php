<?php

// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Flametrench\Authz\Exceptions;

/**
 * Rewrite-rule evaluation exceeded a configured bound (depth or fan-out).
 *
 * Bounds are configurable per-store; the spec floor is depth=8,
 * fan-out=1024. Apps hitting this in practice should restructure their
 * rule set or explicitly raise the limit.
 *
 * v0.2; see ADR 0007.
 */
final class EvaluationLimitExceededException extends AuthzException
{
    public function __construct(string $message)
    {
        parent::__construct($message, 'evaluation_limit_exceeded');
    }
}
