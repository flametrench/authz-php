<?php

// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Flametrench\Authz\RewriteRules;

/**
 * The explicit-tuple set: equivalent to v0.1 check() semantics.
 *
 * In v0.2, ThisNode is always implicitly part of every rule's union —
 * the direct-tuple fast path runs before rule expansion. Listing it
 * explicitly is documentation, not behavior.
 */
final readonly class ThisNode implements RuleNode
{
}
