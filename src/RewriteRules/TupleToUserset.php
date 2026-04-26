<?php

// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Flametrench\Authz\RewriteRules;

/**
 * Parent-child inheritance via a relation traversal.
 *
 * `new TupleToUserset(tuplesetRelation: 'parent_org',
 * computedUsersetRelation: 'viewer')` on a rule for `proj.viewer`
 * means: enumerate all `(*, parent_org, this_proj)` tuples — for each
 * such tuple's subject (which will be an org), recursively check
 * whether the original subject has `viewer` on that org.
 *
 * The two-relation hop expresses "org member can view all projects
 * owned by their org" without per-project denormalization.
 */
final readonly class TupleToUserset implements RuleNode
{
    public function __construct(
        public string $tuplesetRelation,
        public string $computedUsersetRelation,
    ) {
    }
}
