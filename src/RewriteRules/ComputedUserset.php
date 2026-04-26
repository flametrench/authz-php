<?php

// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Flametrench\Authz\RewriteRules;

/**
 * Role implication on the same object.
 *
 * `new ComputedUserset(relation: 'editor')` on a rule for `proj.viewer`
 * means: anyone holding `editor` on this same project also has
 * `viewer`. The check recurses with the same object, different relation.
 */
final readonly class ComputedUserset implements RuleNode
{
    public function __construct(public string $relation)
    {
    }
}
