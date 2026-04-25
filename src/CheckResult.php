<?php

// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Flametrench\Authz;

final readonly class CheckResult
{
    public function __construct(
        public bool $allowed,
        public ?string $matchedTupleId = null,
    ) {}
}
