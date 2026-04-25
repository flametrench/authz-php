<?php

// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Flametrench\Authz;

final readonly class Tuple
{
    public function __construct(
        public string $id,
        public string $subjectType,
        public string $subjectId,
        public string $relation,
        public string $objectType,
        public string $objectId,
        public \DateTimeImmutable $createdAt,
        public ?string $createdBy = null,
    ) {}
}
