<?php

// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Flametrench\Authz\Exceptions;

final class DuplicateTupleException extends AuthzException
{
    public function __construct(
        string $message,
        public readonly string $existingTupleId,
    ) {
        parent::__construct($message, 'conflict.duplicate_tuple');
    }
}
