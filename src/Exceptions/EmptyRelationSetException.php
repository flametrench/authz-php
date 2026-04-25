<?php

// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Flametrench\Authz\Exceptions;

final class EmptyRelationSetException extends AuthzException
{
    public function __construct()
    {
        parent::__construct(
            'checkAny() relations array must be non-empty',
            'invalid_format.relations',
        );
    }
}
