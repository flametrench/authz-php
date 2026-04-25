<?php

// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Flametrench\Authz\Exceptions;

class AuthzException extends \RuntimeException
{
    public function __construct(string $message, public readonly string $flametrenchCode)
    {
        parent::__construct($message);
    }
}
