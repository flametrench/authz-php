<?php

// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Flametrench\Authz\Exceptions;

final class InvalidFormatException extends AuthzException
{
    public function __construct(string $message, string $field)
    {
        parent::__construct($message, "invalid_format.{$field}");
    }
}
