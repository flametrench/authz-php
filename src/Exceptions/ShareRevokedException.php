<?php

// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Flametrench\Authz\Exceptions;

final class ShareRevokedException extends AuthzException
{
    public function __construct(string $message = 'Share has been revoked')
    {
        parent::__construct($message, 'share_revoked');
    }
}
