<?php

// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Flametrench\Authz\Exceptions;

/**
 * Generic violation of `verifyShareToken` precondition: token doesn't match
 * any row, or hash comparison failed. Deliberately conflated to avoid a
 * timing oracle distinguishing "no such hash" from "hash collision but
 * mismatch."
 */
final class InvalidShareTokenException extends AuthzException
{
    public function __construct(string $message = 'Invalid share token')
    {
        parent::__construct($message, 'invalid_share_token');
    }
}
