<?php

// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

if (!function_exists('pdoFromUrl')) {
    /**
     * Convert a postgres:// URL into a PDO connection. Shared by every
     * Postgres-backed test file so test isolation logic
     * (DROP SCHEMA / load fixture schema) lives in one place.
     */
    function pdoFromUrl(string $url): PDO
    {
        $parts = parse_url($url);
        if ($parts === false) {
            throw new RuntimeException("invalid postgres URL: {$url}");
        }
        $host = $parts['host'] ?? '127.0.0.1';
        $port = $parts['port'] ?? 5432;
        $db = ltrim($parts['path'] ?? '/postgres', '/');
        $user = $parts['user'] ?? 'postgres';
        $pass = $parts['pass'] ?? '';
        $dsn = "pgsql:host={$host};port={$port};dbname={$db}";
        return new PDO($dsn, $user, $pass, [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        ]);
    }
}
