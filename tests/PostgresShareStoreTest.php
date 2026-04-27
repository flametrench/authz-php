<?php

// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

use Flametrench\Authz\Exceptions\InvalidFormatException;
use Flametrench\Authz\Exceptions\InvalidShareTokenException;
use Flametrench\Authz\Exceptions\ShareConsumedException;
use Flametrench\Authz\Exceptions\ShareExpiredException;
use Flametrench\Authz\Exceptions\ShareNotFoundException;
use Flametrench\Authz\Exceptions\ShareRevokedException;
use Flametrench\Authz\PostgresShareStore;
use Flametrench\Authz\ShareStore;
use Flametrench\Ids\Id;

$shareUrl = getenv('AUTHZ_POSTGRES_URL') ?: null;

if ($shareUrl === null) {
    fwrite(STDERR, "[PostgresShareStoreTest] AUTHZ_POSTGRES_URL not set; tests skipped.\n");
    return;
}

beforeEach(function () use ($shareUrl) {
    $pdo = sharePgPdoFromUrl($shareUrl);
    $this->pdo = $pdo;
    $pdo->exec('DROP SCHEMA IF EXISTS public CASCADE; CREATE SCHEMA public;');
    $pdo->exec((string) file_get_contents(__DIR__ . '/postgres-schema.sql'));
    $this->store = new PostgresShareStore($pdo);
    $this->alice = Id::generate('usr');
    $this->project42 = Id::decode(Id::generate('usr'))['uuid'];
    $stmt = $pdo->prepare("INSERT INTO usr (id, status) VALUES (?, 'active')");
    $stmt->execute([Id::decode($this->alice)['uuid']]);
});

it('createShare yields a fresh shr_ id', function () {
    $r = $this->store->createShare('proj', $this->project42, 'viewer', $this->alice, 600);
    expect($r->share->id)->toMatch('/^shr_[0-9a-f]{32}$/');
    expect($r->token)->not->toBe($r->share->id);
    expect($r->share->singleUse)->toBeFalse();
    expect($r->share->consumedAt)->toBeNull();
});

it('rejects malformed relation', function () {
    $this->store->createShare('proj', $this->project42, 'Viewer!', $this->alice, 600);
})->throws(InvalidFormatException::class);

it('rejects expiresInSeconds beyond the 365-day ceiling', function () {
    $this->store->createShare('proj', $this->project42, 'viewer', $this->alice, ShareStore::MAX_TTL_SECONDS + 1);
})->throws(InvalidFormatException::class);

it('verifyShareToken round-trips for a valid token', function () {
    $r = $this->store->createShare('proj', $this->project42, 'viewer', $this->alice, 600);
    $v = $this->store->verifyShareToken($r->token);
    expect($v->shareId)->toBe($r->share->id);
    expect($v->objectType)->toBe('proj');
    expect($v->objectId)->toBe($this->project42);
    expect($v->relation)->toBe('viewer');
});

it('verifyShareToken raises InvalidShareTokenException for unknown tokens', function () {
    $this->store->verifyShareToken('not-a-real-token');
})->throws(InvalidShareTokenException::class);

it('verifyShareToken raises ShareRevokedException for revoked shares', function () {
    $r = $this->store->createShare('proj', $this->project42, 'viewer', $this->alice, 600);
    $this->store->revokeShare($r->share->id);
    $this->store->verifyShareToken($r->token);
})->throws(ShareRevokedException::class);

it('verifyShareToken raises ShareExpiredException when past expiry', function () {
    $now = new \DateTimeImmutable('2026-04-27T00:00:00Z');
    $clock = function () use (&$now) { return $now; };
    $s = new PostgresShareStore($this->pdo, $clock);
    $r = $s->createShare('proj', $this->project42, 'viewer', $this->alice, 60);
    $now = $now->add(new \DateInterval('PT61S'));
    $s->verifyShareToken($r->token);
})->throws(ShareExpiredException::class);

it('single-use share consumes on first verify and rejects subsequent verifies', function () {
    $r = $this->store->createShare('proj', $this->project42, 'viewer', $this->alice, 600, singleUse: true);
    $this->store->verifyShareToken($r->token);
    $consumed = $this->store->getShare($r->share->id);
    expect($consumed->consumedAt)->not->toBeNull();
    $this->store->verifyShareToken($r->token);
})->throws(ShareConsumedException::class);

it('non-single-use shares can be verified repeatedly', function () {
    $r = $this->store->createShare('proj', $this->project42, 'viewer', $this->alice, 600);
    $this->store->verifyShareToken($r->token);
    $second = $this->store->verifyShareToken($r->token);
    expect($second->relation)->toBe('viewer');
});

it('revoked + expired share raises ShareRevokedException (revoke wins precedence)', function () {
    $now = new \DateTimeImmutable('2026-04-27T00:00:00Z');
    $clock = function () use (&$now) { return $now; };
    $s = new PostgresShareStore($this->pdo, $clock);
    $r = $s->createShare('proj', $this->project42, 'viewer', $this->alice, 60);
    $s->revokeShare($r->share->id);
    $now = $now->add(new \DateInterval('PT61S'));
    $s->verifyShareToken($r->token);
})->throws(ShareRevokedException::class);

it('revokeShare is idempotent — second call returns the same revokedAt', function () {
    $r = $this->store->createShare('proj', $this->project42, 'viewer', $this->alice, 600);
    $first = $this->store->revokeShare($r->share->id);
    $second = $this->store->revokeShare($r->share->id);
    expect($second->revokedAt?->format('Y-m-d H:i:s.uP'))
        ->toBe($first->revokedAt?->format('Y-m-d H:i:s.uP'));
});

it('revokeShare raises ShareNotFoundException for unknown ids', function () {
    $this->store->revokeShare(Id::generate('shr'));
})->throws(ShareNotFoundException::class);

it('getShare raises ShareNotFoundException for unknown ids', function () {
    $this->store->getShare(Id::generate('shr'));
})->throws(ShareNotFoundException::class);

it('listSharesForObject filters by object and paginates', function () {
    $other = Id::decode(Id::generate('usr'))['uuid'];
    foreach ([$this->project42, $this->project42, $other, $this->project42] as $obj) {
        $this->store->createShare('proj', $obj, 'viewer', $this->alice, 600);
    }
    $page1 = $this->store->listSharesForObject('proj', $this->project42, limit: 2);
    expect($page1->data)->toHaveCount(2);
    expect($page1->nextCursor)->not->toBeNull();
    $page2 = $this->store->listSharesForObject('proj', $this->project42, cursor: $page1->nextCursor, limit: 10);
    $allIds = array_unique(array_merge(
        array_map(fn($s) => $s->id, $page1->data),
        array_map(fn($s) => $s->id, $page2->data),
    ));
    expect(count($allIds))->toBe(3);
});

function sharePgPdoFromUrl(string $url): PDO
{
    $parts = parse_url($url);
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
