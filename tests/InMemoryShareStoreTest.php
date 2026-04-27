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
use Flametrench\Authz\InMemoryShareStore;
use Flametrench\Authz\ShareStore;
use Flametrench\Ids\Id;

beforeEach(function () {
    $this->store = new InMemoryShareStore();
    $this->alice = Id::generate('usr');
    $this->project42 = Id::decode(Id::generate('usr'))['uuid'];
});

it('createShare yields a fresh shr_ id and a token distinct from it', function () {
    $r = $this->store->createShare('proj', $this->project42, 'viewer', $this->alice, 600);
    expect($r->share->id)->toMatch('/^shr_[0-9a-f]{32}$/');
    expect($r->token)->not->toBe($r->share->id);
    expect(strlen($r->token))->toBeGreaterThan(20);
    expect($r->share->singleUse)->toBeFalse();
    expect($r->share->consumedAt)->toBeNull();
    expect($r->share->revokedAt)->toBeNull();
});

it('getShare round-trips the public record', function () {
    $r = $this->store->createShare('proj', $this->project42, 'viewer', $this->alice, 600);
    $fetched = $this->store->getShare($r->share->id);
    expect($fetched->id)->toBe($r->share->id);
});

it('getShare raises ShareNotFoundException for unknown ids', function () {
    $this->store->getShare(Id::generate('shr'));
})->throws(ShareNotFoundException::class);

it('rejects malformed relation', function () {
    $this->store->createShare('proj', $this->project42, 'Viewer!', $this->alice, 600);
})->throws(InvalidFormatException::class);

it('rejects malformed object_type', function () {
    $this->store->createShare('Project', $this->project42, 'viewer', $this->alice, 600);
})->throws(InvalidFormatException::class);

it('rejects negative expiresInSeconds', function () {
    $this->store->createShare('proj', $this->project42, 'viewer', $this->alice, -1);
})->throws(InvalidFormatException::class);

it('rejects expiresInSeconds beyond the 365-day ceiling', function () {
    $this->store->createShare('proj', $this->project42, 'viewer', $this->alice, ShareStore::MAX_TTL_SECONDS + 1);
})->throws(InvalidFormatException::class);

it('verifyShareToken returns the share + relation for a valid token', function () {
    $r = $this->store->createShare('proj', $this->project42, 'viewer', $this->alice, 600);
    $v = $this->store->verifyShareToken($r->token);
    expect($v->shareId)->toBe($r->share->id);
    expect($v->objectType)->toBe('proj');
    expect($v->objectId)->toBe($this->project42);
    expect($v->relation)->toBe('viewer');
});

it('verifyShareToken with junk raises InvalidShareTokenException', function () {
    $this->store->verifyShareToken('not-a-token');
})->throws(InvalidShareTokenException::class);

it('verifyShareToken on a revoked share raises ShareRevokedException', function () {
    $r = $this->store->createShare('proj', $this->project42, 'viewer', $this->alice, 600);
    $this->store->revokeShare($r->share->id);
    $this->store->verifyShareToken($r->token);
})->throws(ShareRevokedException::class);

it('verifyShareToken on an expired share raises ShareExpiredException', function () {
    $now = new \DateTimeImmutable('2026-04-27T00:00:00Z');
    $clock = function () use (&$now) { return $now; };
    $s = new InMemoryShareStore($clock);
    $r = $s->createShare('proj', $this->project42, 'viewer', $this->alice, 60);
    $now = $now->add(new \DateInterval('PT61S'));
    $s->verifyShareToken($r->token);
})->throws(ShareExpiredException::class);

it('single-use share consumes on first verify and rejects subsequent verifies', function () {
    $r = $this->store->createShare('proj', $this->project42, 'viewer', $this->alice, 600, singleUse: true);
    $this->store->verifyShareToken($r->token);
    $this->store->verifyShareToken($r->token);
})->throws(ShareConsumedException::class);

it('single-use consumed_at is set on the public record after verify', function () {
    $r = $this->store->createShare('proj', $this->project42, 'viewer', $this->alice, 600, singleUse: true);
    expect($r->share->consumedAt)->toBeNull();
    $this->store->verifyShareToken($r->token);
    $after = $this->store->getShare($r->share->id);
    expect($after->consumedAt)->not->toBeNull();
});

it('non-single-use shares can be verified repeatedly', function () {
    $r = $this->store->createShare('proj', $this->project42, 'viewer', $this->alice, 600);
    $this->store->verifyShareToken($r->token);
    $second = $this->store->verifyShareToken($r->token);
    expect($second->relation)->toBe('viewer');
});

it('revoked + expired share raises ShareRevokedException (revoke wins precedence)', function () {
    $now = new \DateTimeImmutable('2026-04-27T00:00:00Z');
    $clock = function () use (&$now) { return $now; };
    $s = new InMemoryShareStore($clock);
    $r = $s->createShare('proj', $this->project42, 'viewer', $this->alice, 60);
    $s->revokeShare($r->share->id);
    $now = $now->add(new \DateInterval('PT61S'));
    $s->verifyShareToken($r->token);
})->throws(ShareRevokedException::class);

it('revokeShare is idempotent — second call returns the same revokedAt', function () {
    $r = $this->store->createShare('proj', $this->project42, 'viewer', $this->alice, 600);
    $first = $this->store->revokeShare($r->share->id);
    $second = $this->store->revokeShare($r->share->id);
    expect($second->revokedAt)->toEqual($first->revokedAt);
});

it('revokeShare raises ShareNotFoundException for unknown ids', function () {
    $this->store->revokeShare(Id::generate('shr'));
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
