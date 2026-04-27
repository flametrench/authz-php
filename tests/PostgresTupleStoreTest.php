<?php

// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

use Flametrench\Authz\Exceptions\DuplicateTupleException;
use Flametrench\Authz\Exceptions\EmptyRelationSetException;
use Flametrench\Authz\Exceptions\InvalidFormatException;
use Flametrench\Authz\Exceptions\TupleNotFoundException;
use Flametrench\Authz\PostgresTupleStore;
use Flametrench\Ids\Id;

$postgresUrl = getenv('AUTHZ_POSTGRES_URL') ?: null;

if ($postgresUrl === null) {
    // Pest's `it()` blocks aren't registered, so the runner shows no tests
    // for this file when the env var is missing — equivalent to vitest's
    // `describe.skipIf`.
    fwrite(STDERR, "[PostgresTupleStoreTest] AUTHZ_POSTGRES_URL not set; tests skipped.\n");
    return;
}

beforeEach(function () use ($postgresUrl) {
    $pdo = pdoFromUrl($postgresUrl);
    $this->pdo = $pdo;
    $pdo->exec('DROP SCHEMA IF EXISTS public CASCADE; CREATE SCHEMA public;');
    $pdo->exec((string) file_get_contents(__DIR__ . '/postgres-schema.sql'));
    $this->store = new PostgresTupleStore($pdo);
    $this->alice = Id::generate('usr');
    $this->bob = Id::generate('usr');
    $this->carol = Id::generate('usr');
    $this->project42 = Id::decode(Id::generate('usr'))['uuid'];
    $this->project99 = Id::decode(Id::generate('usr'))['uuid'];
    // tup.created_by FKs to usr(id); register test users so inserts pass.
    foreach ([$this->alice, $this->bob, $this->carol] as $u) {
        $stmt = $pdo->prepare("INSERT INTO usr (id, status) VALUES (?, 'active')");
        $stmt->execute([Id::decode($u)['uuid']]);
    }
});

it('creates a tuple and returns it with a fresh tup_ id', function () {
    $t = $this->store->createTuple(
        subjectType: 'usr',
        subjectId: $this->alice,
        relation: 'owner',
        objectType: 'proj',
        objectId: $this->project42,
        createdBy: $this->alice,
    );
    expect($t->id)->toMatch('/^tup_[0-9a-f]{32}$/');
    expect($t->subjectId)->toBe($this->alice);
    expect($t->createdBy)->toBe($this->alice);
    expect($t->objectId)->toBe($this->project42);
});

it('rejects a duplicate natural key with the existing tuple id attached', function () {
    $first = $this->store->createTuple(
        subjectType: 'usr',
        subjectId: $this->alice,
        relation: 'viewer',
        objectType: 'proj',
        objectId: $this->project42,
    );
    try {
        $this->store->createTuple(
            subjectType: 'usr',
            subjectId: $this->alice,
            relation: 'viewer',
            objectType: 'proj',
            objectId: $this->project42,
        );
        throw new RuntimeException('expected DuplicateTupleException');
    } catch (DuplicateTupleException $e) {
        expect($e->existingTupleId)->toBe($first->id);
    }
});

it('rejects a malformed relation', function () {
    $this->store->createTuple(
        subjectType: 'usr',
        subjectId: $this->alice,
        relation: 'Owner!',
        objectType: 'proj',
        objectId: $this->project42,
    );
})->throws(InvalidFormatException::class);

it('rejects a malformed object type', function () {
    $this->store->createTuple(
        subjectType: 'usr',
        subjectId: $this->alice,
        relation: 'owner',
        objectType: 'Project',
        objectId: $this->project42,
    );
})->throws(InvalidFormatException::class);

it('check returns allowed=true with the matched tuple id', function () {
    $t = $this->store->createTuple(
        subjectType: 'usr',
        subjectId: $this->alice,
        relation: 'editor',
        objectType: 'proj',
        objectId: $this->project42,
    );
    $r = $this->store->check('usr', $this->alice, 'editor', 'proj', $this->project42);
    expect($r->allowed)->toBeTrue();
    expect($r->matchedTupleId)->toBe($t->id);
});

it('check returns allowed=false when no tuple matches', function () {
    $r = $this->store->check('usr', $this->alice, 'owner', 'proj', $this->project42);
    expect($r->allowed)->toBeFalse();
    expect($r->matchedTupleId)->toBeNull();
});

it('checkAny matches any of the supplied relations', function () {
    $this->store->createTuple(
        subjectType: 'usr',
        subjectId: $this->alice,
        relation: 'editor',
        objectType: 'proj',
        objectId: $this->project42,
    );
    $r = $this->store->checkAny(
        subjectType: 'usr',
        subjectId: $this->alice,
        relations: ['viewer', 'editor', 'owner'],
        objectType: 'proj',
        objectId: $this->project42,
    );
    expect($r->allowed)->toBeTrue();
});

it('checkAny rejects an empty relation set', function () {
    $this->store->checkAny(
        subjectType: 'usr',
        subjectId: $this->alice,
        relations: [],
        objectType: 'proj',
        objectId: $this->project42,
    );
})->throws(EmptyRelationSetException::class);

it('deleteTuple removes the row; subsequent check is false', function () {
    $t = $this->store->createTuple(
        subjectType: 'usr',
        subjectId: $this->alice,
        relation: 'editor',
        objectType: 'proj',
        objectId: $this->project42,
    );
    $this->store->deleteTuple($t->id);
    $r = $this->store->check('usr', $this->alice, 'editor', 'proj', $this->project42);
    expect($r->allowed)->toBeFalse();
});

it('deleteTuple of an unknown id raises TupleNotFoundException', function () {
    $this->store->deleteTuple(Id::generate('tup'));
})->throws(TupleNotFoundException::class);

it('cascadeRevokeSubject deletes every tuple for that subject', function () {
    $this->store->createTuple(
        subjectType: 'usr', subjectId: $this->alice,
        relation: 'editor', objectType: 'proj', objectId: $this->project42,
    );
    $this->store->createTuple(
        subjectType: 'usr', subjectId: $this->alice,
        relation: 'viewer', objectType: 'proj', objectId: $this->project99,
    );
    $this->store->createTuple(
        subjectType: 'usr', subjectId: $this->bob,
        relation: 'viewer', objectType: 'proj', objectId: $this->project42,
    );
    $removed = $this->store->cascadeRevokeSubject('usr', $this->alice);
    expect($removed)->toBe(2);
    expect($this->store->listTuplesBySubject('usr', $this->alice)->data)->toBe([]);
    expect($this->store->listTuplesBySubject('usr', $this->bob)->data)->toHaveCount(1);
});

it('getTuple round-trips a created tuple', function () {
    $t = $this->store->createTuple(
        subjectType: 'usr', subjectId: $this->alice,
        relation: 'owner', objectType: 'proj', objectId: $this->project42,
        createdBy: $this->alice,
    );
    $f = $this->store->getTuple($t->id);
    expect($f->id)->toBe($t->id);
    expect($f->subjectId)->toBe($this->alice);
    expect($f->relation)->toBe('owner');
    expect($f->objectId)->toBe($this->project42);
    expect($f->createdBy)->toBe($this->alice);
});

it('getTuple raises TupleNotFoundException for unknown id', function () {
    $this->store->getTuple(Id::generate('tup'));
})->throws(TupleNotFoundException::class);

it('listTuplesByObject filters by object and (optionally) relation', function () {
    $this->store->createTuple(
        subjectType: 'usr', subjectId: $this->alice,
        relation: 'owner', objectType: 'proj', objectId: $this->project42,
    );
    $this->store->createTuple(
        subjectType: 'usr', subjectId: $this->bob,
        relation: 'viewer', objectType: 'proj', objectId: $this->project42,
    );
    $this->store->createTuple(
        subjectType: 'usr', subjectId: $this->carol,
        relation: 'viewer', objectType: 'proj', objectId: $this->project99,
    );
    $allOnP42 = $this->store->listTuplesByObject('proj', $this->project42);
    expect($allOnP42->data)->toHaveCount(2);
    $viewersOnP42 = $this->store->listTuplesByObject('proj', $this->project42, 'viewer');
    expect($viewersOnP42->data)->toHaveCount(1);
    expect($viewersOnP42->data[0]->subjectId)->toBe($this->bob);
});

it('listTuplesBySubject paginates', function () {
    $objects = [];
    for ($i = 0; $i < 5; $i++) {
        $objects[] = Id::decode(Id::generate('usr'))['uuid'];
    }
    foreach ($objects as $o) {
        $this->store->createTuple(
            subjectType: 'usr', subjectId: $this->alice,
            relation: 'viewer', objectType: 'proj', objectId: $o,
        );
    }
    $page1 = $this->store->listTuplesBySubject('usr', $this->alice, limit: 2);
    expect($page1->data)->toHaveCount(2);
    expect($page1->nextCursor)->not->toBeNull();
    $page2 = $this->store->listTuplesBySubject('usr', $this->alice, cursor: $page1->nextCursor, limit: 10);
    $allIds = array_merge(
        array_map(fn($t) => $t->id, $page1->data),
        array_map(fn($t) => $t->id, $page2->data),
    );
    expect(count(array_unique($allIds)))->toBe(5);
});

/**
 * Convert a postgres:// URL into a PDO connection. Accepts the same
 * forms as libpq (postgres://user:pass@host:port/db).
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
