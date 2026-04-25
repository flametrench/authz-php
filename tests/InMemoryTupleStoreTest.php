<?php

// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

use Flametrench\Authz\Exceptions\DuplicateTupleException;
use Flametrench\Authz\Exceptions\EmptyRelationSetException;
use Flametrench\Authz\Exceptions\InvalidFormatException;
use Flametrench\Authz\Exceptions\TupleNotFoundException;
use Flametrench\Authz\InMemoryTupleStore;
use Flametrench\Ids\Id;

beforeEach(function () {
    $this->store = new InMemoryTupleStore();
    $this->alice = Id::generate('usr');
    $this->bob = Id::generate('usr');
    $this->carol = Id::generate('usr');
    $this->orgAcme = Id::generate('org');
    // proj is 4 chars (object-type prefix max is 6 chars per spec).
    $this->project42 = substr(Id::generate('org'), 4); // raw uuid hex
});

describe('createTuple', function () {
    it('creates and returns a tuple with a fresh tup_ id', function () {
        $t = $this->store->createTuple(
            subjectType: 'usr',
            subjectId: $this->alice,
            relation: 'owner',
            objectType: 'org',
            objectId: $this->orgAcme,
            createdBy: $this->alice,
        );
        expect($t->id)->toMatch('/^tup_[0-9a-f]{32}$/');
        expect($t->createdBy)->toBe($this->alice);
    });

    it('rejects duplicate natural key with the existing id attached', function () {
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

    it('rejects invalid relation names (uppercase)', function () {
        expect(fn() => $this->store->createTuple(
            subjectType: 'usr',
            subjectId: $this->alice,
            relation: 'Owner',
            objectType: 'org',
            objectId: $this->orgAcme,
        ))->toThrow(InvalidFormatException::class);
    });

    it('rejects invalid object types (too long)', function () {
        expect(fn() => $this->store->createTuple(
            subjectType: 'usr',
            subjectId: $this->alice,
            relation: 'viewer',
            objectType: 'project', // 7 chars exceeds 6
            objectId: $this->project42,
        ))->toThrow(InvalidFormatException::class);
    });

    it('accepts custom relations matching the regex', function () {
        $t = $this->store->createTuple(
            subjectType: 'usr',
            subjectId: $this->alice,
            relation: 'dispatcher',
            objectType: 'org',
            objectId: $this->orgAcme,
        );
        expect($t->relation)->toBe('dispatcher');
    });
});

describe('check (exact-match)', function () {
    beforeEach(function () {
        $this->store->createTuple(
            subjectType: 'usr',
            subjectId: $this->alice,
            relation: 'editor',
            objectType: 'proj',
            objectId: $this->project42,
        );
    });

    it('hits on exact match', function () {
        $r = $this->store->check(
            subjectType: 'usr',
            subjectId: $this->alice,
            relation: 'editor',
            objectType: 'proj',
            objectId: $this->project42,
        );
        expect($r->allowed)->toBeTrue();
        expect($r->matchedTupleId)->toMatch('/^tup_/');
    });

    it('misses on different relation, subject, or object', function () {
        expect($this->store->check(
            subjectType: 'usr',
            subjectId: $this->alice,
            relation: 'viewer',
            objectType: 'proj',
            objectId: $this->project42,
        )->allowed)->toBeFalse();
        expect($this->store->check(
            subjectType: 'usr',
            subjectId: $this->bob,
            relation: 'editor',
            objectType: 'proj',
            objectId: $this->project42,
        )->allowed)->toBeFalse();
    });
});

describe('no-derivation invariant (ADR 0001)', function () {
    it('admin does NOT imply editor', function () {
        $this->store->createTuple(
            subjectType: 'usr',
            subjectId: $this->alice,
            relation: 'admin',
            objectType: 'org',
            objectId: $this->orgAcme,
        );
        expect($this->store->check(
            subjectType: 'usr',
            subjectId: $this->alice,
            relation: 'editor',
            objectType: 'org',
            objectId: $this->orgAcme,
        )->allowed)->toBeFalse();
    });

    it('membership does NOT imply object-level access', function () {
        $this->store->createTuple(
            subjectType: 'usr',
            subjectId: $this->alice,
            relation: 'member',
            objectType: 'org',
            objectId: $this->orgAcme,
        );
        expect($this->store->check(
            subjectType: 'usr',
            subjectId: $this->alice,
            relation: 'viewer',
            objectType: 'proj',
            objectId: $this->project42,
        )->allowed)->toBeFalse();
    });
});

describe('checkAny', function () {
    beforeEach(function () {
        $this->store->createTuple(
            subjectType: 'usr',
            subjectId: $this->alice,
            relation: 'editor',
            objectType: 'proj',
            objectId: $this->project42,
        );
    });

    it('returns true when any listed relation matches', function () {
        $r = $this->store->checkAny(
            subjectType: 'usr',
            subjectId: $this->alice,
            relations: ['viewer', 'editor', 'owner'],
            objectType: 'proj',
            objectId: $this->project42,
        );
        expect($r->allowed)->toBeTrue();
    });

    it('returns false when none match', function () {
        $r = $this->store->checkAny(
            subjectType: 'usr',
            subjectId: $this->alice,
            relations: ['viewer', 'admin'],
            objectType: 'proj',
            objectId: $this->project42,
        );
        expect($r->allowed)->toBeFalse();
    });

    it('rejects empty relation set', function () {
        expect(fn() => $this->store->checkAny(
            subjectType: 'usr',
            subjectId: $this->alice,
            relations: [],
            objectType: 'proj',
            objectId: $this->project42,
        ))->toThrow(EmptyRelationSetException::class);
    });
});

describe('deleteTuple', function () {
    it('removes from natural-key index too (allowing recreation)', function () {
        $t = $this->store->createTuple(
            subjectType: 'usr',
            subjectId: $this->alice,
            relation: 'viewer',
            objectType: 'proj',
            objectId: $this->project42,
        );
        $this->store->deleteTuple($t->id);
        expect($this->store->check(
            subjectType: 'usr',
            subjectId: $this->alice,
            relation: 'viewer',
            objectType: 'proj',
            objectId: $this->project42,
        )->allowed)->toBeFalse();
        $recreated = $this->store->createTuple(
            subjectType: 'usr',
            subjectId: $this->alice,
            relation: 'viewer',
            objectType: 'proj',
            objectId: $this->project42,
        );
        expect($recreated->id)->not->toBe($t->id);
    });

    it('throws TupleNotFoundException for unknown ids', function () {
        expect(fn() => $this->store->deleteTuple('tup_' . str_repeat('0', 32)))
            ->toThrow(TupleNotFoundException::class);
    });
});

describe('cascadeRevokeSubject', function () {
    it('deletes every tuple held by a subject and returns the count', function () {
        $this->store->createTuple(
            subjectType: 'usr',
            subjectId: $this->alice,
            relation: 'owner',
            objectType: 'org',
            objectId: $this->orgAcme,
        );
        $this->store->createTuple(
            subjectType: 'usr',
            subjectId: $this->alice,
            relation: 'editor',
            objectType: 'proj',
            objectId: $this->project42,
        );
        $this->store->createTuple(
            subjectType: 'usr',
            subjectId: $this->bob,
            relation: 'member',
            objectType: 'org',
            objectId: $this->orgAcme,
        );
        $n = $this->store->cascadeRevokeSubject('usr', $this->alice);
        expect($n)->toBe(2);
        expect(count($this->store->listTuplesBySubject('usr', $this->alice)->data))->toBe(0);
        expect(count($this->store->listTuplesBySubject('usr', $this->bob)->data))->toBe(1);
    });
});

describe('uniqueness fixture', function () {
    it('two tuples with identical natural keys cannot coexist', function () {
        $this->store->createTuple(
            subjectType: 'usr',
            subjectId: $this->alice,
            relation: 'owner',
            objectType: 'org',
            objectId: $this->orgAcme,
        );
        expect(fn() => $this->store->createTuple(
            subjectType: 'usr',
            subjectId: $this->alice,
            relation: 'owner',
            objectType: 'org',
            objectId: $this->orgAcme,
        ))->toThrow(DuplicateTupleException::class);
    });
});

describe('listing', function () {
    it('listTuplesByObject filters by relation when provided', function () {
        foreach ([$this->alice, $this->bob, $this->carol] as $u) {
            $this->store->createTuple(
                subjectType: 'usr',
                subjectId: $u,
                relation: 'viewer',
                objectType: 'proj',
                objectId: $this->project42,
            );
        }
        $this->store->createTuple(
            subjectType: 'usr',
            subjectId: $this->alice,
            relation: 'editor',
            objectType: 'proj',
            objectId: $this->project42,
        );
        $viewers = $this->store->listTuplesByObject('proj', $this->project42, 'viewer');
        expect($viewers->data)->toHaveCount(3);
        $all = $this->store->listTuplesByObject('proj', $this->project42);
        expect($all->data)->toHaveCount(4);
    });
});
