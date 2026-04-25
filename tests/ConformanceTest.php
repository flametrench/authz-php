<?php

// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0
//
// Flametrench v0.1 conformance suite — PHP / PEST harness for the
// authorization capability.
//
// Exercises check, check_any, and create_tuple (uniqueness + format)
// against the fixture corpus vendored from
// github.com/flametrench/spec/conformance/fixtures/authorization/.
// Tests under tests/conformance/fixtures/ are a snapshot; the
// drift-check CI job verifies they match the upstream spec repo.

declare(strict_types=1);

use Flametrench\Authz\Exceptions\DuplicateTupleException;
use Flametrench\Authz\Exceptions\EmptyRelationSetException;
use Flametrench\Authz\Exceptions\InvalidFormatException;
use Flametrench\Authz\InMemoryTupleStore;

const FIXTURES_DIR = __DIR__ . '/conformance/fixtures';

/**
 * @return array{spec_version:string, capability:string, operation:string,
 *     conformance_level:string, description:string, tests:array<int,array>}
 */
function loadAuthzFixture(string $relativePath): array
{
    $raw = file_get_contents(FIXTURES_DIR . '/' . $relativePath);
    if ($raw === false) {
        throw new RuntimeException("Cannot read fixture: {$relativePath}");
    }
    $decoded = json_decode($raw, true);
    if (!is_array($decoded)) {
        throw new RuntimeException("Invalid JSON in fixture: {$relativePath}");
    }
    return $decoded;
}

function errorClassForSpecName(string $name): string
{
    return match ($name) {
        'DuplicateTupleError' => DuplicateTupleException::class,
        'InvalidFormatError' => InvalidFormatException::class,
        'EmptyRelationSetError' => EmptyRelationSetException::class,
        default => throw new RuntimeException("Unknown spec error: {$name}"),
    };
}

/**
 * Seed an empty store with the fixture's `given_tuples` precondition.
 *
 * @param array<int, array{subject_type:string,subject_id:string,relation:string,object_type:string,object_id:string}> $given
 */
function seedAuthz(InMemoryTupleStore $store, array $given): void
{
    foreach ($given as $t) {
        $store->createTuple(
            subjectType: $t['subject_type'],
            subjectId: $t['subject_id'],
            relation: $t['relation'],
            objectType: $t['object_type'],
            objectId: $t['object_id'],
        );
    }
}

// ─── authorization.check (exact match) ───

describe(
    'Conformance · authorization.check [MUST]',
    function () {
        $fixture = loadAuthzFixture('authorization/check.json');
        foreach ($fixture['tests'] as $t) {
            it("[{$t['id']}] {$t['description']}", function () use ($t) {
                $store = new InMemoryTupleStore();
                seedAuthz($store, $t['input']['given_tuples']);
                $c = $t['input']['check'];
                $result = $store->check(
                    subjectType: $c['subject_type'],
                    subjectId: $c['subject_id'],
                    relation: $c['relation'],
                    objectType: $c['object_type'],
                    objectId: $c['object_id'],
                );
                expect($result->allowed)->toBe($t['expected']['result']['allowed']);
            });
        }
    },
);

// ─── authorization.check_any (set form) ───

describe(
    'Conformance · authorization.check_any [MUST]',
    function () {
        $fixture = loadAuthzFixture('authorization/check-any.json');
        foreach ($fixture['tests'] as $t) {
            it("[{$t['id']}] {$t['description']}", function () use ($t) {
                $store = new InMemoryTupleStore();
                seedAuthz($store, $t['input']['given_tuples']);
                $c = $t['input']['check'];
                if (isset($t['expected']['error'])) {
                    $expectedClass = errorClassForSpecName($t['expected']['error']);
                    expect(fn() => $store->checkAny(
                        subjectType: $c['subject_type'],
                        subjectId: $c['subject_id'],
                        relations: $c['relations'],
                        objectType: $c['object_type'],
                        objectId: $c['object_id'],
                    ))->toThrow($expectedClass);
                } else {
                    $result = $store->checkAny(
                        subjectType: $c['subject_type'],
                        subjectId: $c['subject_id'],
                        relations: $c['relations'],
                        objectType: $c['object_type'],
                        objectId: $c['object_id'],
                    );
                    expect($result->allowed)->toBe($t['expected']['result']['allowed']);
                }
            });
        }
    },
);

// ─── authorization.create_tuple (uniqueness) ───

describe(
    'Conformance · authorization.create_tuple [MUST] · uniqueness',
    function () {
        $fixture = loadAuthzFixture('authorization/uniqueness.json');
        foreach ($fixture['tests'] as $t) {
            it("[{$t['id']}] {$t['description']}", function () use ($t) {
                $store = new InMemoryTupleStore();
                seedAuthz($store, $t['input']['given_tuples']);
                $c = $t['input']['create'];
                if (isset($t['expected']['error'])) {
                    $expectedClass = errorClassForSpecName($t['expected']['error']);
                    expect(fn() => $store->createTuple(
                        subjectType: $c['subject_type'],
                        subjectId: $c['subject_id'],
                        relation: $c['relation'],
                        objectType: $c['object_type'],
                        objectId: $c['object_id'],
                    ))->toThrow($expectedClass);
                } else {
                    $created = $store->createTuple(
                        subjectType: $c['subject_type'],
                        subjectId: $c['subject_id'],
                        relation: $c['relation'],
                        objectType: $c['object_type'],
                        objectId: $c['object_id'],
                    );
                    expect($created->id)->toMatch('/^tup_/');
                }
            });
        }
    },
);

// ─── authorization.create_tuple (format) ───

describe(
    'Conformance · authorization.create_tuple [MUST] · format',
    function () {
        $fixture = loadAuthzFixture('authorization/format.json');
        foreach ($fixture['tests'] as $t) {
            it("[{$t['id']}] {$t['description']}", function () use ($t) {
                $store = new InMemoryTupleStore();
                seedAuthz($store, $t['input']['given_tuples']);
                $c = $t['input']['create'];
                if (isset($t['expected']['error'])) {
                    $expectedClass = errorClassForSpecName($t['expected']['error']);
                    expect(fn() => $store->createTuple(
                        subjectType: $c['subject_type'],
                        subjectId: $c['subject_id'],
                        relation: $c['relation'],
                        objectType: $c['object_type'],
                        objectId: $c['object_id'],
                    ))->toThrow($expectedClass);
                } else {
                    $created = $store->createTuple(
                        subjectType: $c['subject_type'],
                        subjectId: $c['subject_id'],
                        relation: $c['relation'],
                        objectType: $c['object_type'],
                        objectId: $c['object_id'],
                    );
                    expect($created->id)->toMatch('/^tup_/');
                }
            });
        }
    },
);
