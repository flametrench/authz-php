<?php

// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0
//
// PostgresTupleStore rewrite-rule evaluation per ADR 0017.
// Mirrors RewriteRulesTest.php so any drift between the in-memory and
// Postgres implementations surfaces as a failing test.

declare(strict_types=1);

use Flametrench\Authz\Exceptions\EvaluationLimitExceededException;
use Flametrench\Authz\PostgresTupleStore;
use Flametrench\Authz\RewriteRules\ComputedUserset;
use Flametrench\Authz\RewriteRules\ThisNode;
use Flametrench\Authz\RewriteRules\TupleToUserset;
use Flametrench\Ids\Id;

$postgresUrl = getenv('AUTHZ_POSTGRES_URL') ?: null;

if ($postgresUrl === null) {
    fwrite(STDERR, "[PostgresRewriteRulesTest] AUTHZ_POSTGRES_URL not set; tests skipped.\n");
    return;
}

beforeEach(function () use ($postgresUrl) {
    $pdo = pdoFromUrl($postgresUrl);
    $this->pdo = $pdo;
    $pdo->exec('DROP SCHEMA IF EXISTS public CASCADE; CREATE SCHEMA public;');
    $pdo->exec((string) file_get_contents(__DIR__ . '/postgres-schema.sql'));
    $this->alice = Id::generate('usr');
    $this->orgAcme = substr(Id::generate('org'), 4);
    $this->proj42 = substr(Id::generate('org'), 4);
    // tup.created_by FKs to usr(id) — register Alice for test inserts.
    $stmt = $pdo->prepare("INSERT INTO usr (id, status) VALUES (?, 'active')");
    $stmt->execute([Id::decode($this->alice)['uuid']]);
});

describe('empty rules → v0.2-equivalent behavior', function () {
    it('null rules: no derivation', function () {
        $store = new PostgresTupleStore($this->pdo); // rules undefined
        $store->createTuple(
            subjectType: 'usr',
            subjectId: $this->alice,
            relation: 'editor',
            objectType: 'proj',
            objectId: $this->proj42,
        );
        $r = $store->check('usr', $this->alice, 'viewer', 'proj', $this->proj42);
        expect($r->allowed)->toBeFalse();
    });

    it('empty rules array: no derivation', function () {
        $store = new PostgresTupleStore($this->pdo, rules: []);
        $store->createTuple(
            subjectType: 'usr',
            subjectId: $this->alice,
            relation: 'editor',
            objectType: 'proj',
            objectId: $this->proj42,
        );
        $r = $store->check('usr', $this->alice, 'viewer', 'proj', $this->proj42);
        expect($r->allowed)->toBeFalse();
    });
});

describe('computed_userset (role implication)', function () {
    it('editor implies viewer', function () {
        $rules = [
            'proj' => [
                'viewer' => [new ThisNode(), new ComputedUserset(relation: 'editor')],
            ],
        ];
        $store = new PostgresTupleStore($this->pdo, rules: $rules);
        $editorTup = $store->createTuple(
            subjectType: 'usr',
            subjectId: $this->alice,
            relation: 'editor',
            objectType: 'proj',
            objectId: $this->proj42,
        );
        $r = $store->check('usr', $this->alice, 'viewer', 'proj', $this->proj42);
        expect($r->allowed)->toBeTrue();
        expect($r->matchedTupleId)->toBe($editorTup->id);
    });

    it('admin → editor → viewer chain', function () {
        $rules = [
            'proj' => [
                'viewer' => [new ThisNode(), new ComputedUserset(relation: 'editor')],
                'editor' => [new ThisNode(), new ComputedUserset(relation: 'admin')],
            ],
        ];
        $store = new PostgresTupleStore($this->pdo, rules: $rules);
        $adminTup = $store->createTuple(
            subjectType: 'usr',
            subjectId: $this->alice,
            relation: 'admin',
            objectType: 'proj',
            objectId: $this->proj42,
        );
        $r = $store->check('usr', $this->alice, 'viewer', 'proj', $this->proj42);
        expect($r->allowed)->toBeTrue();
        expect($r->matchedTupleId)->toBe($adminTup->id);
    });
});

describe('tuple_to_userset (parent-child inheritance)', function () {
    it('org admin implies proj admin via parent_org', function () {
        $rules = [
            'proj' => [
                'admin' => [
                    new ThisNode(),
                    new TupleToUserset(
                        tuplesetRelation: 'parent_org',
                        computedUsersetRelation: 'admin',
                    ),
                ],
            ],
        ];
        $store = new PostgresTupleStore($this->pdo, rules: $rules);
        $orgAdminTup = $store->createTuple(
            subjectType: 'usr',
            subjectId: $this->alice,
            relation: 'admin',
            objectType: 'org',
            objectId: $this->orgAcme,
        );
        // The parent_org hop tuple: subject is the org, object is the proj.
        // Wire-format the org subject id so PostgresTupleStore decodes it.
        $store->createTuple(
            subjectType: 'org',
            subjectId: 'org_' . $this->orgAcme,
            relation: 'parent_org',
            objectType: 'proj',
            objectId: $this->proj42,
        );
        $r = $store->check('usr', $this->alice, 'admin', 'proj', $this->proj42);
        expect($r->allowed)->toBeTrue();
        expect($r->matchedTupleId)->toBe($orgAdminTup->id);
    });

    it('org member does NOT imply proj admin', function () {
        $rules = [
            'proj' => [
                'admin' => [
                    new ThisNode(),
                    new TupleToUserset(
                        tuplesetRelation: 'parent_org',
                        computedUsersetRelation: 'admin',
                    ),
                ],
            ],
        ];
        $store = new PostgresTupleStore($this->pdo, rules: $rules);
        $store->createTuple(
            subjectType: 'usr',
            subjectId: $this->alice,
            relation: 'member',
            objectType: 'org',
            objectId: $this->orgAcme,
        );
        $store->createTuple(
            subjectType: 'org',
            subjectId: 'org_' . $this->orgAcme,
            relation: 'parent_org',
            objectType: 'proj',
            objectId: $this->proj42,
        );
        $r = $store->check('usr', $this->alice, 'admin', 'proj', $this->proj42);
        expect($r->allowed)->toBeFalse();
    });
});

describe('cycle detection', function () {
    it('self-referential cycle terminates silently', function () {
        $rules = [
            'proj' => [
                'viewer' => [new ThisNode(), new ComputedUserset(relation: 'viewer')],
            ],
        ];
        $store = new PostgresTupleStore($this->pdo, rules: $rules);
        $r = $store->check('usr', $this->alice, 'viewer', 'proj', $this->proj42);
        expect($r->allowed)->toBeFalse();
    });
});

describe('evaluation bounds', function () {
    it('depth limit raises', function () {
        $rules = [
            'proj' => [
                'viewer' => [new ComputedUserset(relation: 'editor')],
                'editor' => [new ComputedUserset(relation: 'admin')],
                'admin' => [new ComputedUserset(relation: 'owner')],
                'owner' => [new ComputedUserset(relation: 'super')],
            ],
        ];
        $store = new PostgresTupleStore($this->pdo, rules: $rules, maxDepth: 2);
        expect(fn() => $store->check('usr', $this->alice, 'viewer', 'proj', $this->proj42))
            ->toThrow(EvaluationLimitExceededException::class);
    });
});

describe('checkAny()', function () {
    it('fast path with no rules: single SELECT short-circuits', function () {
        $store = new PostgresTupleStore($this->pdo);
        $store->createTuple(
            subjectType: 'usr',
            subjectId: $this->alice,
            relation: 'editor',
            objectType: 'proj',
            objectId: $this->proj42,
        );
        $r = $store->checkAny('usr', $this->alice, ['viewer', 'editor'], 'proj', $this->proj42);
        expect($r->allowed)->toBeTrue();
    });

    it('with rules: evaluates each relation in turn', function () {
        $rules = [
            'proj' => [
                'viewer' => [new ThisNode(), new ComputedUserset(relation: 'editor')],
            ],
        ];
        $store = new PostgresTupleStore($this->pdo, rules: $rules);
        $store->createTuple(
            subjectType: 'usr',
            subjectId: $this->alice,
            relation: 'editor',
            objectType: 'proj',
            objectId: $this->proj42,
        );
        $r = $store->checkAny('usr', $this->alice, ['admin', 'viewer'], 'proj', $this->proj42);
        expect($r->allowed)->toBeTrue();
    });
});
