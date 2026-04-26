<?php

// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0
//
// Unit tests for v0.2 rewrite-rule evaluation in the PHP SDK.
// Mirrors authz-python/tests/test_rewrite_rules.py and
// node-repo/packages/authz/test/rewrite-rules.test.ts so any
// behavioral drift between implementations surfaces as a failing test.

declare(strict_types=1);

use Flametrench\Authz\Exceptions\EvaluationLimitExceededException;
use Flametrench\Authz\InMemoryTupleStore;
use Flametrench\Authz\RewriteRules\ComputedUserset;
use Flametrench\Authz\RewriteRules\ThisNode;
use Flametrench\Authz\RewriteRules\TupleToUserset;
use Flametrench\Ids\Id;

beforeEach(function () {
    $this->alice = Id::generate('usr');
    $this->bob = Id::generate('usr');
    $this->orgAcme = substr(Id::generate('org'), 4);
    $this->proj42 = substr(Id::generate('org'), 4);
});

describe('empty rules → v0.1-equivalent', function () {
    it('no rules means no derivation', function () {
        $store = new InMemoryTupleStore();
        $store->createTuple(
            subjectType: 'usr',
            subjectId: $this->alice,
            relation: 'editor',
            objectType: 'proj',
            objectId: $this->proj42,
        );
        $result = $store->check(
            subjectType: 'usr',
            subjectId: $this->alice,
            relation: 'viewer',
            objectType: 'proj',
            objectId: $this->proj42,
        );
        expect($result->allowed)->toBeFalse();
    });

    it('empty rules array means no derivation', function () {
        $store = new InMemoryTupleStore(rules: []);
        $store->createTuple(
            subjectType: 'usr',
            subjectId: $this->alice,
            relation: 'editor',
            objectType: 'proj',
            objectId: $this->proj42,
        );
        $result = $store->check(
            subjectType: 'usr',
            subjectId: $this->alice,
            relation: 'viewer',
            objectType: 'proj',
            objectId: $this->proj42,
        );
        expect($result->allowed)->toBeFalse();
    });
});

describe('computed_userset (role implication)', function () {
    it('editor implies viewer', function () {
        $rules = [
            'proj' => [
                'viewer' => [new ThisNode(), new ComputedUserset(relation: 'editor')],
            ],
        ];
        $store = new InMemoryTupleStore(rules: $rules);
        $editor = $store->createTuple(
            subjectType: 'usr',
            subjectId: $this->alice,
            relation: 'editor',
            objectType: 'proj',
            objectId: $this->proj42,
        );
        $result = $store->check(
            subjectType: 'usr',
            subjectId: $this->alice,
            relation: 'viewer',
            objectType: 'proj',
            objectId: $this->proj42,
        );
        expect($result->allowed)->toBeTrue();
        expect($result->matchedTupleId)->toBe($editor->id);
    });

    it('admin → editor → viewer chain', function () {
        $rules = [
            'proj' => [
                'viewer' => [new ThisNode(), new ComputedUserset(relation: 'editor')],
                'editor' => [new ThisNode(), new ComputedUserset(relation: 'admin')],
            ],
        ];
        $store = new InMemoryTupleStore(rules: $rules);
        $admin = $store->createTuple(
            subjectType: 'usr',
            subjectId: $this->alice,
            relation: 'admin',
            objectType: 'proj',
            objectId: $this->proj42,
        );
        $result = $store->check(
            subjectType: 'usr',
            subjectId: $this->alice,
            relation: 'viewer',
            objectType: 'proj',
            objectId: $this->proj42,
        );
        expect($result->allowed)->toBeTrue();
        expect($result->matchedTupleId)->toBe($admin->id);
    });

    it('missing intermediate rule breaks the chain', function () {
        $rules = [
            'proj' => [
                'viewer' => [new ThisNode(), new ComputedUserset(relation: 'editor')],
            ],
        ];
        $store = new InMemoryTupleStore(rules: $rules);
        $store->createTuple(
            subjectType: 'usr',
            subjectId: $this->alice,
            relation: 'admin',
            objectType: 'proj',
            objectId: $this->proj42,
        );
        $result = $store->check(
            subjectType: 'usr',
            subjectId: $this->alice,
            relation: 'viewer',
            objectType: 'proj',
            objectId: $this->proj42,
        );
        expect($result->allowed)->toBeFalse();
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
        $store = new InMemoryTupleStore(rules: $rules);
        $orgAdmin = $store->createTuple(
            subjectType: 'usr',
            subjectId: $this->alice,
            relation: 'admin',
            objectType: 'org',
            objectId: $this->orgAcme,
        );
        $store->createTuple(
            subjectType: 'org',
            subjectId: $this->orgAcme,
            relation: 'parent_org',
            objectType: 'proj',
            objectId: $this->proj42,
        );
        $result = $store->check(
            subjectType: 'usr',
            subjectId: $this->alice,
            relation: 'admin',
            objectType: 'proj',
            objectId: $this->proj42,
        );
        expect($result->allowed)->toBeTrue();
        expect($result->matchedTupleId)->toBe($orgAdmin->id);
    });

    it('org member does not imply proj admin', function () {
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
        $store = new InMemoryTupleStore(rules: $rules);
        $store->createTuple(
            subjectType: 'usr',
            subjectId: $this->alice,
            relation: 'member',
            objectType: 'org',
            objectId: $this->orgAcme,
        );
        $store->createTuple(
            subjectType: 'org',
            subjectId: $this->orgAcme,
            relation: 'parent_org',
            objectType: 'proj',
            objectId: $this->proj42,
        );
        $result = $store->check(
            subjectType: 'usr',
            subjectId: $this->alice,
            relation: 'admin',
            objectType: 'proj',
            objectId: $this->proj42,
        );
        expect($result->allowed)->toBeFalse();
    });
});

describe('cycle detection', function () {
    it('self-referential cycle terminates silently', function () {
        $rules = [
            'proj' => [
                'viewer' => [new ThisNode(), new ComputedUserset(relation: 'viewer')],
            ],
        ];
        $store = new InMemoryTupleStore(rules: $rules);
        $result = $store->check(
            subjectType: 'usr',
            subjectId: $this->alice,
            relation: 'viewer',
            objectType: 'proj',
            objectId: $this->proj42,
        );
        expect($result->allowed)->toBeFalse();
    });

    it('two-node cycle terminates silently', function () {
        $rules = [
            'proj' => [
                'viewer' => [new ThisNode(), new ComputedUserset(relation: 'editor')],
                'editor' => [new ThisNode(), new ComputedUserset(relation: 'viewer')],
            ],
        ];
        $store = new InMemoryTupleStore(rules: $rules);
        $result = $store->check(
            subjectType: 'usr',
            subjectId: $this->alice,
            relation: 'viewer',
            objectType: 'proj',
            objectId: $this->proj42,
        );
        expect($result->allowed)->toBeFalse();
    });
});

describe('evaluation limits', function () {
    it('depth limit raises', function () {
        $rules = [
            'proj' => [
                'r0' => [new ThisNode(), new ComputedUserset(relation: 'r1')],
                'r1' => [new ThisNode(), new ComputedUserset(relation: 'r2')],
                'r2' => [new ThisNode(), new ComputedUserset(relation: 'r3')],
                'r3' => [new ThisNode(), new ComputedUserset(relation: 'r4')],
            ],
        ];
        $store = new InMemoryTupleStore(rules: $rules, maxDepth: 2);
        expect(fn () => $store->check(
            subjectType: 'usr',
            subjectId: $this->alice,
            relation: 'r0',
            objectType: 'proj',
            objectId: $this->proj42,
        ))->toThrow(EvaluationLimitExceededException::class);
    });

    it('fan-out limit raises', function () {
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
        $store = new InMemoryTupleStore(rules: $rules, maxFanOut: 3);
        for ($i = 0; $i < 5; $i++) {
            $store->createTuple(
                subjectType: 'org',
                subjectId: substr(Id::generate('org'), 4),
                relation: 'parent_org',
                objectType: 'proj',
                objectId: $this->proj42,
            );
        }
        expect(fn () => $store->check(
            subjectType: 'usr',
            subjectId: $this->alice,
            relation: 'admin',
            objectType: 'proj',
            objectId: $this->proj42,
        ))->toThrow(EvaluationLimitExceededException::class);
    });
});

describe('direct fast path bypasses rules', function () {
    it('a direct match short-circuits an otherwise-cycling rule set', function () {
        $rules = [
            'proj' => [
                'viewer' => [new ThisNode(), new ComputedUserset(relation: 'viewer')],
            ],
        ];
        $store = new InMemoryTupleStore(rules: $rules, maxDepth: 2);
        $direct = $store->createTuple(
            subjectType: 'usr',
            subjectId: $this->alice,
            relation: 'viewer',
            objectType: 'proj',
            objectId: $this->proj42,
        );
        $result = $store->check(
            subjectType: 'usr',
            subjectId: $this->alice,
            relation: 'viewer',
            objectType: 'proj',
            objectId: $this->proj42,
        );
        expect($result->allowed)->toBeTrue();
        expect($result->matchedTupleId)->toBe($direct->id);
    });
});
