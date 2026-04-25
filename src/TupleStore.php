<?php

// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Flametrench\Authz;

/**
 * The contract every authorization backend implements. Exact-match
 * semantics: check() returns true iff a tuple with the EXACT 5-tuple key
 * exists. No derivation, no inheritance, no group expansion in v0.1.
 */
interface TupleStore
{
    public function createTuple(
        string $subjectType, // 'usr' in v0.1
        string $subjectId,
        string $relation,
        string $objectType,
        string $objectId,
        ?string $createdBy = null,
    ): Tuple;

    public function deleteTuple(string $tupleId): void;

    /** @return int Number of tuples deleted. */
    public function cascadeRevokeSubject(string $subjectType, string $subjectId): int;

    public function check(
        string $subjectType,
        string $subjectId,
        string $relation,
        string $objectType,
        string $objectId,
    ): CheckResult;

    /**
     * @param list<string> $relations
     */
    public function checkAny(
        string $subjectType,
        string $subjectId,
        array $relations,
        string $objectType,
        string $objectId,
    ): CheckResult;

    public function getTuple(string $tupleId): Tuple;

    /**
     * @return Page<Tuple>
     */
    public function listTuplesBySubject(
        string $subjectType,
        string $subjectId,
        ?string $cursor = null,
        int $limit = 50,
    ): Page;

    /**
     * @return Page<Tuple>
     */
    public function listTuplesByObject(
        string $objectType,
        string $objectId,
        ?string $relation = null,
        ?string $cursor = null,
        int $limit = 50,
    ): Page;
}
