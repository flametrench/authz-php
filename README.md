# flametrench/authz

[![CI](https://github.com/flametrench/authz-php/actions/workflows/ci.yml/badge.svg)](https://github.com/flametrench/authz-php/actions/workflows/ci.yml)

Authorization primitives for [Flametrench](https://flametrench.dev): relational tuples and exact-match `check()`. Spec-conformant — exact-match remains the default, with **no implicit rewriting** at the API boundary ([ADR 0001](https://github.com/flametrench/spec/blob/main/decisions/0001-authorization-model.md)). v0.2 adds opt-in rewrite rules ([ADR 0007](https://github.com/flametrench/spec/blob/main/decisions/0007-rewrite-rules.md)) — `computed_userset` (role implication) and `tuple_to_userset` (parent-child inheritance) — for adopters who want hierarchies. Group expansion remains deferred.

The PHP counterpart of [`@flametrench/authz`](https://github.com/flametrench/node/tree/main/packages/authz). Same shapes, same invariants, same test fixtures.

**Status:** v0.2.0-rc.4 (release candidate). PHP 8.3+ required. Includes `ShareStore` ([ADR 0012](https://github.com/flametrench/spec/blob/main/decisions/0012-share-tokens.md)) and Postgres-backed adapters (`PostgresTupleStore`, `PostgresShareStore`).

## Install

```bash
composer require flametrench/authz
```

## Quick start

```php
use Flametrench\Authz\InMemoryTupleStore;

$store = new InMemoryTupleStore();

$store->createTuple(
    subjectType: 'usr',
    subjectId: 'usr_0190...alice',
    relation: 'editor',
    objectType: 'proj',
    objectId: '0190...project42',
);

// Single-relation check.
$result = $store->check(
    subjectType: 'usr',
    subjectId: 'usr_0190...alice',
    relation: 'editor',
    objectType: 'proj',
    objectId: '0190...project42',
);
// $result->allowed === true

// Set-form: true if any of the listed relations matches.
$any = $store->checkAny(
    subjectType: 'usr',
    subjectId: 'usr_0190...alice',
    relations: ['owner', 'admin', 'editor'],
    objectType: 'proj',
    objectId: '0190...project42',
);
```

## Default `check()` semantics

`check()` is **exact match by default**. `admin` does NOT imply `editor`. `editor` does NOT imply `viewer`. Being a `member` of an org does NOT imply any object-level access. The test suite has dedicated fixtures for each invariant — they catch the most common way an SDK could accidentally violate ADR 0001.

If you want implication or inheritance, three options:

- **Materialize at state-change time** (Pattern A) — write the implied tuples explicitly when state changes. Works at every spec version.
- **Pass a relation set to `checkAny`** (Pattern B) — let the caller list equivalent relations.
- **Opt into v0.2 rewrite rules** ([ADR 0007](https://github.com/flametrench/spec/blob/main/decisions/0007-rewrite-rules.md)) — declare `computed_userset` (role implication) and `tuple_to_userset` (parent-child inheritance) explicitly, with depth and fan-out caps. Currently in-memory only; Postgres-backed rule evaluation lands in a future release.

## Format rules

- **Relations** match `/^[a-z_]{2,32}$/`. Six built-ins (`owner`, `admin`, `member`, `guest`, `viewer`, `editor`); applications register custom relations matching the same pattern.
- **Object-type prefixes** match `/^[a-z]{2,6}$/` per `docs/ids.md`. Use short prefixes — `proj` not `project`, `doc` not `document`.
- **Subject types** must be `'usr'`. Group subjects (`grp`) remain deferred.

## Errors

Every error is a `Flametrench\Authz\Exceptions\AuthzException` subclass with a `flametrenchCode` matching the OpenAPI Error envelope:

| Class | Code |
|---|---|
| `TupleNotFoundException` | `not_found` |
| `DuplicateTupleException` | `conflict.duplicate_tuple` (carries `existingTupleId`) |
| `InvalidFormatException` | `invalid_format.<field>` |
| `EmptyRelationSetException` | `invalid_format.relations` |

## Development

```bash
composer install
composer test
```

## License

Apache License 2.0. Copyright 2026 NDC Digital, LLC.
