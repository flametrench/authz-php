# flametrench/authz

Authorization primitives for [Flametrench](https://flametrench.dev): relational tuples and exact-match `check()`. Spec-conformant to v0.1 — **no rewrite rules, no derivation, no group expansion** in v0.1 per [ADR 0001](https://github.com/flametrench/spec/blob/main/decisions/0001-authorization-model.md).

The PHP counterpart of [`@flametrench/authz`](https://github.com/flametrench/node/tree/main/packages/authz). Same shapes, same invariants, same test fixtures (the no-derivation invariants are explicitly tested in both languages).

**Status:** v0.0.1 — early. PHP 8.3+ required.

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

## What's explicitly excluded from v0.1

`check()` is **exact match only**. `admin` does NOT imply `editor`. `editor` does NOT imply `viewer`. Being a `member` of an org does NOT imply any object-level access. The test suite has dedicated fixtures for each invariant — they catch the most common way an SDK could accidentally violate ADR 0001.

If you need implication or inheritance, the spec's Pattern A (materialize implied tuples at state-change time) or Pattern B (pass a relation set to `checkAny`) are the sanctioned workarounds. See [`docs/authorization.md`](https://github.com/flametrench/spec/blob/main/docs/authorization.md).

## Format rules

- **Relations** match `/^[a-z_]{2,32}$/`. Six built-ins (`owner`, `admin`, `member`, `guest`, `viewer`, `editor`); applications register custom relations matching the same pattern.
- **Object-type prefixes** match `/^[a-z]{2,6}$/` per `docs/ids.md`. Use short prefixes — `proj` not `project`, `doc` not `document`.
- **Subject types** in v0.1 must be `'usr'`. `grp` (group subjects) is a v0.2+ addition.

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
