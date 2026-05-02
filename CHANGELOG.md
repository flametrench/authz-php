# Changelog

All notable changes to `flametrench/authz` are recorded here.
Spec-level changes live in [`spec/CHANGELOG.md`](https://github.com/flametrench/spec/blob/main/CHANGELOG.md).

## [v0.3.0] — Unreleased

### Added (Postgres rewrite-rule evaluation, ADR 0017)
- `PostgresTupleStore` constructor accepts a new optional `$rules` parameter mirroring `InMemoryTupleStore`. With `$rules` unset (or `[]`), behavior is byte-identical to v0.2 (single SELECT with `relation = ANY($3)` short-circuits the `checkAny` fast path).
- With `$rules` set, `check()` evaluates rewrite rules via iterative expansion against Postgres — same algorithm as `InMemoryTupleStore` (cycle detection, depth + fan-out bounds, short-circuit semantics from ADR 0007 unchanged).
- New `$maxDepth` and `$maxFanOut` constructor parameters expose the same evaluation bounds as `InMemoryTupleStore`.
- New private `subjectIdToUuid` helper accepts wire-format ids with any registered prefix (e.g. `org_<hex>`), not just `usr_<hex>`. Required for `tuple_to_userset` patterns where the parent hop is a non-`usr` object.
- New `PostgresRewriteRulesTest` covers `computed_userset` chains, `tuple_to_userset` parent inheritance, cycle detection, depth limit, and `checkAny` fast-path / rules-path against the live Postgres adapter.

### Test infrastructure
- Test-vendored `postgres-schema.sql` re-synced from spec `reference/postgres.sql` to pick up the relaxed `tup.subject_type` constraint (now `^[a-z]{2,6}$` per ADR 0017 follow-up). The v0.1/v0.2 `subject_type IN ('usr')` constraint silently blocked `tuple_to_userset` patterns; lifting it is additive.
- `pdoFromUrl()` extracted to `tests/Helpers.php` and loaded via `Pest.php` so multiple Postgres-backed test files share one DSN parser.

### Required dependency bump
- `flametrench/ids` constraint now `^0.3.0` to track the v0.3 family. The runtime doesn't require any new prefixes from ids-php (PAT lives on identity-php), but the bump keeps the dependency family aligned.

## [v0.2.0-rc.4] — 2026-04-27

### Fixed
- `PostgresTupleStore` (`createTuple`, `checkAny`, `listTuplesByObject`) and `PostgresShareStore` (`createShare`, `listSharesForObject`) now accept wire-format `object_id` values with app-defined prefixes (e.g. `proj_<32hex>`, `file_<32hex>`) in addition to bare 32-hex and canonical hyphenated UUIDs. Previously, binding a wire-format `object_id` directly to the UUID column raised a Postgres parse error. `object_type` is application-defined per ADR 0001, so adopters legitimately pass wire-format prefixed IDs at this boundary. Closes [`spec#8`](https://github.com/flametrench/spec/issues/8).

## [v0.2.0-rc.3] — 2026-04-27

### Added
- `Flametrench\Authz\ShareStore` interface and two implementations — `InMemoryShareStore` and `PostgresShareStore`. Implements [ADR 0012](https://github.com/flametrench/spec/blob/main/decisions/0012-share-tokens.md)'s share-token primitive: time-bounded, presentation-bearer access to a single resource without minting an authenticated principal. Closes [`spec#7`](https://github.com/flametrench/spec/issues/7).
  - Token storage matches `ses`: SHA-256 → 32 bytes `BYTEA`, `hash_equals` constant-time compare on verify.
  - Verification ordering is normative: revoked > consumed > expired > success.
  - `singleUse` shares consume on first verify via `UPDATE … WHERE consumed_at IS NULL RETURNING …`, so concurrent verifies of a single-use token race-correctly to exactly one success and one `ShareConsumedException`.
  - 365-day spec ceiling on `$expiresInSeconds`; `InvalidFormatException` raised for over-long lifetimes. `ShareStore::MAX_TTL_SECONDS` constant exposes the bound.
  - New value classes: `Share`, `CreateShareResult`, `VerifiedShare`.
  - New exceptions: `InvalidShareTokenException`, `ShareExpiredException`, `ShareRevokedException`, `ShareConsumedException`, `ShareNotFoundException`.
- 32 new tests (18 in-memory + 14 Postgres); Postgres set gated on `AUTHZ_POSTGRES_URL`.

### Bumped
- Dependency on `flametrench/ids` retains the `^0.2.0-rc` constraint; the `shr` prefix lands in `flametrench/ids` v0.2.0-rc.2.

## [v0.2.0-rc.2] — 2026-04-27

### Added
- `Flametrench\Authz\PostgresTupleStore` — a Postgres-backed `TupleStore`. Mirrors `InMemoryTupleStore` byte-for-byte at the SDK boundary; the difference is durability and concurrency.
  - Schema: `spec/reference/postgres.sql` (the `tup` table). Apply before constructing the store.
  - Connection: accepts a `PDO` instance. `ext-pdo` and `ext-pdo_pgsql` are listed under `suggest` rather than `require` — adopters using only the in-memory store don't need them.
  - Coverage: 15 integration tests, gated on `AUTHZ_POSTGRES_URL`.
- Rewrite-rule support (ADR 0007) is exact-match only in the Postgres store; bridging the synchronous evaluator to PDO is tracked for v0.3. Adopters with rule needs can pull the relevant tuple subset into memory and use `InMemoryTupleStore` with the `rules` constructor option.

## [v0.2.0-rc.1] — 2026-04-25

Initial v0.2 release-candidate. ADR 0007 rewrite rules in `InMemoryTupleStore`. See [`spec/CHANGELOG.md`](https://github.com/flametrench/spec/blob/main/CHANGELOG.md) for the spec-level summary.

For pre-rc history, see git tags.
