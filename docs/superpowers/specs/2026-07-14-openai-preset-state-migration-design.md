# OpenAI Preset State Migration Design

## Background

`DomainPresetService` gained three OpenAI login helper domains after existing users had already saved the earlier OpenAI or AI Services Bundle preset. `StateStore.Load()` currently normalizes missing collections but does not evolve saved preset rules, so an old `state.json` can remain incomplete after the application is upgraded.

The affected helper domains are:

- `files.oaiusercontent.com`
- `challenges.cloudflare.com`
- `cdn.auth0.com`

## Goal

When the primary application state contains the complete, unchanged legacy OpenAI preset, automatically add the three helper-domain rules and persist the upgraded state before domain-route renewal starts.

## Non-goals

- Do not add OpenAI rules to an empty state or a manually assembled partial rule set.
- Do not change, enable, disable, or remove existing domain rules.
- Do not migrate `applied-state.json` or `temp-lists.json`.
- Do not change route-renewal, DNS-resolution, rollback, or tunnel-selection behavior.
- Do not introduce general schema-version or applied-preset metadata in this scoped fix.

## Migration Match

The state qualifies only when every legacy OpenAI preset domain below exists, using a case-insensitive comparison, and every matching rule is enabled with mode `UseWireGuard`:

- `chatgpt.com`
- `*.chatgpt.com`
- `openai.com`
- `*.openai.com`
- `auth.openai.com`
- `api.openai.com`
- `platform.openai.com`
- `oaistatic.com`
- `*.oaistatic.com`
- `oaiusercontent.com`
- `*.oaiusercontent.com`

Extra custom rules and rules belonging to other presets do not prevent migration.

If any legacy OpenAI rule is missing, disabled, or set to another mode, the migration makes no changes. This conservative check prevents a partial or intentionally customized rule set from being treated as the old preset.

## Architecture

Add a focused core migration service that accepts an `AppState`, checks the legacy preset signature, adds only missing helper domains through the existing rule-mutation path, and returns a result containing the number of rules added.

The service must be idempotent. If all helper domains already exist, or the same state is migrated twice, the second run adds zero rules. An existing helper-domain rule is preserved exactly, even if it is disabled or uses another route mode.

Windows and macOS primary-state initialization will call the migration immediately after loading `state.json`. When the result reports one or more additions, the application saves that state through the existing atomic `StateStore.Save()` implementation before loading the UI or renewing routes.

The generic `StateStore.Load()` behavior remains unchanged because the same store type is also used for rollback and temporary-list files that must not be migrated.

## Data Flow

1. Load the primary `state.json` with `StateStore.Load()`.
2. Pass the loaded state to the preset migration service.
3. Check the complete legacy OpenAI preset signature.
4. If it matches, add each missing helper rule as enabled and `UseWireGuard`.
5. Save only when at least one rule was added.
6. Continue the existing startup flow; route renewal sees the upgraded rules.

## Error Handling

Existing invalid-JSON and atomic-save behavior remains authoritative. Migration is in-memory and does not catch or hide load/save failures. If the state does not match the legacy signature, the result is a normal no-op rather than an error.

## Test Strategy

Core regression tests will verify:

- A complete enabled `UseWireGuard` legacy OpenAI preset adds exactly the three helper domains.
- A second migration run adds zero rules and creates no duplicates.
- A partial/manual OpenAI rule set is unchanged.
- A legacy signature with a disabled rule is unchanged.
- A legacy signature with a non-`UseWireGuard` rule is unchanged.
- An existing customized helper-domain rule is preserved rather than overwritten.
- Extra unrelated rules do not block migration.
- Primary-state integration saves an upgraded state, while ordinary `StateStore.Load()` remains migration-free.

The focused regression tests run first in red-green order, followed by the complete test suite and Release build.

## Success Criteria

- The user's current legacy AI Services Bundle state receives exactly the three missing helper rules on next startup.
- Hand-built or customized partial OpenAI configurations remain untouched.
- Repeated startups do not change the state after the first successful migration.
- Windows and macOS behave consistently.
- `applied-state.json` and `temp-lists.json` are not modified by migration.
