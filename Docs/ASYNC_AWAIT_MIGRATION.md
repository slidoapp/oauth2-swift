# Async/Await and Swift 6 Migration

Status: implemented Swift 5.10 rewrite and Swift 6 migration plan for [PS-22014](https://sli-do.atlassian.net/browse/PS-22014)

## Goals

- Make Swift 5.10 the minimum toolchain and compile every owned target in Swift 5 language mode with complete strict-concurrency checking.
- Replace the public callback API with async/await. Source compatibility with the current API is not a goal.
- Make an OAuth client safe to call from background tasks without isolating networking or token work to the main actor.
- Isolate UIKit, AppKit, and AuthenticationServices state to `MainActor`.
- Preserve the currently supported OAuth behavior unless a separate product decision explicitly removes a flow or provider variation.
- Establish a continuously tested path to Swift 6 language mode.

The migration must not hide warnings with broad `@preconcurrency` imports, `nonisolated(unsafe)`, or unaudited `@unchecked Sendable` conformances. A narrow interoperability wrapper may use one of these tools only when it documents and enforces the missing synchronization guarantee.

## Toolchain Terms

The migration treats these as three independent settings:

1. **Package tools version** controls which `Package.swift` APIs are available. The first target is `swift-tools-version: 5.10`.
2. **Compiler version** is the installed Swift toolchain. Xcode 15.4 supplies Swift 5.10; newer Xcodes supply Swift 6 compilers.
3. **Language mode** controls source semantics. The first target uses Swift 5 language mode with complete checking. The final target uses Swift 6 language mode.

For a Swift 5.10 manifest, complete checking is enabled per target with:

```swift
.enableExperimentalFeature("StrictConcurrency")
```

A Swift 6 compiler can test Swift 6 language mode before the manifest moves to tools 6:

```shell
swift test -Xswiftc -swift-version -Xswiftc 6
```

After that command passes, the manifest can move to tools 6 and declare Swift 6 language mode directly.

## Current Baseline

The baseline was captured from tag `6.2.0` on 2026-07-10:

- `Package.swift` uses tools 5.5 and `.swift-version` contains `5.5.3`.
- Xcode 26.6 with Swift 6.3.3 runs 59 tests successfully in Swift 5 language mode.
- `swift build --target OAuth2 -Xswiftc -strict-concurrency=complete -Xswiftc -swift-version -Xswiftc 5` succeeds with isolation warnings in the AuthenticationServices presentation provider and `URLSessionTaskDelegate` implementation.
- A Swift 6 language-mode build fails first in `SwiftKeychain`, where Core Foundation reference values cross `Sendable` dictionary boundaries.
- The `Semaphore` dependency exists only to serialize refresh-token rotation.
- The current `OAuth2Actor` is a custom global actor. It serializes unrelated OAuth clients together and does not match the main-actor requirements of platform UI protocols.
- Callback state remains in `OAuth2Base`, `OAuth2DataLoader`, `OAuth2DataRequest`, password-grant presentation, web-view controllers, and platform authorizers.
- `DataLoaderTests` is disabled in `Package.swift`.
- The GitHub Actions matrix already identifies Xcode 15.4 and Xcode 16.2, but unit tests use `continue-on-error` and complete checking is not a gate.

## Target Architecture

### Isolation boundaries

There is no library-wide global actor.

- `OAuth2Client` is a per-client actor. It is the only owner of mutable OAuth credentials and authorization state for one configured client.
- `OAuth2AuthorizationPresenter` is a `MainActor` protocol. Platform UI and AuthenticationServices objects never leave this boundary.
- `OAuth2Transport` is a `Sendable` async protocol. Its default implementation delegates to `URLSession` and is not actor-isolated.
- `OAuth2CredentialStore` is a `Sendable` async protocol. It persists client credentials and token sets without leaking Keychain or Core Foundation values across isolation boundaries.
- `OAuth2ResourceClient` is a `Sendable` value. It performs independent resource requests concurrently and consults `OAuth2Client` only for token snapshots and authorization recovery.
- Grant and provider behavior is represented by immutable `Sendable` strategies instead of subclasses.

`MainActor` is not a general OAuth executor. A background caller remains in its own isolation domain while loading credentials, refreshing tokens, and performing requests. It crosses to `MainActor` only after explicitly requesting interactive authorization.

### Sendable value model

Replace `[String: any Sendable]` with explicit public value types:

- `OAuth2ClientConfiguration` for immutable endpoints, scopes, redirect URI, client-authentication method, and provider behavior.
- `OAuth2ClientCredentials` for a dynamically registered or initially configured client identifier and secret.
- `OAuth2TokenSet` for access, refresh, and ID tokens, token type, scope, and expiry.
- `OAuth2TokenSnapshot` for a token set plus its monotonically increasing revision.
- `OAuth2TokenResponse`, `OAuth2ErrorResponse`, and `OAuth2DeviceAuthorization` for protocol responses.
- `JSONValue` for unknown provider fields.

Token and registration decoders preserve unknown fields in `[String: JSONValue]`. This keeps provider extensions available without making arbitrary reference types part of the concurrency contract.

Configuration is immutable after initialization. Dynamic client registration updates actor-owned `OAuth2ClientCredentials`, not the configuration object.

### OAuth2Client actor

The public API is centered on intent rather than callbacks:

```swift
public actor OAuth2Client {
	public nonisolated let configuration: OAuth2ClientConfiguration

	public func tokenSnapshot() async throws -> OAuth2TokenSnapshot?
	public func validAccessToken() async throws -> OAuth2TokenSnapshot
	public func authorize(
		using presenter: any OAuth2AuthorizationPresenter
	) async throws -> OAuth2TokenSnapshot
	public func recoverAfterUnauthorized(
		_ failedSnapshot: OAuth2TokenSnapshot
	) async throws -> OAuth2TokenSnapshot
	public func clearCredentials() async throws
	public func cancelAuthorization() async
}
```

`validAccessToken()` is always headless:

1. Return a sufficiently unexpired access token.
2. Otherwise coalesce on one refresh operation.
3. If refresh is unavailable or rejected, clear invalid token state as appropriate and throw `OAuth2Error.interactiveAuthorizationRequired`.
4. Never invoke a presenter.

`authorize(using:)` may cross to `MainActor`. The presenter returns the redirect URL or a typed cancellation error. Code exchange and persistence resume on the client actor.

### State revisions and commit checks

Every credential mutation increments a monotonic revision. Network operations capture both the revision and the credential material they use. When an awaited operation returns, the actor commits its result only if the captured operation identifier and revision are still current.

This prevents a late refresh, code exchange, device poll, or Keychain load from overwriting state that was cleared or replaced during the suspension.

No invariant is assumed to survive an `await`. In particular, response parsing may be pure and nonisolated, but committing parsed credentials is a synchronous actor operation with no suspension point.

### Single-flight operations

Refresh and interactive authorization each have an explicitly identified in-flight operation. Concurrent callers join the existing operation instead of receiving `alreadyAuthorizing` or starting duplicate work.

The shared operation is an unstructured `Task` owned by the actor. Waiters are registered separately with checked continuations so a cancelled waiter can stop waiting without cancelling work required by other callers. Cancellation removes only that waiter. If the last waiter leaves, the actor may cancel the operation and tear down interactive UI.

Completion and cancellation use the operation identifier before clearing state. A late waiter or late framework callback cannot clear a newer operation.

Refresh coalescing and refresh-token rotation are related but distinct:

- Identical refresh requests coalesce into one refresh flight.
- Heterogeneous operations that may rotate the subject refresh token, such as refresh-token exchange, run through one cancellation-aware token-mutation gate.
- Each gated operation reads the current refresh token only when it begins execution. It never captures a queued token value.
- A failed operation releases the gate and does not poison later operations.

This replaces the blocking semaphore without permitting two rotating operations to use the same refresh token.

### Generation-aware 401 recovery

`OAuth2ResourceClient` signs a request with an `OAuth2TokenSnapshot`. On a 401, it calls `recoverAfterUnauthorized(_:)` once.

The actor performs the following decision synchronously, without an `await` between the checks:

1. If the current revision is newer than the failed snapshot, return the current valid token. Another request already recovered authorization.
2. If the failed snapshot is still current, invalidate that access token and join or start one refresh flight.
3. If headless recovery is impossible, throw `interactiveAuthorizationRequired`.

The resource client then signs one recovery attempt with the returned snapshot. A second 401 is returned as an authorization failure. There is no recursive retry and no callback FIFO.

Interactive authorization is never triggered by a resource request. The caller decides whether and when to call `authorize(using:)`.

### MainActor presentation

```swift
@MainActor
public protocol OAuth2AuthorizationPresenter: AnyObject, Sendable {
	func authorize(
		_ request: OAuth2AuthorizationPresentationRequest
	) async throws -> URL
	func cancel()
}
```

Concrete presenters are final `MainActor` types. They own all `ASWebAuthenticationSession`, `UIViewController`, `NSWindow`, and presentation-context state.

System completion handlers with no async equivalent are private implementation details behind a checked continuation. Each bridge has a `MainActor`-isolated single-resume state box shared by natural completion and cancellation. Calling cancel and receiving a framework completion concurrently must resolve the continuation exactly once.

An external-browser presenter may expose an async-safe `resume(with:)` method for application or scene delegate forwarding. It does not expose a completion property.

### Token persistence

`SwiftKeychain` is removed. Keychain requests are constructed and consumed inside the persistence implementation so `CFString`, `CFBoolean`, and mutable dictionaries never cross an isolation boundary.

Because `SecItem` operations are synchronous, the default Keychain store uses a private serial execution context and resumes its async caller with `Sendable` value models. An audited `@unchecked Sendable` wrapper is acceptable only around this encapsulated queue-backed implementation. Marking the old mutable Keychain types unchecked is not acceptable.

`InMemoryCredentialStore` is an actor and supports deterministic tests.

### Transport and redirects

The default transport uses `URLSession.data(for:)`. Request and response DTOs are `Sendable` values.

If same-host redirect re-signing remains required, use a per-task delegate with immutable `Sendable` inputs and platform availability of at least macOS 12, iOS 15, tvOS 15, and watchOS 8. Do not restore a session-wide delegate coupled to mutable client state.

### Grant flows

The rewrite preserves these current behaviors as composable strategies:

- Authorization code with PKCE and client authentication variations.
- Client credentials, including the Reddit installed-client variation.
- Device authorization with RFC 8628 polling and slow-down behavior.
- Refresh and token exchange, including refresh-token rotation.
- Dynamic client registration.
- Current response-decoding variations such as missing token type or form-encoded responses.
- Password and implicit grants until a separate security/product decision removes them.

Provider-specific differences become configuration or `Sendable` strategy implementations rather than subclasses with mutable overrides.

Device authorization is structured as two observable operations:

```swift
let authorization = try await client.beginDeviceAuthorization()
let tokens = try await client.pollForDeviceAuthorization(authorization)
```

Polling runs in a cancellable task, uses iterative rather than recursive retry, adds five seconds after `slow_down`, respects expiry, and returns typed terminal errors.

## Migration Process

Each phase keeps the package buildable and adds tests before deleting the behavior it replaces.

### Phase 1: Lock the baseline and toolchain

1. Record the existing 59-test baseline and the disabled DataLoader suite.
2. Move the manifest and `.swift-version` to Swift 5.10 without changing language mode.
3. Make the Xcode 15.4 lane the exact Swift 5.10 reference lane.
4. Remove `continue-on-error` from test steps and preserve platform Xcode builds.
5. Add a newer-compiler lane so new diagnostics are visible during the migration.

### Phase 2: Remove concurrency-hostile dependencies

1. Replace `SwiftKeychain` with the new credential-store boundary and implementations.
2. Replace `Semaphore` with explicit single-flight state and the token-mutation gate.
3. Verify the legacy behavior tests still pass before changing the public API.

### Phase 3: Enable complete checking

1. Add `.enableExperimentalFeature("StrictConcurrency")` to every owned target.
2. Treat warnings as errors in CI.
3. Permit only narrow, documented interoperability annotations.
4. Keep a Swift 6 language-mode build as a non-optional compatibility gate once dependencies compile in that mode.

### Phase 4: Introduce the Sendable core

1. Build the new `OAuth2` product target from an isolated source directory so it can be checked in Swift 6 language mode without compiling legacy test-only dependencies.
2. Add typed configuration, credential, token, error, device, and `JSONValue` models.
3. Add async transport, credential-store, clock, randomness, and presentation protocols.
4. Test encoding, provider extension round trips, expiry skew, request construction, and injected failures.

### Phase 5: Implement the client actor

1. Implement revisioned actor state and persistence loading.
2. Implement headless token lookup and refresh single-flight.
3. Implement cancellation-aware waiter registration.
4. Implement the token-mutation gate for rotating operations.
5. Implement atomic generation-aware 401 recovery.
6. Add stress tests before connecting platform UI.

### Phase 6: Migrate flows by behavior

1. Authorization code and PKCE.
2. Refresh and resource-token exchange.
3. Client credentials and provider variations.
4. Device authorization and polling.
5. Dynamic registration.
6. Password and implicit grants while they remain in scope.

Each migrated flow receives request, response, error, cancellation, and concurrency tests. Subclass overrides are converted to strategies only after their behavior is captured.

### Phase 7: Replace resource loading

1. Add `OAuth2ResourceClient` with injected transport.
2. Implement one generation-aware recovery attempt.
3. Rewrite and re-enable the disabled DataLoader tests against the new API.
4. Delete `OAuth2DataLoader`, `OAuth2DataRequest`, and their callback queue after equivalent tests pass.

### Phase 8: Replace platform authorization UI

1. Add `MainActor` presenters for AuthenticationServices and supported fallback presentation.
2. Add the single-resume continuation guard.
3. Test success, provider error, user cancellation, explicit cancellation, and simultaneous cancel/completion.
4. Remove UI context from `Sendable` configuration and delete callback properties.

### Phase 9: Retire the legacy architecture

1. Delete `OAuth2Actor`, the open-class flow hierarchy, callback helpers, and continuation properties.
2. Remove the legacy test-only targets after their behavior coverage has been ported to the new product.
3. Collapse obsolete internal modules where they do not represent isolation or packaging boundaries.
4. Update README examples to show background work followed by an explicit `MainActor` UI update.
5. Update or remove stale CocoaPods and Xcode-project metadata deliberately; do not leave them claiming Swift 5.3 support.
6. Generate the public symbol graph and verify that no completion-handler API remains.

### Phase 10: Swift 6 cutover

1. Require clean Swift 5.10 builds and tests with complete checking and warnings as errors.
2. Require clean builds and tests under a Swift 6 compiler in Swift 6 language mode.
3. Move `Package.swift` to tools 6 and declare Swift 6 language mode.
4. Retain a version-specific Swift 5.10 manifest only if the project intentionally continues dual-toolchain support.

## Required Concurrency Tests

The test suite must use injected transports, stores, clocks, randomness, and presenters. It must not depend on timing races against real servers.

1. One hundred concurrent `validAccessToken()` callers on an expired token make exactly one refresh request.
2. A 401 storm from one token revision makes exactly one refresh request; every request uses the recovered revision once.
3. A late 401 for an old revision uses the current revision without invalidating it.
4. A recovered request that also receives 401 stops without recursion.
5. Cancelling one waiter does not cancel shared refresh or authorization needed by another waiter.
6. Cancelling the final waiter tears down the shared operation and interactive UI.
7. Explicit authorization cancellation and framework completion resolve exactly once.
8. Clearing credentials during an awaited refresh prevents the late response from restoring tokens.
9. Rotating token operations never use one refresh token concurrently.
10. An invalid refresh token clears wedged state and returns `interactiveAuthorizationRequired` from a headless call without invoking a presenter.
11. Device polling handles `authorization_pending`, `slow_down`, expiry, denial, transport errors, and task cancellation.
12. Unknown token and registration response fields survive decode/encode round trips.
13. UI presenter calls execute on `MainActor`; headless and transport calls do not require `MainActor`.
14. Two separately configured clients authorize and refresh independently.

Run the stress tests repeatedly and under Thread Sanitizer where the platform test runner supports it.

## Acceptance Gates

The Swift 5.10 rewrite is complete only when all of the following are true:

- `Package.swift` requires tools 5.10 and every owned target enables complete checking.
- The exact Swift 5.10 lane builds and tests with concurrency warnings treated as errors.
- A newer Swift compiler also builds and tests the package in Swift 5 language mode with complete checking.
- The public symbol graph contains no completion-handler API or callback property.
- `OAuth2Actor`, `Semaphore`, `SwiftKeychain`, `callOnMainThread`, callback request queues, and unsafe UI context storage are gone.
- Background-only token and resource APIs never invoke `MainActor` presentation.
- Interactive authorization crosses to a `MainActor` presenter and returns asynchronously.
- Concurrency, cancellation, rotation, device-flow, persistence, and 401-storm tests pass.
- README and package metadata describe the actual async API and supported toolchains.

Swift 6 migration is complete only after the tools-6 manifest and Swift 6 language mode pass the same build, test, and public-API gates.
