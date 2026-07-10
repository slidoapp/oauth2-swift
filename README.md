# OAuth2

OAuth2 is an async/await OAuth client for Apple platforms. Its mutable state is isolated per configured client, while networking remains safe to call from background tasks and user-interface presentation is isolated to `MainActor`.

## Requirements

- Swift 5.10 or newer
- Complete strict-concurrency checking
- macOS 12+, iOS 15+, tvOS 15+, or watchOS 8+

The package currently uses Swift 5 language mode so projects can migrate incrementally. The same public module is continuously compiled in Swift 6 language mode.

## Installation

Add the package with Swift Package Manager and import its single library product:

```swift
import OAuth2
```

## Create a client

Configuration is immutable and `Sendable`. Runtime credentials and tokens belong to one `OAuth2Client` actor.

```swift
let configuration = OAuth2ClientConfiguration(
	authorizationEndpoint: URL(string: "https://accounts.example.com/authorize")!,
	tokenEndpoint: URL(string: "https://accounts.example.com/token")!,
	redirectURI: URL(string: "myapp://oauth/callback")!,
	scopes: ["openid", "profile"],
	clientAuthentication: .none,
	usesPKCE: true
)

let credentialStore = OAuth2KeychainCredentialStore(
	configuration: OAuth2KeychainConfiguration(
		service: "com.example.myapp.oauth"
	)
)

let client = OAuth2Client(
	configuration: configuration,
	clientCredentials: OAuth2ClientCredentials(clientID: "my-client"),
	credentialStore: credentialStore
)
```

`OAuth2KeychainCredentialStore` executes synchronous Security framework calls on its own serial queue. For ephemeral clients and tests, use `InMemoryOAuth2CredentialStore`.

## Headless access from background work

`validAccessToken()` checks memory and persisted state, then coalesces concurrent refresh attempts. It never presents user interface.

```swift
do {
	let snapshot = try await client.validAccessToken()
	print(snapshot.tokenSet.accessToken)
}
catch OAuth2ClientError.interactiveAuthorizationRequired {
	// Schedule an explicit interactive authorization at an appropriate time.
}
```

If one hundred background tasks request an expired token concurrently, they await one refresh operation. Cancelling one waiter does not cancel work still required by other waiters.

## Interactive authorization

Interactive authorization takes an explicit `MainActor` presenter. Calling the client from a background task does not move token exchange, persistence, or later resource requests onto the main actor.

```swift
import AuthenticationServices

@MainActor
func makePresenter(window: ASPresentationAnchor) -> OAuth2AuthenticationSessionPresenter {
	OAuth2AuthenticationSessionPresenter(presentationAnchor: window)
}

let presenter = await makePresenter(window: window)
let snapshot = try await client.authorize(using: presenter)
```

`OAuth2AuthenticationSessionPresenter` owns its `ASWebAuthenticationSession` and presentation anchor on `MainActor`. Success, provider failure, user cancellation, and explicit cancellation resolve the async call exactly once.

To cancel the shared interactive operation:

```swift
await client.cancelAuthorization()
```

## Protected resource requests

`OAuth2ResourceClient` performs independent requests concurrently. A 401 invalidates only the token revision used by that request, coalesces headless recovery, and makes one recovery attempt. It never starts interactive authorization.

```swift
let resources = OAuth2ResourceClient(client: client)
let request = URLRequest(url: URL(string: "https://api.example.com/profile")!)
let response = try await resources.data(for: request)

let profile = try JSONDecoder().decode(Profile.self, from: response.data)
await MainActor.run {
	viewModel.profile = profile
}
```

A second 401 is returned as `OAuth2ClientError.unauthorized`; requests cannot enter an unbounded retry loop.

## Device authorization

Device authorization exposes both phases as structured, cancellable operations. It does not create a fire-and-forget polling task.

```swift
let authorization = try await client.beginDeviceAuthorization()

print(authorization.userCode)
print(authorization.verificationURI)

let snapshot = try await client.pollForDeviceAuthorization(authorization)
```

Polling implements `authorization_pending`, the RFC 8628 five-second `slow_down` increase, local expiry, server expiry, and task cancellation.

## Other grants and extensions

The actor also provides async methods for existing supported behavior:

```swift
let clientToken = try await client.authorizeWithClientCredentials()

let passwordToken = try await client.authorizeWithPassword(
	username: username,
	password: password
)

let implicitToken = try await client.authorizeImplicit(using: presenter)

let audienceRefreshToken = try await client.exchangeRefreshToken(
	forAudience: "audience-client-id"
)

let resourceToken = try await client.exchangeAccessToken(
	forResources: ["https://api.example.com"]
)
```

Client credentials, refreshes, code exchanges, device exchanges, and token exchanges share a cancellation-aware mutation gate. Providers that rotate refresh tokens therefore cannot receive the same subject token from concurrent operations.

Dynamic client registration stores returned credentials as actor-owned runtime state:

```swift
let registration = try await client.registerClient(
	OAuth2ClientRegistration(
		clientName: "My App",
		redirectURIs: [URL(string: "myapp://oauth/callback")!]
	)
)
```

Provider variations are configuration rather than subclasses:

- `additionalAuthorizationParameters` and `additionalTokenParameters`
- custom `tokenAuthorizationHeader`
- JSON or form-URL-encoded token responses
- optional missing `token_type`
- implicit responses in the fragment or query
- custom client-credentials grant types and parameters

Unknown response fields are retained as `JSONValue` values.

## Testing

The principal boundaries are injectable and `Sendable`:

- `OAuth2Transport`
- `OAuth2CredentialStore`
- `OAuth2Clock`
- `OAuth2Sleeper`
- `OAuth2Randomness`
- `OAuth2AuthorizationPresenter`

This makes refresh storms, cancellation, token rotation, device polling, and actor reentrancy deterministic in unit tests.

Run the package tests:

```shell
swift test
```

Compile the public module and its tests in Swift 6 language mode:

```shell
swift build --target OAuth2 \
	-Xswiftc -swift-version -Xswiftc 6 \
	-Xswiftc -warnings-as-errors

swift build --target OAuth2ConcurrencyTests \
	-Xswiftc -swift-version -Xswiftc 6 \
	-Xswiftc -warnings-as-errors
```

The detailed architecture, migration phases, and acceptance gates are in [Docs/ASYNC_AWAIT_MIGRATION.md](Docs/ASYNC_AWAIT_MIGRATION.md).

## License

OAuth2 is available under the Apache License 2.0. See [LICENSE.txt](LICENSE.txt).
