import Foundation
import Security

/// A Sendable HTTP response that does not expose Foundation header dictionaries containing `Any` values.
public struct OAuth2HTTPResponse: Sendable, Equatable {
	public let data: Data
	public let statusCode: Int
	public let headers: [String: String]
	public let url: URL?

	public init(data: Data, statusCode: Int, headers: [String: String] = [:], url: URL? = nil) {
		self.data = data
		self.statusCode = statusCode
		self.headers = headers
		self.url = url
	}
}

/// Performs HTTP requests without imposing an actor on networking.
public protocol OAuth2Transport: Sendable {
	func data(for request: URLRequest) async throws -> OAuth2HTTPResponse
}

/// Presents interactive authorization on the main actor and returns its redirect URL.
@MainActor
public protocol OAuth2AuthorizationPresenter: AnyObject, Sendable {
	func authorize(_ request: OAuth2AuthorizationPresentationRequest) async throws -> URL
	func cancel()
}

/// Default transport backed by Foundation async URLSession APIs.
public struct URLSessionOAuth2Transport: OAuth2Transport {
	private let session: URLSession

	public init(session: URLSession = .shared) {
		self.session = session
	}

	public func data(for request: URLRequest) async throws -> OAuth2HTTPResponse {
		let (data, response) = try await session.data(for: request)
		guard let response = response as? HTTPURLResponse else {
			throw OAuth2ClientError.nonHTTPResponse
		}

		var headers = [String: String]()
		for (key, value) in response.allHeaderFields {
			headers[String(describing: key)] = String(describing: value)
		}
		return OAuth2HTTPResponse(data: data, statusCode: response.statusCode, headers: headers, url: response.url)
	}
}

/// Persists credentials for one configured OAuth client.
///
/// Implementations must linearize calls so a later `clear()` cannot be overtaken by an earlier `save(_:)`.
public protocol OAuth2CredentialStore: Sendable {
	func load() async throws -> OAuth2CredentialRecord?
	func save(_ record: OAuth2CredentialRecord) async throws
	func clear() async throws
}

/// Deterministic actor-backed credential storage for tests and ephemeral clients.
public actor InMemoryOAuth2CredentialStore: OAuth2CredentialStore {
	private var record: OAuth2CredentialRecord?

	public init(record: OAuth2CredentialRecord? = nil) {
		self.record = record
	}

	public func load() -> OAuth2CredentialRecord? {
		record
	}

	public func save(_ record: OAuth2CredentialRecord) {
		self.record = record
	}

	public func clear() {
		record = nil
	}
}

/// Supplies time without coupling token-expiry tests to wall-clock delays.
public protocol OAuth2Clock: Sendable {
	func now() -> Date
}

public struct SystemOAuth2Clock: OAuth2Clock {
	public init() {}

	public func now() -> Date {
		Date()
	}
}

/// Supplies cancellable delays without using wall-clock sleeps in tests.
public protocol OAuth2Sleeper: Sendable {
	func sleep(for interval: TimeInterval) async throws
}

public struct SystemOAuth2Sleeper: OAuth2Sleeper {
	public init() {}

	public func sleep(for interval: TimeInterval) async throws {
		guard interval.isFinite else {
			throw OAuth2ClientError.invalidTokenResponse("The polling interval must be finite")
		}
		let maximumSeconds = TimeInterval(UInt64.max / 1_000_000_000)
		let nanoseconds = UInt64(min(max(0, interval), maximumSeconds) * 1_000_000_000)
		try await Task.sleep(nanoseconds: nanoseconds)
	}
}

/// Supplies cryptographically secure random bytes for state and PKCE values.
public protocol OAuth2Randomness: Sendable {
	func randomBytes(count: Int) throws -> Data
}

public struct SystemOAuth2Randomness: OAuth2Randomness {
	public init() {}

	public func randomBytes(count: Int) throws -> Data {
		var bytes = [UInt8](repeating: 0, count: count)
		guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess else {
			throw OAuth2ClientError.invalidAuthorizationResponse("Secure random generation failed")
		}
		return Data(bytes)
	}
}
