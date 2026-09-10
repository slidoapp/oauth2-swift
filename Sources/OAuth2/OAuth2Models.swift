import Foundation

/// A concurrency-safe JSON value used for provider-specific response fields.
public enum JSONValue: Sendable, Equatable, Codable {
	case string(String)
	case integer(Int)
	case number(Double)
	case boolean(Bool)
	case object([String: JSONValue])
	case array([JSONValue])
	case null

	public init(from decoder: any Decoder) throws {
		let container = try decoder.singleValueContainer()
		if container.decodeNil() {
			self = .null
		}
		else if let value = try? container.decode(Bool.self) {
			self = .boolean(value)
		}
		else if let value = try? container.decode(Int.self) {
			self = .integer(value)
		}
		else if let value = try? container.decode(Double.self) {
			self = .number(value)
		}
		else if let value = try? container.decode(String.self) {
			self = .string(value)
		}
		else if let value = try? container.decode([String: JSONValue].self) {
			self = .object(value)
		}
		else if let value = try? container.decode([JSONValue].self) {
			self = .array(value)
		}
		else {
			throw DecodingError.dataCorruptedError(in: container, debugDescription: "Unsupported JSON value")
		}
	}

	public func encode(to encoder: any Encoder) throws {
		var container = encoder.singleValueContainer()
		switch self {
		case .string(let value):
			try container.encode(value)
		case .integer(let value):
			try container.encode(value)
		case .number(let value):
			try container.encode(value)
		case .boolean(let value):
			try container.encode(value)
		case .object(let value):
			try container.encode(value)
		case .array(let value):
			try container.encode(value)
		case .null:
			try container.encodeNil()
		}
	}

	var stringValue: String? {
		guard case .string(let value) = self else { return nil }
		return value
	}

	var timeIntervalValue: TimeInterval? {
		switch self {
		case .integer(let value):
			return TimeInterval(value)
		case .number(let value):
			return value
		case .string(let value):
			return TimeInterval(value)
		default:
			return nil
		}
	}
}

/// How the client authenticates to the token endpoint.
public enum OAuth2ClientAuthentication: String, Sendable, Codable {
	case none
	case clientSecretBasic
	case clientSecretPost
}

public enum OAuth2TokenResponseFormat: Sendable, Equatable {
	case json
	case formURLEncoded
}

public enum OAuth2ImplicitResponseLocation: Sendable, Equatable {
	case fragment
	case query
}

/// Immutable configuration shared safely by all operations for one OAuth client.
public struct OAuth2ClientConfiguration: Sendable, Equatable {
	public let authorizationEndpoint: URL?
	public let deviceAuthorizationEndpoint: URL?
	public let registrationEndpoint: URL?
	public let tokenEndpoint: URL
	public let refreshEndpoint: URL?
	public let redirectURI: URL?
	public let scopes: [String]
	public let clientAuthentication: OAuth2ClientAuthentication
	public let tokenAuthorizationHeader: String?
	public let tokenResponseFormat: OAuth2TokenResponseFormat
	public let implicitResponseLocation: OAuth2ImplicitResponseLocation
	public let usesPKCE: Bool
	public let refreshLeeway: TimeInterval
	public let assumesUnexpiredTokensWithoutExpiry: Bool
	public let allowsMissingTokenType: Bool
	public let additionalAuthorizationParameters: [String: String]
	public let additionalTokenParameters: [String: String]

	public init(
		authorizationEndpoint: URL? = nil,
		deviceAuthorizationEndpoint: URL? = nil,
		registrationEndpoint: URL? = nil,
		tokenEndpoint: URL,
		refreshEndpoint: URL? = nil,
		redirectURI: URL? = nil,
		scopes: [String] = [],
		clientAuthentication: OAuth2ClientAuthentication = .none,
		tokenAuthorizationHeader: String? = nil,
		tokenResponseFormat: OAuth2TokenResponseFormat = .json,
		implicitResponseLocation: OAuth2ImplicitResponseLocation = .fragment,
		usesPKCE: Bool = true,
		refreshLeeway: TimeInterval = 30,
		assumesUnexpiredTokensWithoutExpiry: Bool = true,
		allowsMissingTokenType: Bool = false,
		additionalAuthorizationParameters: [String: String] = [:],
		additionalTokenParameters: [String: String] = [:]
	) {
		self.authorizationEndpoint = authorizationEndpoint
		self.deviceAuthorizationEndpoint = deviceAuthorizationEndpoint
		self.registrationEndpoint = registrationEndpoint
		self.tokenEndpoint = tokenEndpoint
		self.refreshEndpoint = refreshEndpoint
		self.redirectURI = redirectURI
		self.scopes = scopes
		self.clientAuthentication = clientAuthentication
		self.tokenAuthorizationHeader = tokenAuthorizationHeader
		self.tokenResponseFormat = tokenResponseFormat
		self.implicitResponseLocation = implicitResponseLocation
		self.usesPKCE = usesPKCE
		self.refreshLeeway = refreshLeeway
		self.assumesUnexpiredTokensWithoutExpiry = assumesUnexpiredTokensWithoutExpiry
		self.allowsMissingTokenType = allowsMissingTokenType
		self.additionalAuthorizationParameters = additionalAuthorizationParameters
		self.additionalTokenParameters = additionalTokenParameters
	}
}

/// Client credentials that may be replaced by dynamic registration.
public struct OAuth2ClientCredentials: Sendable, Equatable, Codable {
	public let clientID: String
	public let clientSecret: String?
	public let authenticationMethod: OAuth2ClientAuthentication?

	public init(
		clientID: String,
		clientSecret: String? = nil,
		authenticationMethod: OAuth2ClientAuthentication? = nil
	) {
		self.clientID = clientID
		self.clientSecret = clientSecret
		self.authenticationMethod = authenticationMethod
	}
}

/// RFC 7591 client metadata used for dynamic registration.
public struct OAuth2ClientRegistration: Sendable, Equatable {
	public let clientName: String?
	public let redirectURIs: [URL]
	public let grantTypes: [String]
	public let responseTypes: [String]
	public let additionalParameters: [String: JSONValue]

	public init(
		clientName: String? = nil,
		redirectURIs: [URL] = [],
		grantTypes: [String] = ["authorization_code", "refresh_token"],
		responseTypes: [String] = ["code"],
		additionalParameters: [String: JSONValue] = [:]
	) {
		self.clientName = clientName
		self.redirectURIs = redirectURIs
		self.grantTypes = grantTypes
		self.responseTypes = responseTypes
		self.additionalParameters = additionalParameters
	}
}

/// Dynamic-registration result with provider-specific fields preserved.
public struct OAuth2ClientRegistrationResponse: Sendable, Equatable {
	public let credentials: OAuth2ClientCredentials
	public let additionalParameters: [String: JSONValue]

	public init(credentials: OAuth2ClientCredentials, additionalParameters: [String: JSONValue]) {
		self.credentials = credentials
		self.additionalParameters = additionalParameters
	}
}

/// Tokens currently owned by an OAuth client.
public struct OAuth2TokenSet: Sendable, Equatable, Codable {
	public let accessToken: String
	public let refreshToken: String?
	public let idToken: String?
	public let tokenType: String?
	public let scopes: [String]
	public let expiresAt: Date?
	public let additionalParameters: [String: JSONValue]

	public init(
		accessToken: String,
		refreshToken: String? = nil,
		idToken: String? = nil,
		tokenType: String? = "Bearer",
		scopes: [String] = [],
		expiresAt: Date? = nil,
		additionalParameters: [String: JSONValue] = [:]
	) {
		self.accessToken = accessToken
		self.refreshToken = refreshToken
		self.idToken = idToken
		self.tokenType = tokenType
		self.scopes = scopes
		self.expiresAt = expiresAt
		self.additionalParameters = additionalParameters
	}

	func isUsable(
		at date: Date,
		leeway: TimeInterval,
		assumeUnexpiredWithoutExpiry: Bool
	) -> Bool {
		guard !accessToken.isEmpty else { return false }
		guard let expiresAt else { return assumeUnexpiredWithoutExpiry }
		return expiresAt.timeIntervalSince(date) > leeway
	}
}

/// A token value plus the process-local revision used to create a request.
public struct OAuth2TokenSnapshot: Sendable, Equatable {
	public let tokenSet: OAuth2TokenSet
	public let revision: UInt64

	public init(tokenSet: OAuth2TokenSet, revision: UInt64) {
		self.tokenSet = tokenSet
		self.revision = revision
	}
}

/// Value passed from the client actor to a main-actor authorization presenter.
public struct OAuth2AuthorizationPresentationRequest: Sendable, Equatable {
	public let authorizationURL: URL
	public let callbackURLScheme: String?

	public init(authorizationURL: URL, callbackURLScheme: String?) {
		self.authorizationURL = authorizationURL
		self.callbackURLScheme = callbackURLScheme
	}
}

/// RFC 8628 device-authorization data required to display instructions and poll for completion.
public struct OAuth2DeviceAuthorization: Sendable, Equatable {
	public let deviceCode: String
	public let userCode: String
	public let verificationURI: URL
	public let verificationURIComplete: URL?
	public let expiresAt: Date
	public let pollingInterval: TimeInterval
	public let additionalParameters: [String: JSONValue]

	public init(
		deviceCode: String,
		userCode: String,
		verificationURI: URL,
		verificationURIComplete: URL?,
		expiresAt: Date,
		pollingInterval: TimeInterval,
		additionalParameters: [String: JSONValue] = [:]
	) {
		self.deviceCode = deviceCode
		self.userCode = userCode
		self.verificationURI = verificationURI
		self.verificationURIComplete = verificationURIComplete
		self.expiresAt = expiresAt
		self.pollingInterval = pollingInterval
		self.additionalParameters = additionalParameters
	}
}

/// Persisted state for one configured OAuth client.
public struct OAuth2CredentialRecord: Sendable, Equatable, Codable {
	public let clientCredentials: OAuth2ClientCredentials?
	public let tokenSet: OAuth2TokenSet?

	public init(clientCredentials: OAuth2ClientCredentials?, tokenSet: OAuth2TokenSet?) {
		self.clientCredentials = clientCredentials
		self.tokenSet = tokenSet
	}
}

/// A decoded token-endpoint response with provider-specific fields preserved.
public struct OAuth2TokenResponse: Sendable, Equatable {
	public let accessToken: String
	public let refreshToken: String?
	public let idToken: String?
	public let tokenType: String?
	public let scope: String?
	public let expiresIn: TimeInterval?
	public let additionalParameters: [String: JSONValue]

	init(data: Data) throws {
		try self.init(values: JSONDecoder().decode([String: JSONValue].self, from: data))
	}

	init(values: [String: JSONValue]) throws {
		var values = values
		guard let accessToken = values.removeValue(forKey: "access_token")?.stringValue, !accessToken.isEmpty else {
			throw OAuth2ClientError.invalidTokenResponse("The response does not contain a non-empty access_token")
		}

		self.accessToken = accessToken
		refreshToken = values.removeValue(forKey: "refresh_token")?.stringValue
		idToken = values.removeValue(forKey: "id_token")?.stringValue
		tokenType = values.removeValue(forKey: "token_type")?.stringValue
		scope = values.removeValue(forKey: "scope")?.stringValue
		expiresIn = values.removeValue(forKey: "expires_in")?.timeIntervalValue
		additionalParameters = values
	}
}

/// Errors produced by the new actor-based client API.
public enum OAuth2ClientError: Error, Sendable, Equatable {
	case interactiveAuthorizationRequired
	case missingAuthorizationEndpoint
	case missingDeviceAuthorizationEndpoint
	case missingRegistrationEndpoint
	case missingClientIdentifier
	case missingClientSecret
	case missingRedirectURI
	case missingRefreshToken
	case deviceAuthorizationExpired
	case invalidAuthorizationResponse(String)
	case invalidTokenResponse(String)
	case nonHTTPResponse
	case authorizationServer(code: String?, description: String?, statusCode: Int)
	case unauthorized(statusCode: Int)
	case operationSuperseded
}

extension OAuth2ClientError: LocalizedError {
	public var errorDescription: String? {
		switch self {
		case .interactiveAuthorizationRequired:
			return "Interactive authorization is required"
		case .missingAuthorizationEndpoint:
			return "The authorization endpoint is missing"
		case .missingDeviceAuthorizationEndpoint:
			return "The device authorization endpoint is missing"
		case .missingRegistrationEndpoint:
			return "The dynamic client-registration endpoint is missing"
		case .missingClientIdentifier:
			return "The OAuth client identifier is missing"
		case .missingClientSecret:
			return "The OAuth client secret is missing"
		case .missingRedirectURI:
			return "The OAuth redirect URI is missing"
		case .missingRefreshToken:
			return "The refresh token is missing"
		case .deviceAuthorizationExpired:
			return "The device authorization has expired"
		case .invalidAuthorizationResponse(let reason):
			return "Invalid authorization response: \(reason)"
		case .invalidTokenResponse(let reason):
			return "Invalid token response: \(reason)"
		case .nonHTTPResponse:
			return "The server returned a non-HTTP response"
		case .authorizationServer(let code, let description, let statusCode):
			return description ?? code ?? "The authorization server returned HTTP \(statusCode)"
		case .unauthorized(let statusCode):
			return "The resource server rejected the recovered token with HTTP \(statusCode)"
		case .operationSuperseded:
			return "The OAuth operation was superseded by newer credential state"
		}
	}
}
