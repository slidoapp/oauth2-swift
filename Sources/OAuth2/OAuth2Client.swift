import Foundation
import CryptoKit

/// Actor-isolated OAuth state for one configured client.
public actor OAuth2Client {
	public nonisolated let configuration: OAuth2ClientConfiguration

	private let transport: any OAuth2Transport
	private let credentialStore: any OAuth2CredentialStore
	private let clock: any OAuth2Clock
	private let randomness: any OAuth2Randomness
	private let sleeper: any OAuth2Sleeper
	private let tokenMutationGate = OAuth2TokenMutationGate()

	private var credentialRecord: OAuth2CredentialRecord
	private var didLoadStoredCredentials = false
	private var isClearingCredentials = false
	private var revision: UInt64 = 0
	private var rejectedAccessTokenRevision: UInt64?
	private var refreshFlight: RefreshFlight?
	private var authorizationFlight: AuthorizationFlight?

	var pendingRefreshWaiterCount: Int {
		refreshFlight?.waiters.count ?? 0
	}

	var pendingAuthorizationWaiterCount: Int {
		authorizationFlight?.waiters.count ?? 0
	}

	private struct RefreshFlight {
		enum Phase {
			case network
			case committing
		}

		let id: UUID
		let baseRevision: UInt64
		let task: Task<Void, Never>
		var phase: Phase
		var waiters: [UUID: CheckedContinuation<OAuth2TokenSnapshot, any Error>]
	}

	private struct AuthorizationFlight {
		enum Phase {
			case presenting
			case committing
		}

		let id: UUID
		let baseRevision: UInt64
		let task: Task<Void, Never>
		let presenter: any OAuth2AuthorizationPresenter
		var phase: Phase
		var waiters: [UUID: CheckedContinuation<OAuth2TokenSnapshot, any Error>]
	}

	private struct AuthorizationContext: Sendable {
		let state: String
		let codeVerifier: String?
		let presentationRequest: OAuth2AuthorizationPresentationRequest
	}

	private enum AuthorizationMode: Sendable, Equatable {
		case authorizationCode
		case implicit
	}

	private struct RefreshInput: Sendable {
		let credentials: OAuth2ClientCredentials
		let currentTokens: OAuth2TokenSet
		let refreshToken: String
	}

	private struct TokenMutationInput: Sendable {
		let credentials: OAuth2ClientCredentials
		let tokens: OAuth2TokenSet
		let revision: UInt64
	}

	private struct PasswordGrantInput: Sendable {
		let credentials: OAuth2ClientCredentials?
		let revision: UInt64
	}

	public init(
		configuration: OAuth2ClientConfiguration,
		clientCredentials: OAuth2ClientCredentials? = nil,
		tokenSet: OAuth2TokenSet? = nil,
		transport: any OAuth2Transport = URLSessionOAuth2Transport(),
		credentialStore: any OAuth2CredentialStore = InMemoryOAuth2CredentialStore(),
		clock: any OAuth2Clock = SystemOAuth2Clock(),
		randomness: any OAuth2Randomness = SystemOAuth2Randomness(),
		sleeper: any OAuth2Sleeper = SystemOAuth2Sleeper()
	) {
		self.configuration = configuration
		self.transport = transport
		self.credentialStore = credentialStore
		self.clock = clock
		self.randomness = randomness
		self.sleeper = sleeper
		credentialRecord = OAuth2CredentialRecord(clientCredentials: clientCredentials, tokenSet: tokenSet)
	}

	/// Returns the current token without refreshing it.
	public func tokenSnapshot() async throws -> OAuth2TokenSnapshot? {
		try await loadStoredCredentialsIfNeeded()
		try ensureCredentialsAreNotClearing()
		return currentSnapshot()
	}

	/// Returns a valid access token from memory or a coalesced headless refresh.
	///
	/// This method never presents user interface. If refresh cannot recover authorization it throws
	/// `OAuth2ClientError.interactiveAuthorizationRequired`.
	public func validAccessToken() async throws -> OAuth2TokenSnapshot {
		try Task.checkCancellation()
		try await loadStoredCredentialsIfNeeded()
		try ensureCredentialsAreNotClearing()

		if let snapshot = currentSnapshot(), isUsable(snapshot), rejectedAccessTokenRevision != snapshot.revision {
			return snapshot
		}
		if authorizationFlight != nil {
			return try await waitForAuthorization(using: nil)
		}
		return try await waitForRefresh()
	}

	/// Obtains a token, crossing to a main-actor presenter only when headless recovery is unavailable.
	public func authorize(using presenter: any OAuth2AuthorizationPresenter) async throws -> OAuth2TokenSnapshot {
		do {
			return try await validAccessToken()
		}
		catch OAuth2ClientError.interactiveAuthorizationRequired {
			return try await waitForAuthorization(using: presenter, mode: .authorizationCode)
		}
	}

	/// Performs the legacy implicit grant while keeping presentation and callback handling async.
	public func authorizeImplicit(using presenter: any OAuth2AuthorizationPresenter) async throws -> OAuth2TokenSnapshot {
		do {
			return try await validAccessToken()
		}
		catch OAuth2ClientError.interactiveAuthorizationRequired {
			return try await waitForAuthorization(using: presenter, mode: .implicit)
		}
	}

	/// Obtains a token with the client-credentials grant and coalesces concurrent callers.
	public func authorizeWithClientCredentials(
		grantType: String = "client_credentials",
		additionalParameters: [String: String] = [:]
	) async throws -> OAuth2TokenSnapshot {
		try Task.checkCancellation()
		try await loadStoredCredentialsIfNeeded()
		try ensureCredentialsAreNotClearing()
		if let snapshot = currentSnapshot(), isUsable(snapshot), rejectedAccessTokenRevision != snapshot.revision {
			return snapshot
		}
		return try await waitForClientCredentials(
			grantType: grantType,
			additionalParameters: additionalParameters
		)
	}

	/// Obtains a token with the resource-owner password grant.
	///
	/// Credential collection belongs to application UI; this background-safe method only performs the protocol exchange.
	public func authorizeWithPassword(
		username: String,
		password: String,
		additionalParameters: [String: String] = [:]
	) async throws -> OAuth2TokenSnapshot {
		try await loadStoredCredentialsIfNeeded()
		try ensureCredentialsAreNotClearing()
		let configuration = configuration
		let transport = transport
		let clock = clock
		return try await tokenMutationGate.withPermit {
			let input = await self.passwordGrantInput()
			let tokens = try await OAuth2TokenEndpoint.password(
				username: username,
				password: password,
				additionalParameters: additionalParameters,
				configuration: configuration,
				credentials: input.credentials,
				transport: transport,
				clock: clock
			)
			return try await self.commitTokenMutation(tokens, baseRevision: input.revision)
		}
	}

	/// Dynamically registers client credentials and persists them as actor-owned runtime state.
	public func registerClient(
		_ registration: OAuth2ClientRegistration
	) async throws -> OAuth2ClientRegistrationResponse {
		try await loadStoredCredentialsIfNeeded()
		try ensureCredentialsAreNotClearing()
		let configuration = configuration
		let transport = transport
		return try await tokenMutationGate.withPermit {
			let baseRevision = try await self.registrationBaseRevision()
			let response = try await OAuth2DynamicRegistrationEndpoint.register(
				registration,
				configuration: configuration,
				transport: transport
			)
			try await self.commitClientCredentials(response.credentials, baseRevision: baseRevision)
			return response
		}
	}

	/// Exchanges the subject refresh token for a token issued to another audience.
	///
	/// If the server rotates the subject refresh token, the rotated token is persisted before this method returns.
	public func exchangeRefreshToken(
		forAudience audienceClientID: String,
		additionalParameters: [String: String] = [:]
	) async throws -> String {
		try await loadStoredCredentialsIfNeeded()
		try ensureCredentialsAreNotClearing()
		let configuration = configuration
		let transport = transport
		return try await tokenMutationGate.withPermit {
			let input = try await self.tokenMutationInput()
			guard let subjectRefreshToken = input.tokens.refreshToken, !subjectRefreshToken.isEmpty else {
				throw OAuth2ClientError.missingRefreshToken
			}
			let response = try await OAuth2TokenEndpoint.exchangeRefreshToken(
				subjectRefreshToken,
				audienceClientID: audienceClientID,
				additionalParameters: additionalParameters,
				configuration: configuration,
				credentials: input.credentials,
				transport: transport
			)
			let updatedTokens = OAuth2TokenSet(
				accessToken: input.tokens.accessToken,
				refreshToken: response.refreshToken ?? input.tokens.refreshToken,
				idToken: input.tokens.idToken,
				tokenType: input.tokens.tokenType,
				scopes: input.tokens.scopes,
				expiresAt: input.tokens.expiresAt,
				additionalParameters: input.tokens.additionalParameters
			)
			_ = try await self.commitTokenMutation(updatedTokens, baseRevision: input.revision)
			return response.accessToken
		}
	}

	/// Exchanges the current access token for a resource-specific access token and makes it current.
	public func exchangeAccessToken(
		forResources resources: [String],
		additionalParameters: [String: String] = [:]
	) async throws -> OAuth2TokenSnapshot {
		try await loadStoredCredentialsIfNeeded()
		try ensureCredentialsAreNotClearing()
		guard !resources.isEmpty else {
			throw OAuth2ClientError.invalidTokenResponse("At least one resource is required for token exchange")
		}
		let configuration = configuration
		let transport = transport
		let clock = clock
		return try await tokenMutationGate.withPermit {
			let input = try await self.tokenMutationInput()
			let response = try await OAuth2TokenEndpoint.exchangeAccessToken(
				input.tokens.accessToken,
				resources: resources,
				additionalParameters: additionalParameters,
				configuration: configuration,
				credentials: input.credentials,
				transport: transport
			)
			let updatedTokens = OAuth2TokenSet(
				accessToken: response.accessToken,
				refreshToken: response.refreshToken ?? input.tokens.refreshToken,
				idToken: response.idToken ?? input.tokens.idToken,
				tokenType: response.tokenType,
				scopes: response.scope?.split(separator: " ").map(String.init) ?? input.tokens.scopes,
				expiresAt: response.expiresIn.map { clock.now().addingTimeInterval($0) },
				additionalParameters: response.additionalParameters
			)
			return try await self.commitTokenMutation(updatedTokens, baseRevision: input.revision)
		}
	}

	/// Starts RFC 8628 device authorization without creating an unstructured polling task.
	public func beginDeviceAuthorization(
		additionalParameters: [String: String] = [:]
	) async throws -> OAuth2DeviceAuthorization {
		try Task.checkCancellation()
		try await loadStoredCredentialsIfNeeded()
		try ensureCredentialsAreNotClearing()
		guard let credentials = credentialRecord.clientCredentials else {
			throw OAuth2ClientError.missingClientIdentifier
		}
		return try await OAuth2TokenEndpoint.beginDeviceAuthorization(
			configuration: configuration,
			credentials: credentials,
			additionalParameters: additionalParameters,
			transport: transport,
			clock: clock
		)
	}

	/// Polls an RFC 8628 authorization until it succeeds, fails, expires, or this task is cancelled.
	public func pollForDeviceAuthorization(
		_ authorization: OAuth2DeviceAuthorization
	) async throws -> OAuth2TokenSnapshot {
		try Task.checkCancellation()
		try await loadStoredCredentialsIfNeeded()
		try ensureCredentialsAreNotClearing()
		guard let credentials = credentialRecord.clientCredentials else {
			throw OAuth2ClientError.missingClientIdentifier
		}

		let baseRevision = revision
		guard authorization.pollingInterval.isFinite, authorization.pollingInterval > 0 else {
			throw OAuth2ClientError.invalidTokenResponse("The device polling interval must be finite and greater than zero")
		}
		var interval = authorization.pollingInterval
		let tokenMutationGate = tokenMutationGate
		let configuration = configuration
		let transport = transport
		let clock = clock
		while clock.now() < authorization.expiresAt {
			try Task.checkCancellation()
			guard revision == baseRevision else {
				throw OAuth2ClientError.operationSuperseded
			}
			try await sleeper.sleep(for: interval)
			try Task.checkCancellation()
			guard revision == baseRevision else {
				throw OAuth2ClientError.operationSuperseded
			}

			do {
				return try await tokenMutationGate.withPermit {
					let tokens = try await OAuth2TokenEndpoint.exchangeDeviceCode(
						authorization.deviceCode,
						configuration: configuration,
						credentials: credentials,
						transport: transport,
						clock: clock
					)
					return try await self.commitDeviceTokens(tokens, baseRevision: baseRevision)
				}
			}
			catch OAuth2ClientError.authorizationServer(let code, _, _) where code == "authorization_pending" {
				continue
			}
			catch OAuth2ClientError.authorizationServer(let code, _, _) where code == "slow_down" {
				interval += 5
				continue
			}
			catch OAuth2ClientError.authorizationServer(let code, _, _) where code == "expired_token" {
				throw OAuth2ClientError.deviceAuthorizationExpired
			}
		}
		throw OAuth2ClientError.deviceAuthorizationExpired
	}

	/// Recovers after a resource server rejects a particular token revision.
	///
	/// The revision comparison and refresh-flight selection happen in one actor turn, before this method suspends.
	public func recoverAfterUnauthorized(_ failedSnapshot: OAuth2TokenSnapshot) async throws -> OAuth2TokenSnapshot {
		try Task.checkCancellation()
		try await loadStoredCredentialsIfNeeded()
		try ensureCredentialsAreNotClearing()

		if revision != failedSnapshot.revision {
			if let snapshot = currentSnapshot(), isUsable(snapshot), rejectedAccessTokenRevision != snapshot.revision {
				return snapshot
			}
			return try await waitForRefresh()
		}
		if authorizationFlight != nil {
			return try await waitForAuthorization(using: nil)
		}

		guard credentialRecord.tokenSet?.accessToken == failedSnapshot.tokenSet.accessToken else {
			if let snapshot = currentSnapshot(), isUsable(snapshot) {
				return snapshot
			}
			throw OAuth2ClientError.operationSuperseded
		}

		rejectedAccessTokenRevision = revision
		return try await waitForRefresh()
	}

	/// Clears in-memory and persisted client credentials and tokens.
	public func clearCredentials() async throws {
		try await loadStoredCredentialsIfNeeded()
		guard !isClearingCredentials else {
			throw OAuth2ClientError.operationSuperseded
		}
		isClearingCredentials = true
		cancelRefreshFlight()
		let presenter = takeAuthorizationFlightForCancellation()
		credentialRecord = OAuth2CredentialRecord(clientCredentials: nil, tokenSet: nil)
		revision &+= 1
		rejectedAccessTokenRevision = nil
		do {
			try await credentialStore.clear()
			isClearingCredentials = false
		}
		catch {
			isClearingCredentials = false
			if let presenter {
				await presenter.cancel()
			}
			throw error
		}
		if let presenter {
			await presenter.cancel()
		}
	}

	/// Cancels the shared interactive authorization and all of its current waiters.
	public func cancelAuthorization() async {
		guard authorizationFlight?.phase == .presenting else { return }
		guard let presenter = takeAuthorizationFlightForCancellation() else { return }
		await presenter.cancel()
	}

	private func takeAuthorizationFlightForCancellation() -> (any OAuth2AuthorizationPresenter)? {
		guard let flight = authorizationFlight else { return nil }
		flight.task.cancel()
		authorizationFlight = nil
		for waiter in flight.waiters.values {
			waiter.resume(throwing: CancellationError())
		}
		return flight.presenter
	}

	private func loadStoredCredentialsIfNeeded() async throws {
		guard !didLoadStoredCredentials else { return }
		let stored = try await credentialStore.load()
		guard !didLoadStoredCredentials else { return }
		if let stored {
			credentialRecord = stored
			revision &+= 1
		}
		didLoadStoredCredentials = true
	}

	private func ensureCredentialsAreNotClearing() throws {
		if isClearingCredentials {
			throw OAuth2ClientError.operationSuperseded
		}
	}

	private func commitDeviceTokens(
		_ tokens: OAuth2TokenSet,
		baseRevision: UInt64
	) async throws -> OAuth2TokenSnapshot {
		guard revision == baseRevision else {
			throw OAuth2ClientError.operationSuperseded
		}
		let updatedRecord = OAuth2CredentialRecord(
			clientCredentials: credentialRecord.clientCredentials,
			tokenSet: tokens
		)
		try await credentialStore.save(updatedRecord)
		guard revision == baseRevision else {
			throw OAuth2ClientError.operationSuperseded
		}
		credentialRecord = updatedRecord
		revision &+= 1
		rejectedAccessTokenRevision = nil
		return OAuth2TokenSnapshot(tokenSet: tokens, revision: revision)
	}

	private func tokenMutationInput() throws -> TokenMutationInput {
		guard let credentials = credentialRecord.clientCredentials else {
			throw OAuth2ClientError.missingClientIdentifier
		}
		guard let tokens = credentialRecord.tokenSet else {
			throw OAuth2ClientError.interactiveAuthorizationRequired
		}
		return TokenMutationInput(credentials: credentials, tokens: tokens, revision: revision)
	}

	private func passwordGrantInput() -> PasswordGrantInput {
		PasswordGrantInput(credentials: credentialRecord.clientCredentials, revision: revision)
	}

	private func registrationBaseRevision() throws -> UInt64 {
		try ensureCredentialsAreNotClearing()
		return revision
	}

	private func commitTokenMutation(
		_ tokens: OAuth2TokenSet,
		baseRevision: UInt64
	) async throws -> OAuth2TokenSnapshot {
		guard revision == baseRevision else {
			throw OAuth2ClientError.operationSuperseded
		}
		let updatedRecord = OAuth2CredentialRecord(
			clientCredentials: credentialRecord.clientCredentials,
			tokenSet: tokens
		)
		try await credentialStore.save(updatedRecord)
		guard revision == baseRevision else {
			throw OAuth2ClientError.operationSuperseded
		}
		credentialRecord = updatedRecord
		revision &+= 1
		rejectedAccessTokenRevision = nil
		return OAuth2TokenSnapshot(tokenSet: tokens, revision: revision)
	}

	private func commitClientCredentials(
		_ credentials: OAuth2ClientCredentials,
		baseRevision: UInt64
	) async throws {
		guard revision == baseRevision else {
			throw OAuth2ClientError.operationSuperseded
		}
		let updatedRecord = OAuth2CredentialRecord(
			clientCredentials: credentials,
			tokenSet: credentialRecord.tokenSet
		)
		try await credentialStore.save(updatedRecord)
		guard revision == baseRevision else {
			throw OAuth2ClientError.operationSuperseded
		}
		credentialRecord = updatedRecord
		revision &+= 1
	}

	private func currentSnapshot() -> OAuth2TokenSnapshot? {
		credentialRecord.tokenSet.map { OAuth2TokenSnapshot(tokenSet: $0, revision: revision) }
	}

	private func isUsable(_ snapshot: OAuth2TokenSnapshot) -> Bool {
		snapshot.tokenSet.isUsable(
			at: clock.now(),
			leeway: configuration.refreshLeeway,
			assumeUnexpiredWithoutExpiry: configuration.assumesUnexpiredTokensWithoutExpiry
		)
	}

	private func waitForAuthorization(
		using presenter: (any OAuth2AuthorizationPresenter)?,
		mode: AuthorizationMode = .authorizationCode
	) async throws -> OAuth2TokenSnapshot {
		let waiterID = UUID()
		return try await withTaskCancellationHandler {
			try await withCheckedThrowingContinuation { continuation in
				if Task.isCancelled {
					continuation.resume(throwing: CancellationError())
					return
				}
				registerAuthorizationWaiter(
					waiterID,
					presenter: presenter,
					mode: mode,
					continuation: continuation
				)
			}
		} onCancel: {
			Task {
				await self.cancelAuthorizationWaiter(waiterID)
			}
		}
	}

	private func registerAuthorizationWaiter(
		_ waiterID: UUID,
		presenter: (any OAuth2AuthorizationPresenter)?,
		mode: AuthorizationMode,
		continuation: CheckedContinuation<OAuth2TokenSnapshot, any Error>
	) {
		if var flight = authorizationFlight {
			flight.waiters[waiterID] = continuation
			authorizationFlight = flight
			return
		}

		guard let presenter else {
			continuation.resume(throwing: OAuth2ClientError.interactiveAuthorizationRequired)
			return
		}
		guard refreshFlight == nil else {
			continuation.resume(throwing: OAuth2ClientError.operationSuperseded)
			return
		}
		guard let credentials = credentialRecord.clientCredentials else {
			continuation.resume(throwing: OAuth2ClientError.missingClientIdentifier)
			return
		}

		let context: AuthorizationContext
		do {
			context = try makeAuthorizationContext(credentials: credentials, mode: mode)
		}
		catch {
			continuation.resume(throwing: error)
			return
		}

		let operationID = UUID()
		let baseRevision = revision
		let configuration = configuration
		let transport = transport
		let clock = clock
		let tokenMutationGate = tokenMutationGate
		let task = Task { [weak self] in
			guard let self else { return }
			do {
				let redirect = try await presenter.authorize(context.presentationRequest)
				try await tokenMutationGate.withPermit {
					do {
						let tokens: OAuth2TokenSet
						switch mode {
						case .authorizationCode:
							let code = try Self.authorizationCode(
								from: redirect,
								configuration: configuration,
								expectedState: context.state
							)
							tokens = try await OAuth2TokenEndpoint.exchangeAuthorizationCode(
								code,
								codeVerifier: context.codeVerifier,
								configuration: configuration,
								credentials: credentials,
								transport: transport,
								clock: clock
							)
						case .implicit:
							tokens = try Self.implicitTokens(
								from: redirect,
								configuration: configuration,
								expectedState: context.state,
								clock: clock
							)
						}
						try Task.checkCancellation()
						try await self.finishAuthorization(
							operationID: operationID,
							baseRevision: baseRevision,
							tokens: tokens
						)
					}
					catch {
						await self.failAuthorization(operationID: operationID, baseRevision: baseRevision, error: error)
					}
				}
			}
			catch {
				await self.failAuthorization(operationID: operationID, baseRevision: baseRevision, error: error)
			}
		}

		authorizationFlight = AuthorizationFlight(
			id: operationID,
			baseRevision: baseRevision,
			task: task,
			presenter: presenter,
			phase: .presenting,
			waiters: [waiterID: continuation]
		)
	}

	private func makeAuthorizationContext(
		credentials: OAuth2ClientCredentials,
		mode: AuthorizationMode
	) throws -> AuthorizationContext {
		guard let authorizationEndpoint = configuration.authorizationEndpoint else {
			throw OAuth2ClientError.missingAuthorizationEndpoint
		}
		guard let redirectURI = configuration.redirectURI else {
			throw OAuth2ClientError.missingRedirectURI
		}

		let state = Self.base64URLEncoded(try randomness.randomBytes(count: 16))
		let codeVerifier: String?
		let codeChallenge: String?
		if configuration.usesPKCE, mode == .authorizationCode {
			let verifier = Self.base64URLEncoded(try randomness.randomBytes(count: 32))
			codeVerifier = verifier
			codeChallenge = Self.base64URLEncoded(Data(SHA256.hash(data: Data(verifier.utf8))))
		}
		else {
			codeVerifier = nil
			codeChallenge = nil
		}

		guard var components = URLComponents(url: authorizationEndpoint, resolvingAgainstBaseURL: false) else {
			throw OAuth2ClientError.invalidAuthorizationResponse("Unable to parse the authorization URL")
		}
		var parameters = configuration.additionalAuthorizationParameters
		parameters["client_id"] = credentials.clientID
		parameters["redirect_uri"] = redirectURI.absoluteString
		parameters["response_type"] = mode == .authorizationCode ? "code" : "token"
		parameters["state"] = state
		if !configuration.scopes.isEmpty {
			parameters["scope"] = configuration.scopes.joined(separator: " ")
		}
		if let codeChallenge {
			parameters["code_challenge"] = codeChallenge
			parameters["code_challenge_method"] = "S256"
		}
		let newItems = parameters.keys.sorted().compactMap { key in
			parameters[key].map { URLQueryItem(name: key, value: $0) }
		}
		let existingItems = (components.queryItems ?? []).filter { parameters[$0.name] == nil }
		components.queryItems = existingItems + newItems
		guard let authorizationURL = components.url else {
			throw OAuth2ClientError.invalidAuthorizationResponse("Unable to construct the authorization URL")
		}

		return AuthorizationContext(
			state: state,
			codeVerifier: codeVerifier,
			presentationRequest: OAuth2AuthorizationPresentationRequest(
				authorizationURL: authorizationURL,
				callbackURLScheme: redirectURI.scheme
			)
		)
	}

	private func finishAuthorization(
		operationID: UUID,
		baseRevision: UInt64,
		tokens: OAuth2TokenSet
	) async throws {
		guard var flight = authorizationFlight, flight.id == operationID else {
			return
		}
		guard revision == baseRevision else {
			throw OAuth2ClientError.operationSuperseded
		}

		let updatedRecord = OAuth2CredentialRecord(
			clientCredentials: credentialRecord.clientCredentials,
			tokenSet: tokens
		)
		flight.phase = .committing
		authorizationFlight = flight
		try await credentialStore.save(updatedRecord)

		guard authorizationFlight?.id == operationID else { return }
		guard revision == baseRevision else {
			throw OAuth2ClientError.operationSuperseded
		}
		credentialRecord = updatedRecord
		revision &+= 1
		rejectedAccessTokenRevision = nil
		resumeAuthorizationWaiters(with: .success(OAuth2TokenSnapshot(tokenSet: tokens, revision: revision)))
	}

	private func failAuthorization(operationID: UUID, baseRevision: UInt64, error: any Error) {
		guard authorizationFlight?.id == operationID else { return }
		if revision != baseRevision {
			if let snapshot = currentSnapshot(), isUsable(snapshot), rejectedAccessTokenRevision != snapshot.revision {
				resumeAuthorizationWaiters(with: .success(snapshot))
			}
			else {
				resumeAuthorizationWaiters(with: .failure(OAuth2ClientError.operationSuperseded))
			}
			return
		}
		resumeAuthorizationWaiters(with: .failure(error))
	}

	private func cancelAuthorizationWaiter(_ waiterID: UUID) async {
		guard var flight = authorizationFlight, let waiter = flight.waiters.removeValue(forKey: waiterID) else {
			return
		}
		waiter.resume(throwing: CancellationError())

		if flight.waiters.isEmpty, flight.phase == .presenting {
			flight.task.cancel()
			authorizationFlight = nil
			await flight.presenter.cancel()
		}
		else {
			authorizationFlight = flight
		}
	}

	private func resumeAuthorizationWaiters(with result: Result<OAuth2TokenSnapshot, any Error>) {
		guard let flight = authorizationFlight else { return }
		authorizationFlight = nil
		for waiter in flight.waiters.values {
			waiter.resume(with: result)
		}
	}

	private nonisolated static func authorizationCode(
		from redirect: URL,
		configuration: OAuth2ClientConfiguration,
		expectedState: String
	) throws -> String {
		guard let expectedRedirect = configuration.redirectURI else {
			throw OAuth2ClientError.missingRedirectURI
		}
		guard redirectMatches(redirect, expected: expectedRedirect) else {
			throw OAuth2ClientError.invalidAuthorizationResponse("The redirect URI does not match the configured redirect")
		}

		let items = URLComponents(url: redirect, resolvingAgainstBaseURL: false)?.queryItems ?? []
		let values = Dictionary(items.map { ($0.name, $0.value ?? "") }, uniquingKeysWith: { _, last in last })
		if let error = values["error"] {
			throw OAuth2ClientError.authorizationServer(
				code: error,
				description: values["error_description"],
				statusCode: 0
			)
		}
		guard values["state"] == expectedState else {
			throw OAuth2ClientError.invalidAuthorizationResponse("The state parameter does not match")
		}
		guard let code = values["code"], !code.isEmpty else {
			throw OAuth2ClientError.invalidAuthorizationResponse("The redirect does not contain an authorization code")
		}
		return code
	}

	private nonisolated static func implicitTokens(
		from redirect: URL,
		configuration: OAuth2ClientConfiguration,
		expectedState: String,
		clock: any OAuth2Clock
	) throws -> OAuth2TokenSet {
		guard let expectedRedirect = configuration.redirectURI else {
			throw OAuth2ClientError.missingRedirectURI
		}
		guard redirectMatches(redirect, expected: expectedRedirect) else {
			throw OAuth2ClientError.invalidAuthorizationResponse("The redirect URI does not match the configured redirect")
		}

		let components = URLComponents(url: redirect, resolvingAgainstBaseURL: false)
		let encoded: String?
		switch configuration.implicitResponseLocation {
		case .fragment:
			encoded = components?.percentEncodedFragment
		case .query:
			encoded = components?.percentEncodedQuery
		}
		guard let encoded, !encoded.isEmpty else {
			throw OAuth2ClientError.invalidAuthorizationResponse("The redirect does not contain implicit-grant parameters")
		}

		var values = formStringValues(encoded)
		if let error = values["error"] {
			throw OAuth2ClientError.authorizationServer(
				code: error,
				description: values["error_description"],
				statusCode: 0
			)
		}
		guard values.removeValue(forKey: "state") == expectedState else {
			throw OAuth2ClientError.invalidAuthorizationResponse("The state parameter does not match")
		}
		guard let accessToken = values.removeValue(forKey: "access_token"), !accessToken.isEmpty else {
			throw OAuth2ClientError.invalidTokenResponse("The response does not contain a non-empty access_token")
		}
		let tokenType = values.removeValue(forKey: "token_type")
		if let tokenType, tokenType.caseInsensitiveCompare("bearer") != .orderedSame {
			throw OAuth2ClientError.invalidTokenResponse("Unsupported token_type \(tokenType)")
		}
		if tokenType == nil, !configuration.allowsMissingTokenType {
			throw OAuth2ClientError.invalidTokenResponse("The response does not contain token_type")
		}
		let refreshToken = values.removeValue(forKey: "refresh_token")
		let idToken = values.removeValue(forKey: "id_token")
		let scope = values.removeValue(forKey: "scope")
		let expiresIn = values.removeValue(forKey: "expires_in").flatMap(TimeInterval.init)
		return OAuth2TokenSet(
			accessToken: accessToken,
			refreshToken: refreshToken,
			idToken: idToken,
			tokenType: tokenType,
			scopes: scope?.split(separator: " ").map(String.init) ?? configuration.scopes,
			expiresAt: expiresIn.map { clock.now().addingTimeInterval($0) },
			additionalParameters: values.mapValues(JSONValue.string)
		)
	}

	private nonisolated static func redirectMatches(_ redirect: URL, expected: URL) -> Bool {
		redirect.scheme?.lowercased() == expected.scheme?.lowercased()
			&& (redirect.host ?? "").lowercased() == (expected.host ?? "").lowercased()
			&& redirect.port == expected.port
			&& redirect.path == expected.path
	}

	private nonisolated static func formStringValues(_ value: String) -> [String: String] {
		var result = [String: String]()
		for pair in value.split(separator: "&", omittingEmptySubsequences: false) {
			let components = pair.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
			guard let rawKey = components.first else { continue }
			let rawValue = components.count > 1 ? String(components[1]) : ""
			let key = String(rawKey).replacingOccurrences(of: "+", with: " ").removingPercentEncoding ?? String(rawKey)
			let decoded = rawValue.replacingOccurrences(of: "+", with: " ").removingPercentEncoding ?? rawValue
			result[key] = decoded
		}
		return result
	}

	private nonisolated static func base64URLEncoded(_ data: Data) -> String {
		data.base64EncodedString()
			.replacingOccurrences(of: "+", with: "-")
			.replacingOccurrences(of: "/", with: "_")
			.replacingOccurrences(of: "=", with: "")
	}

	private func waitForRefresh() async throws -> OAuth2TokenSnapshot {
		let waiterID = UUID()
		return try await withTaskCancellationHandler {
			try await withCheckedThrowingContinuation { continuation in
				if Task.isCancelled {
					continuation.resume(throwing: CancellationError())
					return
				}
				registerRefreshWaiter(waiterID, continuation: continuation)
			}
		} onCancel: {
			Task {
				await self.cancelRefreshWaiter(waiterID)
			}
		}
	}

	private func waitForClientCredentials(
		grantType: String,
		additionalParameters: [String: String]
	) async throws -> OAuth2TokenSnapshot {
		let waiterID = UUID()
		return try await withTaskCancellationHandler {
			try await withCheckedThrowingContinuation { continuation in
				if Task.isCancelled {
					continuation.resume(throwing: CancellationError())
					return
				}
				registerClientCredentialsWaiter(
					waiterID,
					grantType: grantType,
					additionalParameters: additionalParameters,
					continuation: continuation
				)
			}
		} onCancel: {
			Task {
				await self.cancelRefreshWaiter(waiterID)
			}
		}
	}

	private func registerClientCredentialsWaiter(
		_ waiterID: UUID,
		grantType: String,
		additionalParameters: [String: String],
		continuation: CheckedContinuation<OAuth2TokenSnapshot, any Error>
	) {
		if var flight = refreshFlight {
			flight.waiters[waiterID] = continuation
			refreshFlight = flight
			return
		}
		guard authorizationFlight == nil else {
			continuation.resume(throwing: OAuth2ClientError.operationSuperseded)
			return
		}
		guard let credentials = credentialRecord.clientCredentials else {
			continuation.resume(throwing: OAuth2ClientError.missingClientIdentifier)
			return
		}

		let operationID = UUID()
		let baseRevision = revision
		let configuration = configuration
		let transport = transport
		let clock = clock
		let tokenMutationGate = tokenMutationGate
		let task = Task { [weak self] in
			guard let self else { return }
			do {
				try await tokenMutationGate.withPermit {
					do {
						let tokens = try await OAuth2TokenEndpoint.clientCredentials(
							grantType: grantType,
							additionalParameters: additionalParameters,
							configuration: configuration,
							credentials: credentials,
							transport: transport,
							clock: clock
						)
						try Task.checkCancellation()
						try await self.finishRefresh(
							operationID: operationID,
							baseRevision: baseRevision,
							refreshedTokens: tokens
						)
					}
					catch {
						await self.failRefresh(operationID: operationID, baseRevision: baseRevision, error: error)
					}
				}
			}
			catch {
				await self.failRefresh(operationID: operationID, baseRevision: baseRevision, error: error)
			}
		}
		refreshFlight = RefreshFlight(
			id: operationID,
			baseRevision: baseRevision,
			task: task,
			phase: .network,
			waiters: [waiterID: continuation]
		)
	}

	private func registerRefreshWaiter(
		_ waiterID: UUID,
		continuation: CheckedContinuation<OAuth2TokenSnapshot, any Error>
	) {
		if var flight = refreshFlight {
			flight.waiters[waiterID] = continuation
			refreshFlight = flight
			return
		}

		guard
			credentialRecord.clientCredentials != nil,
			let refreshToken = credentialRecord.tokenSet?.refreshToken,
			!refreshToken.isEmpty
		else {
			continuation.resume(throwing: OAuth2ClientError.interactiveAuthorizationRequired)
			return
		}

		let operationID = UUID()
		let baseRevision = revision
		let configuration = configuration
		let transport = transport
		let clock = clock
		let tokenMutationGate = tokenMutationGate
		let task = Task { [weak self] in
			guard let self else { return }
			do {
				try await tokenMutationGate.withPermit {
					do {
						let input = try await self.refreshInput(
							operationID: operationID,
							baseRevision: baseRevision
						)
						let refreshed = try await OAuth2TokenEndpoint.refresh(
							configuration: configuration,
							credentials: input.credentials,
							currentTokens: input.currentTokens,
							refreshToken: input.refreshToken,
							transport: transport,
							clock: clock
						)
						try Task.checkCancellation()
						try await self.finishRefresh(
							operationID: operationID,
							baseRevision: baseRevision,
							refreshedTokens: refreshed
						)
					}
					catch {
						await self.failRefresh(operationID: operationID, baseRevision: baseRevision, error: error)
					}
				}
			}
			catch {
				await self.failRefresh(operationID: operationID, baseRevision: baseRevision, error: error)
			}
		}

		refreshFlight = RefreshFlight(
			id: operationID,
			baseRevision: baseRevision,
			task: task,
			phase: .network,
			waiters: [waiterID: continuation]
		)
	}

	private func refreshInput(operationID: UUID, baseRevision: UInt64) throws -> RefreshInput {
		guard refreshFlight?.id == operationID, revision == baseRevision else {
			throw OAuth2ClientError.operationSuperseded
		}
		guard
			let credentials = credentialRecord.clientCredentials,
			let currentTokens = credentialRecord.tokenSet,
			let refreshToken = currentTokens.refreshToken,
			!refreshToken.isEmpty
		else {
			throw OAuth2ClientError.interactiveAuthorizationRequired
		}
		return RefreshInput(
			credentials: credentials,
			currentTokens: currentTokens,
			refreshToken: refreshToken
		)
	}

	private func finishRefresh(
		operationID: UUID,
		baseRevision: UInt64,
		refreshedTokens: OAuth2TokenSet
	) async throws {
		guard var flight = refreshFlight, flight.id == operationID else {
			return
		}
		guard revision == baseRevision else {
			throw OAuth2ClientError.operationSuperseded
		}

		let updatedRecord = OAuth2CredentialRecord(
			clientCredentials: credentialRecord.clientCredentials,
			tokenSet: refreshedTokens
		)
		flight.phase = .committing
		refreshFlight = flight
		try await credentialStore.save(updatedRecord)

		guard let currentFlight = refreshFlight, currentFlight.id == operationID else {
			return
		}
		guard revision == baseRevision else {
			throw OAuth2ClientError.operationSuperseded
		}
		credentialRecord = updatedRecord
		revision &+= 1
		rejectedAccessTokenRevision = nil
		resumeRefreshWaiters(with: .success(OAuth2TokenSnapshot(tokenSet: refreshedTokens, revision: revision)))
	}

	private func failRefresh(operationID: UUID, baseRevision: UInt64, error: any Error) async {
		guard var flight = refreshFlight, flight.id == operationID else {
			return
		}
		if revision != baseRevision {
			if let snapshot = currentSnapshot(), isUsable(snapshot), rejectedAccessTokenRevision != snapshot.revision {
				resumeRefreshWaiters(with: .success(snapshot))
			}
			else {
				resumeRefreshWaiters(with: .failure(OAuth2ClientError.operationSuperseded))
			}
			return
		}

		if isTerminalRefreshRejection(error) {
			let clearedRecord = OAuth2CredentialRecord(
				clientCredentials: credentialRecord.clientCredentials,
				tokenSet: nil
			)
			flight.phase = .committing
			refreshFlight = flight
			do {
				try await credentialStore.save(clearedRecord)
			}
			catch {
				guard refreshFlight?.id == operationID else { return }
				resumeRefreshWaiters(with: .failure(error))
				return
			}

			guard refreshFlight?.id == operationID, revision == baseRevision else { return }
			credentialRecord = clearedRecord
			revision &+= 1
			rejectedAccessTokenRevision = nil
			resumeRefreshWaiters(with: .failure(OAuth2ClientError.interactiveAuthorizationRequired))
			return
		}

		resumeRefreshWaiters(with: .failure(error))
	}

	private func isTerminalRefreshRejection(_ error: any Error) -> Bool {
		guard case .authorizationServer(let code, _, _) = error as? OAuth2ClientError else {
			return false
		}
		return code == "invalid_grant" || code == "unauthorized_client"
	}

	private func cancelRefreshWaiter(_ waiterID: UUID) {
		guard var flight = refreshFlight, let waiter = flight.waiters.removeValue(forKey: waiterID) else {
			return
		}
		waiter.resume(throwing: CancellationError())

		if flight.waiters.isEmpty, flight.phase == .network {
			flight.task.cancel()
			refreshFlight = nil
		}
		else {
			refreshFlight = flight
		}
	}

	private func cancelRefreshFlight() {
		guard let flight = refreshFlight else { return }
		flight.task.cancel()
		refreshFlight = nil
		for waiter in flight.waiters.values {
			waiter.resume(throwing: CancellationError())
		}
	}

	private func resumeRefreshWaiters(with result: Result<OAuth2TokenSnapshot, any Error>) {
		guard let flight = refreshFlight else { return }
		refreshFlight = nil
		for waiter in flight.waiters.values {
			waiter.resume(with: result)
		}
	}
}

private enum OAuth2TokenEndpoint {
	static func password(
		username: String,
		password: String,
		additionalParameters: [String: String],
		configuration: OAuth2ClientConfiguration,
		credentials: OAuth2ClientCredentials?,
		transport: any OAuth2Transport,
		clock: any OAuth2Clock
	) async throws -> OAuth2TokenSet {
		var parameters = configuration.additionalTokenParameters
		parameters.merge(additionalParameters) { _, replacement in replacement }
		parameters["grant_type"] = "password"
		parameters["username"] = username
		parameters["password"] = password
		if !configuration.scopes.isEmpty {
			parameters["scope"] = configuration.scopes.joined(separator: " ")
		}

		var request = URLRequest(url: configuration.tokenEndpoint)
		request.httpMethod = "POST"
		request.setValue("application/json", forHTTPHeaderField: "Accept")
		request.setValue("application/x-www-form-urlencoded; charset=utf-8", forHTTPHeaderField: "Content-Type")
		if let credentials {
			try authenticate(&request, parameters: &parameters, configuration: configuration, credentials: credentials)
		}
		else if let authorizationHeader = configuration.tokenAuthorizationHeader {
			request.setValue(authorizationHeader, forHTTPHeaderField: "Authorization")
		}
		else if configuration.clientAuthentication != .none {
			throw OAuth2ClientError.missingClientIdentifier
		}
		request.httpBody = formEncoded(parameters).data(using: .utf8)

		let response = try await transport.data(for: request)
		let tokenResponse = try decodeTokenResponse(response, configuration: configuration)
		return OAuth2TokenSet(
			accessToken: tokenResponse.accessToken,
			refreshToken: tokenResponse.refreshToken,
			idToken: tokenResponse.idToken,
			tokenType: tokenResponse.tokenType,
			scopes: tokenResponse.scope?.split(separator: " ").map(String.init) ?? configuration.scopes,
			expiresAt: tokenResponse.expiresIn.map { clock.now().addingTimeInterval($0) },
			additionalParameters: tokenResponse.additionalParameters
		)
	}

	static func exchangeRefreshToken(
		_ subjectRefreshToken: String,
		audienceClientID: String,
		additionalParameters: [String: String],
		configuration: OAuth2ClientConfiguration,
		credentials: OAuth2ClientCredentials,
		transport: any OAuth2Transport
	) async throws -> OAuth2TokenResponse {
		var parameters = configuration.additionalTokenParameters
		parameters.merge(additionalParameters) { _, replacement in replacement }
		parameters["grant_type"] = "urn:ietf:params:oauth:grant-type:token-exchange"
		parameters["audience"] = audienceClientID
		parameters["requested_token_type"] = "urn:ietf:params:oauth:token-type:refresh_token"
		parameters["subject_token"] = subjectRefreshToken
		parameters["subject_token_type"] = "urn:ietf:params:oauth:token-type:refresh_token"

		let request = try tokenRequest(
			parameters: parameters,
			configuration: configuration,
			credentials: credentials
		)
		let response = try await transport.data(for: request)
		return try decodeTokenResponse(response, configuration: configuration)
	}

	static func exchangeAccessToken(
		_ subjectAccessToken: String,
		resources: [String],
		additionalParameters: [String: String],
		configuration: OAuth2ClientConfiguration,
		credentials: OAuth2ClientCredentials,
		transport: any OAuth2Transport
	) async throws -> OAuth2TokenResponse {
		var parameters = configuration.additionalTokenParameters
		parameters.merge(additionalParameters) { _, replacement in replacement }
		parameters["grant_type"] = "urn:ietf:params:oauth:grant-type:token-exchange"
		parameters["requested_token_type"] = "urn:ietf:params:oauth:token-type:access_token"
		parameters["subject_token"] = subjectAccessToken
		parameters["subject_token_type"] = "urn:ietf:params:oauth:token-type:access_token"

		let request = try tokenRequest(
			parameters: parameters,
			repeatedParameters: resources.map { ("resource", $0) },
			configuration: configuration,
			credentials: credentials
		)
		let response = try await transport.data(for: request)
		return try decodeTokenResponse(response, configuration: configuration)
	}

	static func clientCredentials(
		grantType: String,
		additionalParameters: [String: String],
		configuration: OAuth2ClientConfiguration,
		credentials: OAuth2ClientCredentials,
		transport: any OAuth2Transport,
		clock: any OAuth2Clock
	) async throws -> OAuth2TokenSet {
		var parameters = configuration.additionalTokenParameters
		parameters.merge(additionalParameters) { _, replacement in replacement }
		parameters["grant_type"] = grantType
		if !configuration.scopes.isEmpty {
			parameters["scope"] = configuration.scopes.joined(separator: " ")
		}

		var request = URLRequest(url: configuration.tokenEndpoint)
		request.httpMethod = "POST"
		request.setValue("application/json", forHTTPHeaderField: "Accept")
		request.setValue("application/x-www-form-urlencoded; charset=utf-8", forHTTPHeaderField: "Content-Type")
		try authenticate(&request, parameters: &parameters, configuration: configuration, credentials: credentials)
		request.httpBody = formEncoded(parameters).data(using: .utf8)

		let response = try await transport.data(for: request)
		let tokenResponse = try decodeTokenResponse(response, configuration: configuration)
		return OAuth2TokenSet(
			accessToken: tokenResponse.accessToken,
			refreshToken: tokenResponse.refreshToken,
			idToken: tokenResponse.idToken,
			tokenType: tokenResponse.tokenType,
			scopes: tokenResponse.scope?.split(separator: " ").map(String.init) ?? configuration.scopes,
			expiresAt: tokenResponse.expiresIn.map { clock.now().addingTimeInterval($0) },
			additionalParameters: tokenResponse.additionalParameters
		)
	}

	static func beginDeviceAuthorization(
		configuration: OAuth2ClientConfiguration,
		credentials: OAuth2ClientCredentials,
		additionalParameters: [String: String],
		transport: any OAuth2Transport,
		clock: any OAuth2Clock
	) async throws -> OAuth2DeviceAuthorization {
		guard let endpoint = configuration.deviceAuthorizationEndpoint else {
			throw OAuth2ClientError.missingDeviceAuthorizationEndpoint
		}

		var parameters = additionalParameters
		parameters["client_id"] = credentials.clientID
		if !configuration.scopes.isEmpty {
			parameters["scope"] = configuration.scopes.joined(separator: " ")
		}
		var request = URLRequest(url: endpoint)
		request.httpMethod = "POST"
		request.setValue("application/json", forHTTPHeaderField: "Accept")
		request.setValue("application/x-www-form-urlencoded; charset=utf-8", forHTTPHeaderField: "Content-Type")
		request.httpBody = formEncoded(parameters).data(using: .utf8)

		let response = try await transport.data(for: request)
		guard (200..<300).contains(response.statusCode) else {
			throw authorizationServerError(from: response)
		}
		var values = try JSONDecoder().decode([String: JSONValue].self, from: response.data)
		guard
			let deviceCode = values.removeValue(forKey: "device_code")?.stringValue,
			let userCode = values.removeValue(forKey: "user_code")?.stringValue,
			let verificationURIString = values.removeValue(forKey: "verification_uri")?.stringValue,
			let verificationURI = URL(string: verificationURIString),
			let expiresIn = values.removeValue(forKey: "expires_in")?.timeIntervalValue,
			expiresIn.isFinite,
			expiresIn > 0
		else {
			throw OAuth2ClientError.invalidTokenResponse("The device authorization response is missing a required field")
		}
		let completeURI = values.removeValue(forKey: "verification_uri_complete")?.stringValue.flatMap(URL.init(string:))
		let interval = values.removeValue(forKey: "interval")?.timeIntervalValue ?? 5
		guard interval.isFinite, interval > 0 else {
			throw OAuth2ClientError.invalidTokenResponse("The device polling interval must be finite and greater than zero")
		}
		return OAuth2DeviceAuthorization(
			deviceCode: deviceCode,
			userCode: userCode,
			verificationURI: verificationURI,
			verificationURIComplete: completeURI,
			expiresAt: clock.now().addingTimeInterval(expiresIn),
			pollingInterval: interval,
			additionalParameters: values
		)
	}

	static func exchangeDeviceCode(
		_ deviceCode: String,
		configuration: OAuth2ClientConfiguration,
		credentials: OAuth2ClientCredentials,
		transport: any OAuth2Transport,
		clock: any OAuth2Clock
	) async throws -> OAuth2TokenSet {
		var parameters = configuration.additionalTokenParameters
		parameters["device_code"] = deviceCode
		parameters["grant_type"] = "urn:ietf:params:oauth:grant-type:device_code"

		var request = URLRequest(url: configuration.tokenEndpoint)
		request.httpMethod = "POST"
		request.setValue("application/json", forHTTPHeaderField: "Accept")
		request.setValue("application/x-www-form-urlencoded; charset=utf-8", forHTTPHeaderField: "Content-Type")
		try authenticate(&request, parameters: &parameters, configuration: configuration, credentials: credentials)
		request.httpBody = formEncoded(parameters).data(using: .utf8)

		let response = try await transport.data(for: request)
		let tokenResponse = try decodeTokenResponse(response, configuration: configuration)
		return OAuth2TokenSet(
			accessToken: tokenResponse.accessToken,
			refreshToken: tokenResponse.refreshToken,
			idToken: tokenResponse.idToken,
			tokenType: tokenResponse.tokenType,
			scopes: tokenResponse.scope?.split(separator: " ").map(String.init) ?? configuration.scopes,
			expiresAt: tokenResponse.expiresIn.map { clock.now().addingTimeInterval($0) },
			additionalParameters: tokenResponse.additionalParameters
		)
	}

	static func exchangeAuthorizationCode(
		_ code: String,
		codeVerifier: String?,
		configuration: OAuth2ClientConfiguration,
		credentials: OAuth2ClientCredentials,
		transport: any OAuth2Transport,
		clock: any OAuth2Clock
	) async throws -> OAuth2TokenSet {
		guard let redirectURI = configuration.redirectURI else {
			throw OAuth2ClientError.missingRedirectURI
		}

		var parameters = configuration.additionalTokenParameters
		parameters["code"] = code
		parameters["grant_type"] = "authorization_code"
		parameters["redirect_uri"] = redirectURI.absoluteString
		if let codeVerifier {
			parameters["code_verifier"] = codeVerifier
		}

		var request = URLRequest(url: configuration.tokenEndpoint)
		request.httpMethod = "POST"
		request.setValue("application/json", forHTTPHeaderField: "Accept")
		request.setValue("application/x-www-form-urlencoded; charset=utf-8", forHTTPHeaderField: "Content-Type")
		try authenticate(&request, parameters: &parameters, configuration: configuration, credentials: credentials)
		request.httpBody = formEncoded(parameters).data(using: .utf8)

		let response = try await transport.data(for: request)
		let tokenResponse = try decodeTokenResponse(response, configuration: configuration)
		return OAuth2TokenSet(
			accessToken: tokenResponse.accessToken,
			refreshToken: tokenResponse.refreshToken,
			idToken: tokenResponse.idToken,
			tokenType: tokenResponse.tokenType,
			scopes: tokenResponse.scope?.split(separator: " ").map(String.init) ?? configuration.scopes,
			expiresAt: tokenResponse.expiresIn.map { clock.now().addingTimeInterval($0) },
			additionalParameters: tokenResponse.additionalParameters
		)
	}

	static func refresh(
		configuration: OAuth2ClientConfiguration,
		credentials: OAuth2ClientCredentials,
		currentTokens: OAuth2TokenSet,
		refreshToken: String,
		transport: any OAuth2Transport,
		clock: any OAuth2Clock
	) async throws -> OAuth2TokenSet {
		var parameters = configuration.additionalTokenParameters
		parameters["grant_type"] = "refresh_token"
		parameters["refresh_token"] = refreshToken
		if !configuration.scopes.isEmpty {
			parameters["scope"] = configuration.scopes.joined(separator: " ")
		}

		var request = URLRequest(url: configuration.refreshEndpoint ?? configuration.tokenEndpoint)
		request.httpMethod = "POST"
		request.setValue("application/json", forHTTPHeaderField: "Accept")
		request.setValue("application/x-www-form-urlencoded; charset=utf-8", forHTTPHeaderField: "Content-Type")

		try authenticate(&request, parameters: &parameters, configuration: configuration, credentials: credentials)

		request.httpBody = formEncoded(parameters).data(using: .utf8)
		let response = try await transport.data(for: request)
		let tokenResponse = try decodeTokenResponse(response, configuration: configuration)

		return OAuth2TokenSet(
			accessToken: tokenResponse.accessToken,
			refreshToken: tokenResponse.refreshToken ?? currentTokens.refreshToken,
			idToken: tokenResponse.idToken ?? currentTokens.idToken,
			tokenType: tokenResponse.tokenType,
			scopes: tokenResponse.scope?.split(separator: " ").map(String.init) ?? currentTokens.scopes,
			expiresAt: tokenResponse.expiresIn.map { clock.now().addingTimeInterval($0) },
			additionalParameters: tokenResponse.additionalParameters
		)
	}

	private static func authenticate(
		_ request: inout URLRequest,
		parameters: inout [String: String],
		configuration: OAuth2ClientConfiguration,
		credentials: OAuth2ClientCredentials
	) throws {
		if let authorizationHeader = configuration.tokenAuthorizationHeader {
			request.setValue(authorizationHeader, forHTTPHeaderField: "Authorization")
			return
		}
		switch credentials.authenticationMethod ?? configuration.clientAuthentication {
		case .none:
			parameters["client_id"] = credentials.clientID
		case .clientSecretBasic:
			guard let secret = credentials.clientSecret else {
				throw OAuth2ClientError.missingClientSecret
			}
			let encodedClientID = encodeFormComponent(credentials.clientID)
			let encodedSecret = encodeFormComponent(secret)
			let value = Data("\(encodedClientID):\(encodedSecret)".utf8).base64EncodedString()
			request.setValue("Basic \(value)", forHTTPHeaderField: "Authorization")
		case .clientSecretPost:
			guard let secret = credentials.clientSecret else {
				throw OAuth2ClientError.missingClientSecret
			}
			parameters["client_id"] = credentials.clientID
			parameters["client_secret"] = secret
		}
	}

	private static func tokenRequest(
		parameters: [String: String],
		repeatedParameters: [(String, String)] = [],
		configuration: OAuth2ClientConfiguration,
		credentials: OAuth2ClientCredentials
	) throws -> URLRequest {
		var request = URLRequest(url: configuration.tokenEndpoint)
		request.httpMethod = "POST"
		request.setValue("application/json", forHTTPHeaderField: "Accept")
		request.setValue("application/x-www-form-urlencoded; charset=utf-8", forHTTPHeaderField: "Content-Type")
		let authenticatedParameters = try parametersForAuthenticatedRequest(
			parameters,
			request: &request,
			configuration: configuration,
			credentials: credentials
		)
		request.httpBody = formEncoded(
			authenticatedParameters,
			repeatedParameters: repeatedParameters
		).data(using: .utf8)
		return request
	}

	private static func parametersForAuthenticatedRequest(
		_ parameters: [String: String],
		request: inout URLRequest,
		configuration: OAuth2ClientConfiguration,
		credentials: OAuth2ClientCredentials
	) throws -> [String: String] {
		var parameters = parameters
		try authenticate(&request, parameters: &parameters, configuration: configuration, credentials: credentials)
		return parameters
	}

	private static func decodeTokenResponse(
		_ response: OAuth2HTTPResponse,
		configuration: OAuth2ClientConfiguration
	) throws -> OAuth2TokenResponse {
		guard (200..<300).contains(response.statusCode) else {
			throw authorizationServerError(from: response)
		}

		let tokenResponse: OAuth2TokenResponse
		switch configuration.tokenResponseFormat {
		case .json:
			tokenResponse = try OAuth2TokenResponse(data: response.data)
		case .formURLEncoded:
			guard let responseString = String(data: response.data, encoding: .utf8) else {
				throw OAuth2ClientError.invalidTokenResponse("The form-encoded response is not UTF-8")
			}
			tokenResponse = try OAuth2TokenResponse(values: formDecoded(responseString))
		}
		if let tokenType = tokenResponse.tokenType, tokenType.caseInsensitiveCompare("bearer") != .orderedSame {
			throw OAuth2ClientError.invalidTokenResponse("Unsupported token_type \(tokenType)")
		}
		if tokenResponse.tokenType == nil, !configuration.allowsMissingTokenType {
			throw OAuth2ClientError.invalidTokenResponse("The response does not contain token_type")
		}
		return tokenResponse
	}

	private static func formDecoded(_ value: String) -> [String: JSONValue] {
		var result = [String: JSONValue]()
		for pair in value.split(separator: "&", omittingEmptySubsequences: false) {
			let components = pair.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
			guard let rawKey = components.first else { continue }
			let rawValue = components.count > 1 ? String(components[1]) : ""
			let key = String(rawKey).replacingOccurrences(of: "+", with: " ").removingPercentEncoding ?? String(rawKey)
			let decoded = rawValue.replacingOccurrences(of: "+", with: " ").removingPercentEncoding ?? rawValue
			result[key] = .string(decoded)
		}
		return result
	}

	private static func authorizationServerError(from response: OAuth2HTTPResponse) -> OAuth2ClientError {
		let values = (try? JSONDecoder().decode([String: JSONValue].self, from: response.data)) ?? [:]
		return OAuth2ClientError.authorizationServer(
			code: values["error"]?.stringValue,
			description: values["error_description"]?.stringValue,
			statusCode: response.statusCode
		)
	}

	private static func formEncoded(
		_ parameters: [String: String],
		repeatedParameters: [(String, String)] = []
	) -> String {
		let unique = parameters.keys.sorted().map { key in
			let value = parameters[key, default: ""]
			return "\(encodeFormComponent(key))=\(encodeFormComponent(value))"
		}
		let repeated = repeatedParameters.map { key, value in
			"\(encodeFormComponent(key))=\(encodeFormComponent(value))"
		}
		return (unique + repeated).joined(separator: "&")
	}

	private static func encodeFormComponent(_ value: String) -> String {
		var allowed = CharacterSet.alphanumerics
		allowed.insert(charactersIn: "-._~")
		return value.addingPercentEncoding(withAllowedCharacters: allowed)?
			.replacingOccurrences(of: "%20", with: "+") ?? value
	}
}
