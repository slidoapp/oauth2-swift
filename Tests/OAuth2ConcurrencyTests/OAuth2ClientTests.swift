import Foundation
import XCTest
@testable import OAuth2

final class OAuth2ClientTests: XCTestCase {
	func testConcurrentCallersCoalesceRefresh() async throws {
		let transport = RefreshTransport()
		let client = makeClient(transport: transport)

		let snapshots = try await withThrowingTaskGroup(of: OAuth2TokenSnapshot.self) { group in
			for _ in 0..<100 {
				group.addTask {
					try await client.validAccessToken()
				}
			}

			var snapshots = [OAuth2TokenSnapshot]()
			for try await snapshot in group {
				snapshots.append(snapshot)
			}
			return snapshots
		}

		XCTAssertEqual(100, snapshots.count)
		XCTAssertTrue(snapshots.allSatisfy { $0.tokenSet.accessToken == "new-access-token" })
		let refreshCount = await transport.refreshCount
		XCTAssertEqual(1, refreshCount)
	}

	func testConcurrentClientCredentialsCallersCoalesceTokenRequest() async throws {
		let transport = RefreshTransport()
		let client = OAuth2Client(
			configuration: OAuth2ClientConfiguration(
				tokenEndpoint: URL(string: "https://auth.example.com/token")!,
				clientAuthentication: .clientSecretPost
			),
			clientCredentials: OAuth2ClientCredentials(clientID: "client", clientSecret: "secret"),
			transport: transport
		)

		let snapshots = try await withThrowingTaskGroup(of: OAuth2TokenSnapshot.self) { group in
			for _ in 0..<100 {
				group.addTask {
					try await client.authorizeWithClientCredentials()
				}
			}
			var snapshots = [OAuth2TokenSnapshot]()
			for try await snapshot in group {
				snapshots.append(snapshot)
			}
			return snapshots
		}

		XCTAssertEqual(100, snapshots.count)
		XCTAssertTrue(snapshots.allSatisfy { $0.tokenSet.accessToken == "new-access-token" })
		let requestCount = await transport.refreshCount
		XCTAssertEqual(1, requestCount)
	}

	func testBackgroundAuthorizationUsesMainActorPresenter() async throws {
		let transport = AuthorizationTransport()
		let presenter = await MainActor.run {
			ImmediateAuthorizationPresenter(redirectURI: URL(string: "myapp://oauth/callback")!)
		}
		let client = makeAuthorizationClient(transport: transport)

		let snapshot = try await Task.detached {
			try await client.authorize(using: presenter)
		}.value

		XCTAssertEqual("new-access-token", snapshot.tokenSet.accessToken)
		let presentationCount = await presenter.presentationCount
		XCTAssertEqual(1, presentationCount)
		let tokenRequest = await transport.tokenRequest
		let body = try XCTUnwrap(tokenRequest?.httpBody.flatMap { String(data: $0, encoding: .utf8) })
		XCTAssertTrue(body.contains("grant_type=authorization_code"))
		XCTAssertTrue(body.contains("code_verifier="))
	}

	func testInvalidAuthorizationStateDoesNotExchangeCode() async throws {
		let transport = AuthorizationTransport()
		let presenter = await MainActor.run {
			ImmediateAuthorizationPresenter(
				redirectURI: URL(string: "myapp://oauth/callback")!,
				stateOverride: "wrong-state"
			)
		}
		let client = makeAuthorizationClient(transport: transport)

		do {
			_ = try await client.authorize(using: presenter)
			XCTFail("Expected state validation to fail")
		}
		catch let error as OAuth2ClientError {
			XCTAssertEqual(.invalidAuthorizationResponse("The state parameter does not match"), error)
		}

		let exchangeCount = await transport.exchangeCount
		XCTAssertEqual(0, exchangeCount)
	}

	func testImplicitGrantSupportsFragmentAndQueryResponsesWithoutTokenExchange() async throws {
		for location in [OAuth2ImplicitResponseLocation.fragment, .query] {
			let transport = AuthorizationTransport()
			let presenter = await MainActor.run {
				ImmediateImplicitPresenter(
					redirectURI: URL(string: "myapp://oauth/callback")!,
					location: location
				)
			}
			let client = OAuth2Client(
				configuration: OAuth2ClientConfiguration(
					authorizationEndpoint: URL(string: "https://auth.example.com/authorize")!,
					tokenEndpoint: URL(string: "https://auth.example.com/token")!,
					redirectURI: URL(string: "myapp://oauth/callback")!,
					implicitResponseLocation: location
				),
				clientCredentials: OAuth2ClientCredentials(clientID: "client"),
				transport: transport
			)

			let snapshot = try await client.authorizeImplicit(using: presenter)
			XCTAssertEqual("implicit-token", snapshot.tokenSet.accessToken)
			XCTAssertEqual(.string("provider-value"), snapshot.tokenSet.additionalParameters["provider_field"])
			let exchangeCount = await transport.exchangeCount
			XCTAssertEqual(0, exchangeCount)
		}
	}

	func testCancellingOneAuthorizationWaiterKeepsSharedPresentationAlive() async throws {
		let transport = AuthorizationTransport()
		let presenter = await MainActor.run {
			ControllableAuthorizationPresenter(redirectURI: URL(string: "myapp://oauth/callback")!)
		}
		let client = makeAuthorizationClient(transport: transport)
		let cancelledWaiter = Task {
			try await client.authorize(using: presenter)
		}

		await presenter.waitUntilStarted()
		let remainingWaiter = Task {
			try await client.authorize(using: presenter)
		}
		while await client.pendingAuthorizationWaiterCount < 2 {
			await Task.yield()
		}

		cancelledWaiter.cancel()
		do {
			_ = try await cancelledWaiter.value
			XCTFail("Expected the cancelled authorization waiter to stop waiting")
		}
		catch is CancellationError {
			// Expected. The other waiter still owns the shared presentation.
		}

		await presenter.succeed()
		let snapshot = try await remainingWaiter.value
		XCTAssertEqual("new-access-token", snapshot.tokenSet.accessToken)
		let cancelCount = await presenter.cancelCount
		XCTAssertEqual(0, cancelCount)
	}

	func testExplicitAuthorizationCancellationCancelsPresenterAndWaiter() async throws {
		let transport = AuthorizationTransport()
		let presenter = await MainActor.run {
			ControllableAuthorizationPresenter(redirectURI: URL(string: "myapp://oauth/callback")!)
		}
		let client = makeAuthorizationClient(transport: transport)
		let waiter = Task {
			try await client.authorize(using: presenter)
		}

		await presenter.waitUntilStarted()
		await client.cancelAuthorization()
		do {
			_ = try await waiter.value
			XCTFail("Expected explicit authorization cancellation")
		}
		catch is CancellationError {
			// Expected.
		}

		let cancelCount = await presenter.cancelCount
		XCTAssertEqual(1, cancelCount)
		let exchangeCount = await transport.exchangeCount
		XCTAssertEqual(0, exchangeCount)
	}

	func testAuthorizationCancellationDoesNotInterruptCredentialCommit() async throws {
		let transport = AuthorizationTransport()
		let store = CommitBlockingCredentialStore()
		let presenter = await MainActor.run {
			ControllableAuthorizationPresenter(redirectURI: URL(string: "myapp://oauth/callback")!)
		}
		let client = OAuth2Client(
			configuration: OAuth2ClientConfiguration(
				authorizationEndpoint: URL(string: "https://auth.example.com/authorize")!,
				tokenEndpoint: URL(string: "https://auth.example.com/token")!,
				redirectURI: URL(string: "myapp://oauth/callback")!,
				clientAuthentication: .clientSecretPost
			),
			clientCredentials: OAuth2ClientCredentials(clientID: "client", clientSecret: "secret"),
			transport: transport,
			credentialStore: store
		)
		let authorization = Task {
			try await client.authorize(using: presenter)
		}

		await presenter.waitUntilStarted()
		await presenter.succeed()
		await store.waitUntilSaveStarted()
		await client.cancelAuthorization()
		let cancelCount = await presenter.cancelCount
		XCTAssertEqual(0, cancelCount)

		await store.completeSave()
		let snapshot = try await authorization.value
		XCTAssertEqual("new-access-token", snapshot.tokenSet.accessToken)
		let persisted = await store.load()
		XCTAssertEqual("new-access-token", persisted?.tokenSet?.accessToken)
	}

	func testAuthorizationEndpointCannotOverrideReservedParameters() async throws {
		let transport = AuthorizationTransport()
		let presenter = await MainActor.run {
			ImmediateAuthorizationPresenter(redirectURI: URL(string: "myapp://oauth/callback")!)
		}
		let client = OAuth2Client(
			configuration: OAuth2ClientConfiguration(
				authorizationEndpoint: URL(string: "https://auth.example.com/authorize?state=attacker&tenant=slido")!,
				tokenEndpoint: URL(string: "https://auth.example.com/token")!,
				redirectURI: URL(string: "myapp://oauth/callback")!,
				clientAuthentication: .clientSecretPost
			),
			clientCredentials: OAuth2ClientCredentials(clientID: "client", clientSecret: "secret"),
			transport: transport
		)

		let snapshot = try await client.authorize(using: presenter)
		XCTAssertEqual("new-access-token", snapshot.tokenSet.accessToken)
	}

	func testAuthorizationRedirectMustMatchConfiguredPort() async throws {
		let transport = AuthorizationTransport()
		let presenter = await MainActor.run {
			ImmediateAuthorizationPresenter(redirectURI: URL(string: "https://app.example.com:9443/callback")!)
		}
		let client = OAuth2Client(
			configuration: OAuth2ClientConfiguration(
				authorizationEndpoint: URL(string: "https://auth.example.com/authorize")!,
				tokenEndpoint: URL(string: "https://auth.example.com/token")!,
				redirectURI: URL(string: "https://app.example.com:8443/callback")!
			),
			clientCredentials: OAuth2ClientCredentials(clientID: "client"),
			transport: transport
		)

		do {
			_ = try await client.authorize(using: presenter)
			XCTFail("Expected redirect validation to reject the wrong port")
		}
		catch let error as OAuth2ClientError {
			XCTAssertEqual(.invalidAuthorizationResponse("The redirect URI does not match the configured redirect"), error)
		}
		let exchangeCount = await transport.exchangeCount
		XCTAssertEqual(0, exchangeCount)
	}

	func testDeviceAuthorizationPollingIsStructuredAndHonorsSlowDown() async throws {
		let transport = DeviceAuthorizationTransport()
		let sleeper = RecordingSleeper()
		let client = OAuth2Client(
			configuration: OAuth2ClientConfiguration(
				deviceAuthorizationEndpoint: URL(string: "https://auth.example.com/device")!,
				tokenEndpoint: URL(string: "https://auth.example.com/token")!,
				scopes: ["openid"],
				clientAuthentication: .none
			),
			clientCredentials: OAuth2ClientCredentials(clientID: "device-client"),
			transport: transport,
			sleeper: sleeper
		)

		let authorization = try await client.beginDeviceAuthorization()
		XCTAssertEqual("ABCD-EFGH", authorization.userCode)
		XCTAssertEqual(.string("tenant-value"), authorization.additionalParameters["tenant"])

		let snapshot = try await client.pollForDeviceAuthorization(authorization)
		XCTAssertEqual("new-access-token", snapshot.tokenSet.accessToken)
		let intervals = await sleeper.intervals
		XCTAssertEqual([5, 5, 10], intervals)
		let pollCount = await transport.pollCount
		XCTAssertEqual(3, pollCount)
	}

	func testDevicePollingRejectsInvalidIntervalsBeforeSleeping() async throws {
		let sleeper = RecordingSleeper()
		let client = OAuth2Client(
			configuration: OAuth2ClientConfiguration(tokenEndpoint: URL(string: "https://auth.example.com/token")!),
			clientCredentials: OAuth2ClientCredentials(clientID: "client"),
			sleeper: sleeper
		)
		let authorization = OAuth2DeviceAuthorization(
			deviceCode: "device-code",
			userCode: "ABCD-EFGH",
			verificationURI: URL(string: "https://auth.example.com/verify")!,
			verificationURIComplete: nil,
			expiresAt: .distantFuture,
			pollingInterval: .infinity
		)

		do {
			_ = try await client.pollForDeviceAuthorization(authorization)
			XCTFail("Expected an invalid polling interval")
		}
		catch let error as OAuth2ClientError {
			XCTAssertEqual(
				.invalidTokenResponse("The device polling interval must be finite and greater than zero"),
				error
			)
		}
		let intervals = await sleeper.intervals
		XCTAssertTrue(intervals.isEmpty)
	}

	func testHeterogeneousTokenMutationsAreSerializedAndStaleRefreshIsSkipped() async throws {
		let transport = ControllableTokenMutationTransport()
		let sleeper = RecordingSleeper()
		let client = OAuth2Client(
			configuration: OAuth2ClientConfiguration(
				tokenEndpoint: URL(string: "https://auth.example.com/token")!,
				clientAuthentication: .none
			),
			clientCredentials: OAuth2ClientCredentials(clientID: "client"),
			tokenSet: OAuth2TokenSet(
				accessToken: "expired-token",
				refreshToken: "refresh-token",
				expiresAt: .distantPast
			),
			transport: transport,
			sleeper: sleeper
		)
		let authorization = OAuth2DeviceAuthorization(
			deviceCode: "device-code",
			userCode: "ABCD-EFGH",
			verificationURI: URL(string: "https://auth.example.com/verify")!,
			verificationURIComplete: nil,
			expiresAt: .distantFuture,
			pollingInterval: 1
		)
		let devicePoll = Task {
			try await client.pollForDeviceAuthorization(authorization)
		}

		await transport.waitUntilStarted()
		let refresh = Task {
			try await client.validAccessToken()
		}
		while await client.pendingRefreshWaiterCount < 1 {
			await Task.yield()
		}
		await transport.complete()

		let deviceSnapshot = try await devicePoll.value
		let refreshSnapshot = try await refresh.value
		XCTAssertEqual(deviceSnapshot, refreshSnapshot)
		let requestCount = await transport.requestCount
		let maximumConcurrentRequests = await transport.maximumConcurrentRequests
		XCTAssertEqual(1, requestCount)
		XCTAssertEqual(1, maximumConcurrentRequests)
	}

	func testTokenExchangePersistsRotatedRefreshAndResourceAccessTokens() async throws {
		let transport = TokenExchangeTransport()
		let client = OAuth2Client(
			configuration: OAuth2ClientConfiguration(
				tokenEndpoint: URL(string: "https://auth.example.com/token")!,
				clientAuthentication: .clientSecretPost
			),
			clientCredentials: OAuth2ClientCredentials(clientID: "client", clientSecret: "secret"),
			tokenSet: OAuth2TokenSet(
				accessToken: "subject-access",
				refreshToken: "subject-refresh",
				expiresAt: .distantFuture
			),
			transport: transport
		)

		let audienceRefresh = try await client.exchangeRefreshToken(forAudience: "audience-client")
		XCTAssertEqual("audience-refresh", audienceRefresh)
		let optionalSnapshot = try await client.tokenSnapshot()
		let afterRefreshExchange = try XCTUnwrap(optionalSnapshot)
		XCTAssertEqual("subject-access", afterRefreshExchange.tokenSet.accessToken)
		XCTAssertEqual("rotated-subject-refresh", afterRefreshExchange.tokenSet.refreshToken)

		let resourceSnapshot = try await client.exchangeAccessToken(
			forResources: ["https://api-one.example.com", "https://api-two.example.com"]
		)
		XCTAssertEqual("resource-access", resourceSnapshot.tokenSet.accessToken)
		XCTAssertEqual("rotated-subject-refresh", resourceSnapshot.tokenSet.refreshToken)
		let bodies = await transport.requestBodies
		XCTAssertEqual(2, bodies.count)
		XCTAssertTrue(bodies[0].contains("subject_token=subject-refresh"))
		XCTAssertEqual(2, bodies[1].components(separatedBy: "resource=").count - 1)
	}

	func testDynamicRegistrationPersistsCredentialsForSubsequentTokenRequest() async throws {
		let transport = DynamicRegistrationTransport()
		let store = InMemoryOAuth2CredentialStore()
		let client = OAuth2Client(
			configuration: OAuth2ClientConfiguration(
				registrationEndpoint: URL(string: "https://auth.example.com/register")!,
				tokenEndpoint: URL(string: "https://auth.example.com/token")!,
				clientAuthentication: .none
			),
			transport: transport,
			credentialStore: store
		)

		let registration = try await client.registerClient(OAuth2ClientRegistration(
			clientName: "Slido for PowerPoint",
			redirectURIs: [URL(string: "myapp://oauth/callback")!]
		))
		XCTAssertEqual("dynamic-client", registration.credentials.clientID)
		XCTAssertEqual(.clientSecretPost, registration.credentials.authenticationMethod)
		XCTAssertEqual(.string("tenant-value"), registration.additionalParameters["tenant"])

		let snapshot = try await client.authorizeWithClientCredentials()
		XCTAssertEqual("new-access-token", snapshot.tokenSet.accessToken)
		let tokenBody = await transport.tokenRequestBody
		XCTAssertTrue(tokenBody.contains("client_id=dynamic-client"))
		XCTAssertTrue(tokenBody.contains("client_secret=dynamic-secret"))
		let persisted = await store.load()
		XCTAssertEqual("dynamic-client", persisted?.clientCredentials?.clientID)
	}

	func testPasswordGrantSupportsCustomAuthorizationAndFormEncodedResponses() async throws {
		let transport = PasswordGrantTransport()
		let client = OAuth2Client(
			configuration: OAuth2ClientConfiguration(
				tokenEndpoint: URL(string: "https://auth.example.com/token")!,
				clientAuthentication: .none,
				tokenAuthorizationHeader: "Basic provider-token",
				tokenResponseFormat: .formURLEncoded,
				allowsMissingTokenType: true
			),
			transport: transport
		)

		let snapshot = try await client.authorizeWithPassword(
			username: "person@example.com",
			password: "a password"
		)
		XCTAssertEqual("form+token", snapshot.tokenSet.accessToken)
		XCTAssertEqual(.string("bar baz"), snapshot.tokenSet.additionalParameters["provider_field"])
		let authorization = await transport.authorizationHeader
		let body = await transport.requestBody
		XCTAssertEqual("Basic provider-token", authorization)
		XCTAssertTrue(body.contains("username=person%40example.com"))
		XCTAssertTrue(body.contains("password=a%20password") || body.contains("password=a+password"))
	}

	func testLateUnauthorizedRevisionDoesNotRefreshAgain() async throws {
		let transport = RefreshTransport()
		let client = makeClient(transport: transport, accessTokenExpiresAt: Date.distantFuture)
		let failedSnapshot = try await client.validAccessToken()

		let recovered = try await client.recoverAfterUnauthorized(failedSnapshot)
		let recoveredAgain = try await client.recoverAfterUnauthorized(failedSnapshot)

		XCTAssertEqual("new-access-token", recovered.tokenSet.accessToken)
		XCTAssertEqual(recovered, recoveredAgain)
		let refreshCount = await transport.refreshCount
		XCTAssertEqual(1, refreshCount)
	}

	func testCancellingOneWaiterDoesNotCancelSharedRefresh() async throws {
		let transport = ControllableRefreshTransport()
		let client = makeClient(transport: transport)
		let cancelledWaiter = Task {
			try await client.validAccessToken()
		}

		await transport.waitUntilStarted()
		let remainingWaiter = Task {
			try await client.validAccessToken()
		}
		while await client.pendingRefreshWaiterCount < 2 {
			await Task.yield()
		}

		cancelledWaiter.cancel()
		do {
			_ = try await cancelledWaiter.value
			XCTFail("Expected the cancelled waiter to stop waiting")
		}
		catch is CancellationError {
			// Expected. The shared refresh still has another waiter.
		}

		await transport.complete()
		let snapshot = try await remainingWaiter.value
		XCTAssertEqual("new-access-token", snapshot.tokenSet.accessToken)
		let refreshCount = await transport.refreshCount
		XCTAssertEqual(1, refreshCount)
	}

	func testCancellingFinalRefreshWaiterCancelsSharedWork() async throws {
		let transport = CancellationAwareRefreshTransport()
		let client = makeClient(transport: transport)
		let waiter = Task {
			try await client.validAccessToken()
		}

		await transport.waitUntilStarted()
		waiter.cancel()
		do {
			_ = try await waiter.value
			XCTFail("Expected the final refresh waiter to be cancelled")
		}
		catch is CancellationError {
			// Expected.
		}

		while await transport.cancellationCount == 0 {
			await Task.yield()
		}
		let waiterCount = await client.pendingRefreshWaiterCount
		XCTAssertEqual(0, waiterCount)
	}

	func testClearingCredentialsPreventsLateRefreshFromRestoringTokens() async throws {
		let transport = ControllableRefreshTransport()
		let store = InMemoryOAuth2CredentialStore()
		let client = makeClient(transport: transport, credentialStore: store)
		let refreshWaiter = Task {
			try await client.validAccessToken()
		}

		await transport.waitUntilStarted()
		try await client.clearCredentials()
		do {
			_ = try await refreshWaiter.value
			XCTFail("Expected clearing credentials to cancel the refresh waiter")
		}
		catch is CancellationError {
			// Expected.
		}

		await transport.complete()
		await Task.yield()
		let snapshot = try await client.tokenSnapshot()
		XCTAssertNil(snapshot)
		let persisted = await store.load()
		XCTAssertNil(persisted)
	}

	func testTerminalRefreshFailureClearsTokensAndRequiresInteraction() async throws {
		let transport = RefreshTransport(result: .failure(
			.authorizationServer(code: "invalid_grant", description: "revoked", statusCode: 400)
		))
		let store = InMemoryOAuth2CredentialStore()
		let client = makeClient(transport: transport, credentialStore: store)

		do {
			_ = try await client.validAccessToken()
			XCTFail("Expected interactive authorization to be required")
		}
		catch let error as OAuth2ClientError {
			XCTAssertEqual(.interactiveAuthorizationRequired, error)
		}

		let snapshot = try await client.tokenSnapshot()
		XCTAssertNil(snapshot)
		let persisted = await store.load()
		XCTAssertNil(persisted?.tokenSet)
	}

	func testResourceClientRetriesOnlyOnce() async throws {
		let transport = RejectingResourceTransport()
		let client = makeClient(transport: transport, accessTokenExpiresAt: Date.distantFuture)
		let resourceClient = OAuth2ResourceClient(client: client, transport: transport)
		let request = URLRequest(url: URL(string: "https://api.example.com/resource")!)

		do {
			_ = try await resourceClient.data(for: request)
			XCTFail("Expected recovered token to be rejected")
		}
		catch let error as OAuth2ClientError {
			XCTAssertEqual(.unauthorized(statusCode: 401), error)
		}

		let refreshCount = await transport.refreshCount
		let resourceCount = await transport.resourceCount
		XCTAssertEqual(1, refreshCount)
		XCTAssertEqual(2, resourceCount)
	}

	func testUnauthorizedStormCoalescesOneRefresh() async throws {
		let transport = RecoveringResourceTransport()
		let client = makeClient(transport: transport, accessTokenExpiresAt: .distantFuture)
		let resourceClient = OAuth2ResourceClient(client: client, transport: transport)
		let request = URLRequest(url: URL(string: "https://api.example.com/resource")!)

		let responses = try await withThrowingTaskGroup(of: OAuth2HTTPResponse.self) { group in
			for _ in 0..<100 {
				group.addTask {
					try await resourceClient.data(for: request)
				}
			}
			var responses = [OAuth2HTTPResponse]()
			for try await response in group {
				responses.append(response)
			}
			return responses
		}

		XCTAssertEqual(100, responses.count)
		XCTAssertTrue(responses.allSatisfy { $0.statusCode == 200 })
		let refreshCount = await transport.refreshCount
		XCTAssertEqual(1, refreshCount)
	}

	func testSeparateClientsRefreshIndependently() async throws {
		let transport = ParallelRefreshTransport()
		let firstClient = makeClient(transport: transport)
		let secondClient = makeClient(transport: transport)
		let first = Task { try await firstClient.validAccessToken() }
		let second = Task { try await secondClient.validAccessToken() }

		await transport.waitForRequestCount(2)
		let maximumConcurrentRequests = await transport.maximumConcurrentRequests
		XCTAssertEqual(2, maximumConcurrentRequests)
		await transport.completeAll()

		let firstSnapshot = try await first.value
		let secondSnapshot = try await second.value
		let snapshots = [firstSnapshot, secondSnapshot]
		XCTAssertEqual(2, snapshots.count)
		XCTAssertTrue(snapshots.allSatisfy { $0.tokenSet.accessToken == "new-access-token" })
	}

	func testClientSecretBasicUsesFormEncodedCredentials() async throws {
		let transport = AuthorizationHeaderTransport()
		let client = OAuth2Client(
			configuration: OAuth2ClientConfiguration(
				tokenEndpoint: URL(string: "https://auth.example.com/token")!,
				clientAuthentication: .clientSecretBasic
			),
			clientCredentials: OAuth2ClientCredentials(clientID: "client id", clientSecret: "s:e/cret"),
			transport: transport
		)

		_ = try await client.authorizeWithClientCredentials()
		let authorizationHeader = await transport.authorizationHeader
		let header = try XCTUnwrap(authorizationHeader)
		let encoded = try XCTUnwrap(header.split(separator: " ").last).description
		let decodedData = try XCTUnwrap(Data(base64Encoded: encoded))
		let decoded = try XCTUnwrap(String(data: decodedData, encoding: .utf8))
		XCTAssertEqual("client+id:s%3Ae%2Fcret", decoded)
	}

	func testUnknownTokenFieldsSurviveCredentialRoundTrip() throws {
		let tokenSet = OAuth2TokenSet(
			accessToken: "token",
			additionalParameters: [
				"tenant": .string("slido"),
				"roles": .array([.string("presenter"), .string("admin")]),
				"metadata": .object(["attempt": .integer(2)]),
			]
		)
		let record = OAuth2CredentialRecord(
			clientCredentials: OAuth2ClientCredentials(clientID: "client"),
			tokenSet: tokenSet
		)

		let data = try JSONEncoder().encode(record)
		let decoded = try JSONDecoder().decode(OAuth2CredentialRecord.self, from: data)

		XCTAssertEqual(record, decoded)
	}

	private func makeClient(
		transport: any OAuth2Transport,
		credentialStore: any OAuth2CredentialStore = InMemoryOAuth2CredentialStore(),
		accessTokenExpiresAt: Date = .distantPast
	) -> OAuth2Client {
		OAuth2Client(
			configuration: OAuth2ClientConfiguration(
				tokenEndpoint: URL(string: "https://auth.example.com/token")!,
				clientAuthentication: .clientSecretPost
			),
			clientCredentials: OAuth2ClientCredentials(clientID: "client", clientSecret: "secret"),
			tokenSet: OAuth2TokenSet(
				accessToken: "old-access-token",
				refreshToken: "refresh-token",
				expiresAt: accessTokenExpiresAt
			),
			transport: transport,
			credentialStore: credentialStore
		)
	}

	private func makeAuthorizationClient(transport: any OAuth2Transport) -> OAuth2Client {
		OAuth2Client(
			configuration: OAuth2ClientConfiguration(
				authorizationEndpoint: URL(string: "https://auth.example.com/authorize")!,
				tokenEndpoint: URL(string: "https://auth.example.com/token")!,
				redirectURI: URL(string: "myapp://oauth/callback")!,
				scopes: ["openid", "profile"],
				clientAuthentication: .clientSecretPost
			),
			clientCredentials: OAuth2ClientCredentials(clientID: "client", clientSecret: "secret"),
			transport: transport
		)
	}
}

private actor CommitBlockingCredentialStore: OAuth2CredentialStore {
	private var record: OAuth2CredentialRecord?
	private var saveContinuation: CheckedContinuation<Void, Never>?
	private var saveStartedWaiters = [CheckedContinuation<Void, Never>]()

	func load() -> OAuth2CredentialRecord? {
		record
	}

	func save(_ record: OAuth2CredentialRecord) async {
		let waiters = saveStartedWaiters
		saveStartedWaiters.removeAll()
		for waiter in waiters {
			waiter.resume()
		}
		await withCheckedContinuation { continuation in
			saveContinuation = continuation
		}
		self.record = record
	}

	func clear() {
		record = nil
	}

	func waitUntilSaveStarted() async {
		guard saveContinuation == nil else { return }
		await withCheckedContinuation { continuation in
			saveStartedWaiters.append(continuation)
		}
	}

	func completeSave() {
		saveContinuation?.resume()
		saveContinuation = nil
	}
}

private actor RefreshTransport: OAuth2Transport {
	private(set) var refreshCount = 0
	private let result: Result<OAuth2HTTPResponse, OAuth2ClientError>

	init(result: Result<OAuth2HTTPResponse, OAuth2ClientError> = .success(.tokenSuccess)) {
		self.result = result
	}

	func data(for request: URLRequest) async throws -> OAuth2HTTPResponse {
		refreshCount += 1
		return try result.get()
	}
}

private actor CancellationAwareRefreshTransport: OAuth2Transport {
	private(set) var refreshCount = 0
	private(set) var cancellationCount = 0
	private var responseContinuation: CheckedContinuation<OAuth2HTTPResponse, any Error>?
	private var startedWaiters = [CheckedContinuation<Void, Never>]()

	func data(for request: URLRequest) async throws -> OAuth2HTTPResponse {
		refreshCount += 1
		let waiters = startedWaiters
		startedWaiters.removeAll()
		for waiter in waiters {
			waiter.resume()
		}
		return try await withTaskCancellationHandler {
			try await withCheckedThrowingContinuation { continuation in
				if Task.isCancelled {
					cancellationCount += 1
					continuation.resume(throwing: CancellationError())
				}
				else {
					responseContinuation = continuation
				}
			}
		} onCancel: {
			Task {
				await self.cancelRequest()
			}
		}
	}

	func waitUntilStarted() async {
		guard refreshCount == 0 else { return }
		await withCheckedContinuation { continuation in
			startedWaiters.append(continuation)
		}
	}

	private func cancelRequest() {
		guard let responseContinuation else { return }
		self.responseContinuation = nil
		cancellationCount += 1
		responseContinuation.resume(throwing: CancellationError())
	}
}

private actor RecoveringResourceTransport: OAuth2Transport {
	private(set) var refreshCount = 0

	func data(for request: URLRequest) async throws -> OAuth2HTTPResponse {
		if request.url?.host == "auth.example.com" {
			refreshCount += 1
			return .tokenSuccess
		}
		let authorization = request.value(forHTTPHeaderField: "Authorization") ?? ""
		return OAuth2HTTPResponse(
			data: Data(),
			statusCode: authorization.contains("new-access-token") ? 200 : 401,
			url: request.url
		)
	}
}

private actor ParallelRefreshTransport: OAuth2Transport {
	private(set) var maximumConcurrentRequests = 0
	private var activeRequests = 0
	private var requestCount = 0
	private var responseContinuations = [CheckedContinuation<Void, Never>]()
	private var requestCountWaiters = [(count: Int, continuation: CheckedContinuation<Void, Never>)]()

	func data(for request: URLRequest) async throws -> OAuth2HTTPResponse {
		requestCount += 1
		activeRequests += 1
		maximumConcurrentRequests = max(maximumConcurrentRequests, activeRequests)
		let readyWaiters = requestCountWaiters.filter { requestCount >= $0.count }
		requestCountWaiters.removeAll { requestCount >= $0.count }
		for waiter in readyWaiters {
			waiter.continuation.resume()
		}
		await withCheckedContinuation { continuation in
			responseContinuations.append(continuation)
		}
		activeRequests -= 1
		return .tokenSuccess
	}

	func waitForRequestCount(_ count: Int) async {
		guard requestCount < count else { return }
		await withCheckedContinuation { continuation in
			requestCountWaiters.append((count, continuation))
		}
	}

	func completeAll() {
		let continuations = responseContinuations
		responseContinuations.removeAll()
		for continuation in continuations {
			continuation.resume()
		}
	}
}

private actor AuthorizationHeaderTransport: OAuth2Transport {
	private(set) var authorizationHeader: String?

	func data(for request: URLRequest) async throws -> OAuth2HTTPResponse {
		authorizationHeader = request.value(forHTTPHeaderField: "Authorization")
		return .tokenSuccess
	}
}

private actor RejectingResourceTransport: OAuth2Transport {
	private(set) var refreshCount = 0
	private(set) var resourceCount = 0

	func data(for request: URLRequest) async throws -> OAuth2HTTPResponse {
		if request.url?.host == "auth.example.com" {
			refreshCount += 1
			return .tokenSuccess
		}
		resourceCount += 1
		return OAuth2HTTPResponse(data: Data(), statusCode: 401, url: request.url)
	}
}

private actor AuthorizationTransport: OAuth2Transport {
	private(set) var exchangeCount = 0
	private(set) var tokenRequest: URLRequest?

	func data(for request: URLRequest) async throws -> OAuth2HTTPResponse {
		exchangeCount += 1
		tokenRequest = request
		return .tokenSuccess
	}
}

private actor DeviceAuthorizationTransport: OAuth2Transport {
	private(set) var pollCount = 0

	func data(for request: URLRequest) async throws -> OAuth2HTTPResponse {
		if request.url?.path == "/device" {
			return OAuth2HTTPResponse(
				data: Data(#"{"device_code":"device-code","user_code":"ABCD-EFGH","verification_uri":"https://auth.example.com/verify","verification_uri_complete":"https://auth.example.com/verify?code=ABCD-EFGH","expires_in":900,"interval":5,"tenant":"tenant-value"}"#.utf8),
				statusCode: 200,
				url: request.url
			)
		}

		pollCount += 1
		switch pollCount {
		case 1:
			return OAuth2HTTPResponse(
				data: Data(#"{"error":"authorization_pending"}"#.utf8),
				statusCode: 400,
				url: request.url
			)
		case 2:
			return OAuth2HTTPResponse(
				data: Data(#"{"error":"slow_down"}"#.utf8),
				statusCode: 400,
				url: request.url
			)
		default:
			return .tokenSuccess
		}
	}
}

private actor RecordingSleeper: OAuth2Sleeper {
	private(set) var intervals = [TimeInterval]()

	func sleep(for interval: TimeInterval) {
		intervals.append(interval)
	}
}

private actor ControllableTokenMutationTransport: OAuth2Transport {
	private(set) var requestCount = 0
	private(set) var maximumConcurrentRequests = 0
	private var activeRequests = 0
	private var responseContinuation: CheckedContinuation<Void, Never>?
	private var startedWaiters = [CheckedContinuation<Void, Never>]()

	func data(for request: URLRequest) async throws -> OAuth2HTTPResponse {
		requestCount += 1
		activeRequests += 1
		maximumConcurrentRequests = max(maximumConcurrentRequests, activeRequests)
		let waiters = startedWaiters
		startedWaiters.removeAll()
		for waiter in waiters {
			waiter.resume()
		}
		await withCheckedContinuation { continuation in
			responseContinuation = continuation
		}
		activeRequests -= 1
		return .tokenSuccess
	}

	func waitUntilStarted() async {
		guard requestCount == 0 else { return }
		await withCheckedContinuation { continuation in
			startedWaiters.append(continuation)
		}
	}

	func complete() {
		responseContinuation?.resume()
		responseContinuation = nil
	}
}

private actor TokenExchangeTransport: OAuth2Transport {
	private(set) var requestBodies = [String]()

	func data(for request: URLRequest) async throws -> OAuth2HTTPResponse {
		let body = request.httpBody.flatMap { String(data: $0, encoding: .utf8) } ?? ""
		requestBodies.append(body)
		if body.contains("requested_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Arefresh_token") {
			return OAuth2HTTPResponse(
				data: Data(#"{"access_token":"audience-refresh","refresh_token":"rotated-subject-refresh","token_type":"Bearer"}"#.utf8),
				statusCode: 200,
				url: request.url
			)
		}
		return OAuth2HTTPResponse(
			data: Data(#"{"access_token":"resource-access","token_type":"Bearer","expires_in":3600}"#.utf8),
			statusCode: 200,
			url: request.url
		)
	}
}

private actor DynamicRegistrationTransport: OAuth2Transport {
	private(set) var tokenRequestBody = ""

	func data(for request: URLRequest) async throws -> OAuth2HTTPResponse {
		if request.url?.path == "/register" {
			return OAuth2HTTPResponse(
				data: Data(#"{"client_id":"dynamic-client","client_secret":"dynamic-secret","token_endpoint_auth_method":"client_secret_post","tenant":"tenant-value"}"#.utf8),
				statusCode: 201,
				url: request.url
			)
		}
		tokenRequestBody = request.httpBody.flatMap { String(data: $0, encoding: .utf8) } ?? ""
		return .tokenSuccess
	}
}

private actor PasswordGrantTransport: OAuth2Transport {
	private(set) var authorizationHeader: String?
	private(set) var requestBody = ""

	func data(for request: URLRequest) async throws -> OAuth2HTTPResponse {
		authorizationHeader = request.value(forHTTPHeaderField: "Authorization")
		requestBody = request.httpBody.flatMap { String(data: $0, encoding: .utf8) } ?? ""
		return OAuth2HTTPResponse(
			data: Data("access_token=form%2Btoken&provider_field=bar+baz".utf8),
			statusCode: 200,
			url: request.url
		)
	}
}

@MainActor
private final class ImmediateAuthorizationPresenter: OAuth2AuthorizationPresenter {
	private let redirectURI: URL
	private let stateOverride: String?
	private(set) var presentationCount = 0

	init(redirectURI: URL, stateOverride: String? = nil) {
		self.redirectURI = redirectURI
		self.stateOverride = stateOverride
	}

	func authorize(_ request: OAuth2AuthorizationPresentationRequest) async throws -> URL {
		presentationCount += 1
		let queryItems = URLComponents(url: request.authorizationURL, resolvingAgainstBaseURL: false)?.queryItems ?? []
		let state = stateOverride ?? queryItems.first(where: { $0.name == "state" })?.value
		var components = URLComponents(url: redirectURI, resolvingAgainstBaseURL: false)!
		components.queryItems = [
			URLQueryItem(name: "code", value: "authorization-code"),
			URLQueryItem(name: "state", value: state),
		]
		return components.url!
	}

	func cancel() {}
}

@MainActor
private final class ImmediateImplicitPresenter: OAuth2AuthorizationPresenter {
	private let redirectURI: URL
	private let location: OAuth2ImplicitResponseLocation

	init(redirectURI: URL, location: OAuth2ImplicitResponseLocation) {
		self.redirectURI = redirectURI
		self.location = location
	}

	func authorize(_ request: OAuth2AuthorizationPresentationRequest) async throws -> URL {
		let queryItems = URLComponents(url: request.authorizationURL, resolvingAgainstBaseURL: false)?.queryItems ?? []
		let state = queryItems.first(where: { $0.name == "state" })?.value ?? ""
		let response = "access_token=implicit-token&token_type=Bearer&expires_in=3600&state=\(state)&provider_field=provider-value"
		var components = URLComponents(url: redirectURI, resolvingAgainstBaseURL: false)!
		switch location {
		case .fragment:
			components.percentEncodedFragment = response
		case .query:
			components.percentEncodedQuery = response
		}
		return components.url!
	}

	func cancel() {}
}

@MainActor
private final class ControllableAuthorizationPresenter: OAuth2AuthorizationPresenter {
	private let redirectURI: URL
	private var request: OAuth2AuthorizationPresentationRequest?
	private var continuation: CheckedContinuation<URL, any Error>?
	private var startedWaiters = [CheckedContinuation<Void, Never>]()
	private(set) var cancelCount = 0

	init(redirectURI: URL) {
		self.redirectURI = redirectURI
	}

	func authorize(_ request: OAuth2AuthorizationPresentationRequest) async throws -> URL {
		self.request = request
		let waiters = startedWaiters
		startedWaiters.removeAll()
		for waiter in waiters {
			waiter.resume()
		}
		return try await withCheckedThrowingContinuation { continuation in
			self.continuation = continuation
		}
	}

	func cancel() {
		cancelCount += 1
		let continuation = continuation
		self.continuation = nil
		continuation?.resume(throwing: CancellationError())
	}

	func waitUntilStarted() async {
		guard request == nil else { return }
		await withCheckedContinuation { continuation in
			startedWaiters.append(continuation)
		}
	}

	func succeed() {
		guard let request, let continuation else { return }
		let queryItems = URLComponents(url: request.authorizationURL, resolvingAgainstBaseURL: false)?.queryItems ?? []
		let state = queryItems.first(where: { $0.name == "state" })?.value
		var components = URLComponents(url: redirectURI, resolvingAgainstBaseURL: false)!
		components.queryItems = [
			URLQueryItem(name: "code", value: "authorization-code"),
			URLQueryItem(name: "state", value: state),
		]
		self.continuation = nil
		continuation.resume(returning: components.url!)
	}
}

private actor ControllableRefreshTransport: OAuth2Transport {
	private(set) var refreshCount = 0
	private var responseContinuation: CheckedContinuation<OAuth2HTTPResponse, Never>?
	private var startedWaiters = [CheckedContinuation<Void, Never>]()

	func data(for request: URLRequest) async throws -> OAuth2HTTPResponse {
		refreshCount += 1
		let waiters = startedWaiters
		startedWaiters.removeAll()
		for waiter in waiters {
			waiter.resume()
		}
		return await withCheckedContinuation { continuation in
			responseContinuation = continuation
		}
	}

	func waitUntilStarted() async {
		guard refreshCount == 0 else { return }
		await withCheckedContinuation { continuation in
			startedWaiters.append(continuation)
		}
	}

	func complete() {
		responseContinuation?.resume(returning: .tokenSuccess)
		responseContinuation = nil
	}
}

private extension OAuth2HTTPResponse {
	static let tokenSuccess = OAuth2HTTPResponse(
		data: Data(#"{"access_token":"new-access-token","refresh_token":"rotated-refresh-token","token_type":"Bearer","expires_in":3600}"#.utf8),
		statusCode: 200,
		url: URL(string: "https://auth.example.com/token")
	)
}
