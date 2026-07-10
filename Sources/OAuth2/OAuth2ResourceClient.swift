import Foundation

/// Executes OAuth-protected resource requests without serializing unrelated network work.
public struct OAuth2ResourceClient: Sendable {
	private let client: OAuth2Client
	private let transport: any OAuth2Transport
	private let unauthorizedStatusCodes: Set<Int>

	public init(
		client: OAuth2Client,
		transport: any OAuth2Transport = URLSessionOAuth2Transport(),
		unauthorizedStatusCodes: Set<Int> = [401]
	) {
		self.client = client
		self.transport = transport
		self.unauthorizedStatusCodes = unauthorizedStatusCodes
	}

	/// Performs one request and at most one generation-aware headless recovery attempt.
	public func data(for request: URLRequest) async throws -> OAuth2HTTPResponse {
		let initialSnapshot = try await client.validAccessToken()
		let initialResponse = try await transport.data(for: signed(request, with: initialSnapshot))
		guard unauthorizedStatusCodes.contains(initialResponse.statusCode) else {
			return initialResponse
		}

		let recoveredSnapshot = try await client.recoverAfterUnauthorized(initialSnapshot)
		let recoveredResponse = try await transport.data(for: signed(request, with: recoveredSnapshot))
		guard !unauthorizedStatusCodes.contains(recoveredResponse.statusCode) else {
			throw OAuth2ClientError.unauthorized(statusCode: recoveredResponse.statusCode)
		}
		return recoveredResponse
	}

	private func signed(_ request: URLRequest, with snapshot: OAuth2TokenSnapshot) -> URLRequest {
		var request = request
		request.setValue("Bearer \(snapshot.tokenSet.accessToken)", forHTTPHeaderField: "Authorization")
		return request
	}
}
