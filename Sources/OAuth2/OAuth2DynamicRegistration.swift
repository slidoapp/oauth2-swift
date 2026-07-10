import Foundation

enum OAuth2DynamicRegistrationEndpoint {
	static func register(
		_ registration: OAuth2ClientRegistration,
		configuration: OAuth2ClientConfiguration,
		transport: any OAuth2Transport
	) async throws -> OAuth2ClientRegistrationResponse {
		guard let endpoint = configuration.registrationEndpoint else {
			throw OAuth2ClientError.missingRegistrationEndpoint
		}

		var values = registration.additionalParameters
		if let clientName = registration.clientName {
			values["client_name"] = .string(clientName)
		}
		if !registration.redirectURIs.isEmpty {
			values["redirect_uris"] = .array(registration.redirectURIs.map { .string($0.absoluteString) })
		}
		values["grant_types"] = .array(registration.grantTypes.map(JSONValue.string))
		values["response_types"] = .array(registration.responseTypes.map(JSONValue.string))
		values["token_endpoint_auth_method"] = .string(authenticationMethodName(configuration.clientAuthentication))

		var request = URLRequest(url: endpoint)
		request.httpMethod = "POST"
		request.setValue("application/json", forHTTPHeaderField: "Accept")
		request.setValue("application/json; charset=utf-8", forHTTPHeaderField: "Content-Type")
		request.httpBody = try JSONEncoder().encode(values)

		let response = try await transport.data(for: request)
		var responseValues = (try? JSONDecoder().decode([String: JSONValue].self, from: response.data)) ?? [:]
		guard (200..<300).contains(response.statusCode) else {
			throw OAuth2ClientError.authorizationServer(
				code: responseValues["error"]?.stringValue,
				description: responseValues["error_description"]?.stringValue,
				statusCode: response.statusCode
			)
		}
		guard let clientID = responseValues.removeValue(forKey: "client_id")?.stringValue, !clientID.isEmpty else {
			throw OAuth2ClientError.invalidTokenResponse("The registration response does not contain client_id")
		}
		let clientSecret = responseValues.removeValue(forKey: "client_secret")?.stringValue
		let method = responseValues.removeValue(forKey: "token_endpoint_auth_method")?.stringValue.flatMap(authenticationMethod)
		return OAuth2ClientRegistrationResponse(
			credentials: OAuth2ClientCredentials(
				clientID: clientID,
				clientSecret: clientSecret,
				authenticationMethod: method
			),
			additionalParameters: responseValues
		)
	}

	private static func authenticationMethodName(_ method: OAuth2ClientAuthentication) -> String {
		switch method {
		case .none:
			return "none"
		case .clientSecretBasic:
			return "client_secret_basic"
		case .clientSecretPost:
			return "client_secret_post"
		}
	}

	private static func authenticationMethod(_ value: String) -> OAuth2ClientAuthentication? {
		switch value {
		case "none":
			return OAuth2ClientAuthentication.none
		case "client_secret_basic":
			return .clientSecretBasic
		case "client_secret_post":
			return .clientSecretPost
		default:
			return nil
		}
	}
}
