public enum OAuth2GrantTypes {
	public static let password = "password"
	public static let authorizationCode = "authorization_code"
	public static let clientCredentials = "client_credentials"
	public static let refreshToken = "refresh_token"
	public static let implicit = "implicit"
	public static let saml2Bearer = "urn:ietf:params:oauth:grant-type:saml2-bearer"
	public static let jwtBearer = "urn:ietf:params:oauth:grant-type:jwt-bearer"
	public static let deviceCode = "urn:ietf:params:oauth:grant-type:device_code"
	public static let tokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange"
	public static let ciba = "urn:ietf:params:oauth:grant-type:ciba"
}
