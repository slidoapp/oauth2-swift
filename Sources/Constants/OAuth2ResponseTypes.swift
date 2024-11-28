public enum OAuth2ResponseTypes {
	public static let code = "code"
	public static let token = "token"
	
	/**
	When supplied as the `response_type` parameter in an OAuth 2.0 Authorization Request, a successful response MUST
	include the parameter `id_token`. The Authorization Server SHOULD NOT return an OAuth 2.0 Authorization Code, Access
	Token, or Access Token Type in a successful response to the grant request. If a `redirect_uri` is supplied, the User
	Agent SHOULD be redirected there after granting or denying access. The request MAY include a `state` parameter, and if
	so, the Authorization Server MUST echo its value as a response parameter when issuing either a successful response or
	an error response. The default Response Mode for this Response Type is the fragment encoding and the query encoding
	MUST NOT be used. Both successful and error responses SHOULD be returned using the supplied Response Mode, or if none
	is supplied, using the default Response Mode.
	*/
	public static let idToken = "id_token"
	
	/**
	When supplied as the value for the `response_type` parameter, a successful response MUST include an Access Token, an
	Access Token Type, and an `id_token`. The default Response Mode for this Response Type is the fragment encoding and the
	query encoding MUST NOT be used. Both successful and error responses SHOULD be returned using the supplied Response
	Mode, or if none is supplied, using the default Response Mode.
	*/
	public static let idTokenToken = "id_token token"
	
	/**
	When supplied as the value for the `response_type` parameter, a successful response MUST include both an Authorization
	Code and an `id_token`. The default Response Mode for this Response Type is the fragment encoding and the query
	encoding MUST NOT be used. Both successful and error responses SHOULD be returned using the supplied Response Mode, or
	if none is supplied, using the default Response Mode.
	*/
	public static let codeIdToken = "code id_token"
	
	/**
	When supplied as the value for the `response_type` parameter, a successful response MUST include an Access Token, an
	Access Token Type, and an Authorization Code. The default Response Mode for this Response Type is the fragment
	encoding and the query encoding MUST NOT be used. Both successful and error responses SHOULD be returned using the
	supplied Response Mode, or if none is supplied, using the default Response Mode.
	*/
	public static let codeToken = "code token"
	
	/**
	When supplied as the value for the `response_type` parameter, a successful response MUST include an Authorization
	Code, an `id_token`, an Access Token, and an Access Token Type. The default Response Mode for this Response Type is
	the fragment encoding and the query encoding MUST NOT be used. Both successful and error responses SHOULD be returned
	using the supplied Response Mode, or if none is supplied, using the default Response Mode.
	*/
	public static let codeIdTokenToken = "code id_token token"
}
