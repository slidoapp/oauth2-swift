//
//  OAuth2ServerMetdadataModel.swift
//  OAuth2
//
//  Created by Dominik Paľo on 24/07/2025.
//  Copyright © 2025 Pascal Pfiffner. All rights reserved.
//


/// https://datatracker.ietf.org/doc/html/rfc8414#section-2
public struct OAuth2ServerMetadata: Decodable {
	
	/// The authorization server's issuer identifier, which is a URL that uses the "https" scheme and has no query or fragment components.
	public let issuer: String
	
	/// URL of the authorization server's authorization endpoint.
	public let authorizationEndpoint: String?
	
	/// URL of the authorization server's token endpoint.
	public let tokenEndpoint: String?
	
	/// URL of the authorization server's JWK Set document.
	public let jwksUri: String?
	
	/// URL of the authorization server's OAuth 2.0 Dynamic Client Registration endpoint.
	public let registrationEndpoint: String?
	
	/// OAuth 2.0 "scope" values that this authorization server supports.
	public let scopesSupported: [String]?
	
	/// OAuth 2.0 "response_type" values that this authorization server supports.
	public let responseTypesSupported: [String]
	
	/// OAuth 2.0 "response_mode" values that this authorization server supports, as specified in "OAuth 2.0 Multiple Response Type Encoding Practices"
	public let responseModesSupported: [String]?
	
	/// OAuth 2.0 grant type values that this authorization server supports.
	public let grantTypesSupported: [String]?
	
	/// Client authentication methods supported by this token endpoint.
	public let tokenEndpointAuthMethodsSupported: [String]?
	
	/// JWS signing algorithms ("alg" values) supported by the token endpoint for the signature on the JWT used to authenticate the client at the token endpoint for the "private_key_jwt" and "client_secret_jwt" authentication methods.
	public let tokenEndpointAuthSigningAlgValuesSupported: [String]?
	
	/// URL of a page containing human-readable information that developers might want or need to know when using the authorization server.
	public let serviceDocumentation: String?
	
	/// Languages and scripts supported for the user interface represented as an array of language tag values from BCP 47.
	public let uiLocalesSupported: [String]?
	
	/// URL that the authorization server provides to the person registering the client to read about the authorization server's requirements on how the client can use the data provided by the authorization server.
	public let opPolicyUri: String?
	
	/// URL that the authorization server provides to the person registering the client to read about the authorization server's terms of service.
	public let opTosUri: String?
	
	/// URL of the authorization server's OAuth 2.0 revocation endpoint.
	public let revocationEndpoint: String?
	
	/// Client authentication methods supported by this revocation endpoint.
	public let revocationEndpointAuthMethodsSupported: [String]?
	
	/// JWS signing algorithms ("alg" values) supported by the revocation endpoint for the signature on the JWT used to authenticate the client at the revocation endpoint for the "private_key_jwt" and "client_secret_jwt" authentication methods.
	public let revocationEndpointAuthSigningAlgValuesSupported: [String]?
	
	/// URL of the authorization server's OAuth 2.0 introspection endpoint.
	public let introspectionEndpoint: String?

	/// Client authentication methods supported by this introspection endpoint.
	public let introspectionEndpointAuthMethodsSupported: [String]?
	
	/// JWS signing algorithms ("alg" values) supported by the introspection endpoint for the signature on the JWT used to authenticate the client at the introspection endpoint for the "private_key_jwt" and "client_secret_jwt" authentication methods.
	public let introspectionEndpointAuthSigningAlgValuesSupported: [String]?
	
	/// Proof Key for Code Exchange (PKCE) code challenge methods supported by this authorization server.
	public let codeChallengeMethodsSupported: [String]?
}
