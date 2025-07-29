//
//  OAuth2.swift
//  OAuth2
//
//  Created by Pascal Pfiffner on 6/4/14.
//  Copyright 2014 Pascal Pfiffner
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.
//

import Foundation
import Semaphore

#if !NO_MODULE_IMPORT
 import Base
 import Constants
 #if os(macOS)
  import macOS
 #elseif os(iOS) || os(visionOS)
  import iOS
 #elseif os(tvOS)
  import tvOS
 #endif
#endif


/**
Base class for specific OAuth2 flow implementations.
*/
open class OAuth2: OAuth2Base {
	
	/// Whether the flow type mandates client identification.
	open class var clientIdMandatory: Bool {
		return true
	}
	
	/// If non-nil, will be called before performing dynamic client registration, giving you a chance to instantiate your own registrar.
	public final var onBeforeDynamicClientRegistration: ((URL) -> OAuth2DynReg?)?
	
	/// The authorizer to use for UI handling, depending on platform.
	open var authorizer: OAuth2AuthorizerUI!
	
	/// The semaphore preventing concurrent execution of any function that could rotate the refresh token.
	private var refreshTokenRotationSemaphore: AsyncSemaphore?
	
	
	/**
	Designated initializer.
	
	The following settings keys are currently supported:
	
	- client_id (String)
	- client_secret (String), usually only needed for code grant
	- authorize_uri (URL-String)
	- token_uri (URL-String), if omitted the authorize_uri will be used to obtain tokens
	- refresh_uri (URL-String), if omitted the token_uri will be used to obtain tokens
	- redirect_uris (Array of URL-Strings)
	- scope (String)
	
	- client_name (String)
	- registration_uri (URL-String)
	- logo_uri (URL-String)
	
	- keychain (Bool, true by default, applies to using the system keychain)
	- keychain_access_mode (String, value for keychain kSecAttrAccessible attribute, kSecAttrAccessibleWhenUnlocked by default)
	- keychain_access_group (String, value for keychain kSecAttrAccessGroup attribute, nil by default)
	- keychain_account_for_client_credentials(String, "clientCredentials" by default)
	- keychain_account_for_tokens(String, "currentTokens" by default)
	- secret_in_body (Bool, false by default, forces the flow to use the request body for the client secret)
	- parameters ([String: String], custom request parameters to be added during authorization)
	- token_assume_unexpired (Bool, true by default, whether to use access tokens that do not come with an "expires_in" parameter)
	- use_pkce (Bool, false by default)
	
	- verbose (bool, false by default, applies to client logging)
	*/
	override public init(settings: OAuth2JSON) {
		super.init(settings: settings)
		self.authorizer = OAuth2Authorizer(oauth2: self)
		
		if (self.clientConfig.refreshTokenRotationIsEnabled) {
			self.refreshTokenRotationSemaphore = AsyncSemaphore(value: 1)
		}
	}
	
	
	// MARK: - Authorization
	
	/**
	Use this method to obtain an access token. Take a look at `authConfig` on how to configure how authorization is presented to the user.
	
	This method is running asynchronously and can only be run one at a time.
	
	This method will first check if the client already has an unexpired access token (possibly from the keychain), if not and it's able to
	use a refresh token it will try to use the refresh token. If this fails it will check whether the client has a client_id and show the
	authorize screen if you have `authConfig` set up sufficiently. If `authConfig` is not set up sufficiently this method will end up
	calling the callback with a failure. If client_id is not set but a "registration_uri" has been provided, a dynamic client registration
	will be attempted and if it success, an access token will be requested.
	
	- parameter params: Optional key/value pairs to pass during authorization and token refresh
	- returns: JSON dictionary or nil
	*/
	public final func authorize(params: OAuth2StringDict? = nil) async throws -> OAuth2JSON? {
		guard !self.isAuthorizing else {
			throw OAuth2Error.alreadyAuthorizing
		}
		
		self.isAuthorizing = true
		logger?.debug("OAuth2", msg: "Starting authorization")
		
		do {
			if let successParams = try await tryToObtainAccessTokenIfNeeded(params: params) {
				self.didAuthorize(withParameters: successParams)
				return successParams
			}
			
			_ = try await self.registerClientIfNeeded()
			return try await self.doAuthorize(params: params)
			
		} catch {
			self.didFail(with: error.asOAuth2Error)
			throw error.asOAuth2Error
		}
	}

	/**
	If the instance has an accessToken, checks if its expiry time has not yet passed. If we don't have an expiry date we assume the token
	is still valid.
	
	- returns: A Bool indicating whether a probably valid access token exists
	*/
	open func hasUnexpiredAccessToken() -> Bool {
		guard let access = accessToken, !access.isEmpty else {
			return false
		}
		if let expiry = accessTokenExpiry {
			return (.orderedDescending == expiry.compare(Date()))
		}
		return clientConfig.accessTokenAssumeUnexpired
	}
	
	/**
	Attempts to receive a new access token by:
	
	1. checking if there still is an unexpired token
	2. attempting to use a refresh token
	
	Indicates, in the callback, whether the client has been able to obtain an access token that is likely to still work (but there is no
	guarantee!) or not.
	
	- parameter params: Optional key/value pairs to pass during authorization
	- returns: TODO
	*/
	open func tryToObtainAccessTokenIfNeeded(params: OAuth2StringDict? = nil) async throws -> OAuth2JSON? {
		if hasUnexpiredAccessToken() {
			logger?.debug("OAuth2", msg: "Have an apparently unexpired access token")
			return OAuth2JSON()
		}
		else {
			logger?.debug("OAuth2", msg: "No access token, checking if a refresh token is available")
			do {
				return try await self.doRefreshToken(params: params)
			} catch {
				self.logger?.debug("OAuth2", msg: "Error refreshing token: \(error)")
			
				switch error.asOAuth2Error {
				case .noRefreshToken, .noClientId, .unauthorizedClient:
					return nil
				default:
					throw error
				}
			}
		}
	}
	
	/**
	Method to actually start authorization. The public `authorize()` method only proceeds to this method if there is no valid access token
	and if optional client registration succeeds.
	
	Can be overridden in subclasses to perform an authorization dance different from directing the user to a website.
	
	- parameter params: Optional key/value pairs to pass during authorization
	*/
	open func doAuthorize(params: OAuth2StringDict? = nil) async throws -> OAuth2JSON? {
		return try await withCheckedThrowingContinuation { continuation in
			Task {
				do {
					if authConfig.authorizeEmbedded {
						try await doAuthorizeEmbedded(with: authConfig, params: params)
					}
					else {
						try doOpenAuthorizeURLInBrowser(params: params)
					}
					self.doAuthorizeContinuation = continuation
				} catch {
					continuation.resume(throwing: error)
				}
			}
		}
	}
	
	/**
	Open the authorize URL in the OS's browser. Forwards to the receiver's `authorizer`, which is a platform-dependent implementation of
	`OAuth2AuthorizerUI`.
	
	- parameter params: Additional parameters to pass to the authorize URL
	- throws: UnableToOpenAuthorizeURL on failure
	*/
	final func doOpenAuthorizeURLInBrowser(params: OAuth2StringDict? = nil) throws {
		let url = try authorizeURL(params: params)
		logger?.debug("OAuth2", msg: "Opening authorize URL in system browser: \(url)")
		try authorizer.openAuthorizeURLInBrowser(url)
	}
	
	/**
	Tries to use the current auth config context, which on iOS should be a UIViewController and on OS X a NSViewController, to present the
	authorization screen. Set `oauth2.authConfig.authorizeContext` accordingly.
	
	Forwards to the receiver's `authorizer`, which is a platform-dependent implementation of `OAuth2AuthorizerUI`.
	
	- throws:           Can throw OAuth2Error if the method is unable to show the authorize screen
	- parameter with:   The configuration to be used; usually uses the instance's `authConfig`
	- parameter params: Additional authorization parameters to supply during the OAuth dance
	*/
	final func doAuthorizeEmbedded(with config: OAuth2AuthConfig, params: OAuth2StringDict? = nil) async throws {
		let url = try authorizeURL(params: params)
		logger?.debug("OAuth2", msg: "Opening authorize URL embedded: \(url)")
		try await authorizer.authorizeEmbedded(with: config, at: url)
	}
	
	/**
	Method that creates the OAuth2AuthRequest instance used to create the authorize URL
	
	- parameter redirect: The redirect URI string to supply. If it is nil, the first value of the settings' `redirect_uris` entries is
						  used. Must be present in the end!
	- parameter scope:    The scope to request
	- parameter params:   Any additional parameters as dictionary with string keys and values that will be added to the query part
	- returns:            OAuth2AuthRequest to be used to call to the authorize endpoint
	*/
	func authorizeRequest(withRedirect redirect: String, scope: String?, params: OAuth2StringDict?) throws -> OAuth2AuthRequest {
		let clientId = clientConfig.clientId
		if type(of: self).clientIdMandatory && (nil == clientId || clientId!.isEmpty) {
			throw OAuth2Error.noClientId
		}
		
		let req = OAuth2AuthRequest(url: clientConfig.authorizeURL, method: .GET)
		req.params["redirect_uri"] = redirect
		req.params["state"] = context.state
		if let clientId = clientId {
			req.params["client_id"] = clientId
		}
		if let responseType = type(of: self).responseType {
			req.params["response_type"] = responseType
		}
		if let scope = scope ?? clientConfig.scope {
			req.params["scope"] = scope
		}
		if clientConfig.safariCancelWorkaround {
			req.params["swa"] = "\(Date.timeIntervalSinceReferenceDate)" // Safari issue workaround
		}
		if clientConfig.useProofKeyForCodeExchange {
			context.generateCodeVerifier()
			req.params["code_challenge"] = context.codeChallenge()
			req.params["code_challenge_method"] = context.codeChallengeMethod
		}
		req.add(params: params)
		
		return req
	}
	
	/**
	Most convenient method if you want the authorize URL to be created as defined in your settings dictionary.
	
	- parameter params: Optional, additional URL params to supply to the request
	- returns:          NSURL to be used to start the OAuth dance
	*/
	open func authorizeURL(params: OAuth2StringDict? = nil) throws -> URL {
		return try authorizeURL(withRedirect: nil, scope: nil, params: params)
	}
	
	/**
	Convenience method to be overridden by and used from subclasses.
	
	- parameter redirect: The redirect URI string to supply. If it is nil, the first value of the settings' `redirect_uris` entries is
						  used. Must be present in the end!
	- parameter scope:    The scope to request
	- parameter params:   Any additional parameters as dictionary with string keys and values that will be added to the query part
	- returns:            NSURL to be used to start the OAuth dance
	*/
	open func authorizeURL(withRedirect redirect: String?, scope: String?, params: OAuth2StringDict?) throws -> URL {
		guard let redirect = (redirect ?? clientConfig.redirect) else {
			throw OAuth2Error.noRedirectURL
		}
		let req = try authorizeRequest(withRedirect: redirect, scope: scope, params: params)
		context.redirectURL = redirect
		return try req.asURL()
	}
	
	
	// MARK: - Refresh Token
	
	/**
	Generate the request to be used for token refresh when we have a refresh token.
	
	This will set "grant_type" to "refresh_token", add the refresh token, and take care of the remaining parameters.
	
	- parameter params: Additional parameters to pass during token refresh
	- returns:          An `OAuth2AuthRequest` instance that is configured for token refresh
	*/
	open func tokenRequestForTokenRefresh(params: OAuth2StringDict? = nil) throws -> OAuth2AuthRequest {
		let clientId = clientConfig.clientId
		if type(of: self).clientIdMandatory && (nil == clientId || clientId!.isEmpty) {
			throw OAuth2Error.noClientId
		}
		guard let refreshToken = clientConfig.refreshToken, !refreshToken.isEmpty else {
			throw OAuth2Error.noRefreshToken
		}
		
		let req = OAuth2AuthRequest(url: (clientConfig.refreshURL ?? clientConfig.tokenURL ?? clientConfig.authorizeURL))
		req.params["grant_type"] = OAuth2GrantTypes.refreshToken
		req.params["refresh_token"] = refreshToken
		if let clientId = clientId {
			req.params["client_id"] = clientId
		}
		if let resourceURIs = clientConfig.resourceURIs {
			req.params.setMultiple(key: "resource", values: resourceURIs)
		}
		req.add(params: params)
		
		return req
	}
	
	/**
	If there is a refresh token, use it to receive a fresh access token.
	
	If the request returns an error, the refresh token is thrown away.
	
	- parameter params:   Optional key/value pairs to pass during token refresh
	- returns: OAuth2 JSON dictionary
	*/
	open func doRefreshToken(params: OAuth2StringDict? = nil) async throws -> OAuth2JSON {
		/// Wait for all running rotations to finish
		await self.refreshTokenRotationSemaphore?.wait()
		defer {
			self.refreshTokenRotationSemaphore?.signal()
		}
		
		do {
			let post = try tokenRequestForTokenRefresh(params: params).asURLRequest(for: self)
			logger?.debug("OAuth2", msg: "Using refresh token to receive access token from \(post.url?.description ?? "nil")")
			
			let response = await perform(request: post)
			let data = try response.responseData()
			let json = try self.parseRefreshTokenResponseData(data)
			if response.response.statusCode >= 400 {
				self.clientConfig.refreshToken = nil
				throw OAuth2Error.generic("Failed with status \(response.response.statusCode)")
			}
			self.logger?.debug("OAuth2", msg: "Did use refresh token for access token [\(nil != self.clientConfig.accessToken)]")
			if (self.useKeychain) {
				self.storeTokensToKeychain()
			}
			
			return json
		}
		catch {
			throw error.asOAuth2Error
		}
	}
	
	// MARK: - Exchange Refresh Token
	
	/**
	Generate the request to be used for token exchange when we have a refresh token.
	
	This will set "grant_type" to "urn:ietf:params:oauth:grant-type:token-exchange", add the refresh token, and take care of the remaining parameters.
	
	- parameter audienceClientId: The client ID of the audience requesting for its own refresh token
	- parameter params:           Additional parameters to pass during refresh token exchange
	- returns:                    An `OAuth2AuthRequest` instance that is configured for refresh token exchange
	*/
	open func tokenRequestForExchangeRefreshToken(audienceClientId: String, params: OAuth2StringDict? = nil) throws -> OAuth2AuthRequest {
		guard let refreshToken = clientConfig.refreshToken, !refreshToken.isEmpty else {
			throw OAuth2Error.noRefreshToken
		}

		let req = OAuth2AuthRequest(url: (clientConfig.tokenURL ?? clientConfig.authorizeURL))
		req.params["grant_type"] = OAuth2GrantTypes.tokenExchange
		req.params["audience"] = audienceClientId
		req.params["requested_token_type"] = OAuth2TokenTypeIdentifiers.refreshToken
		req.params["subject_token"] = refreshToken
		req.params["subject_token_type"] = OAuth2TokenTypeIdentifiers.refreshToken
		req.add(params: params)

		return req
	}
	
	/**
	Exchanges the subject's refresh token for audience client.
	see: https://datatracker.ietf.org/doc/html/rfc8693
	see: https://www.scottbrady91.com/oauth/delegation-patterns-for-oauth-20
	- parameter audienceClientId: The client ID of the audience requesting for its own refresh token
	- parameter traceId: Unique identifier for debugging purposes.
	- parameter params: Optional key/value pairs to pass during token exchange
	- returns: Exchanged refresh token
	*/
	open func doExchangeRefreshToken(audienceClientId: String, traceId: String, params: OAuth2StringDict? = nil) async throws -> String {
		/// Wait for all running rotations to finish
		await self.refreshTokenRotationSemaphore?.wait()
		defer {
			self.refreshTokenRotationSemaphore?.signal()
		}
		
		debugPrint("[doExchangeRefreshToken] Started for \(audienceClientId)")

		do {
			let post = try tokenRequestForExchangeRefreshToken(audienceClientId: audienceClientId, params: params).asURLRequest(for: self)
			logger?.debug("OAuth2", msg: "Exchanging refresh token for client with ID \(audienceClientId) from \(post.url?.description ?? "nil") [trace=\(traceId)]")

			let response = await perform(request: post)
			let data = try response.responseData()
			let json = try self.parseExchangeRefreshTokenResponseData(data)
			if response.response.statusCode >= 400 {
				self.clientConfig.refreshToken = nil
				throw OAuth2Error.generic("Failed with status \(response.response.statusCode)")
			}
			
			/// The `access_token` field contains the `requested_token_type` = the exchanged (audience) refresh token in our case.
			///
			/// **Explanation:**
			/// The security token issued by the authorization server in response to the token exchange request. The access_token parameter
			/// from Section 5.1 of [RFC6749] is used here to carry the requested token, which allows this token exchange protocol to use the
			/// existing OAuth 2.0 request and response constructs defined for the token endpoint.
			/// **The identifier access_token is used for historical reasons and the issued token need not be an OAuth access token.**
			/// See: https://tools.ietf.org/id/draft-ietf-oauth-token-exchange-12.html#rfc.section.2.2.1
			guard let exchangedRefreshToken = json["access_token"] as? String else {
				throw OAuth2Error.generic("Exchange refresh token didn't return exchanged refresh token (response.access_token) [trace=\(traceId)]")
			}
			self.logger?.debug("OAuth2", msg: "Did use refresh token for exchanging refresh token [trace=\(traceId)]")
			self.logger?.trace("OAuth2", msg: "Exchanged refresh token in [trace=\(traceId)] is [\(exchangedRefreshToken)]")
			if self.useKeychain {
				self.storeTokensToKeychain()
			}
			debugPrint("[doExchangeRefreshToken] Ended for \(audienceClientId)")
			return exchangedRefreshToken
		} catch {
			self.logger?.debug("OAuth2", msg: "Error exchanging refresh in [trace=\(traceId)] token: \(error)")
			throw error.asOAuth2Error
		}
	}
	
	// MARK: - Exchange Access Token For Resource

	/**
	Generate the request to be used for token exchange for resource when we have a access token.

	This will set "grant_type" to "urn:ietf:params:oauth:grant-type:token-exchange", add the access token, and take care of the remaining parameters.

	- parameter params:           Additional parameters to pass during resource access token exchange
	- returns:                    An `OAuth2AuthRequest` instance that is configured for resource access token exchange
	*/
	open func tokenRequestForExchangeAccessTokenForResource(params: OAuth2StringDict? = nil) throws -> OAuth2AuthRequest {
		guard let accessToken = clientConfig.accessToken, !accessToken.isEmpty else {
			throw OAuth2Error.noAccessToken
		}
		guard let resourceURIs = clientConfig.resourceURIs, !resourceURIs.isEmpty else {
			throw OAuth2Error.noResourceURI
		}

		let req = OAuth2AuthRequest(url: (clientConfig.tokenURL ?? clientConfig.authorizeURL))
		req.params["grant_type"] = OAuth2GrantTypes.tokenExchange
		req.params.setMultiple(key: "resource", values: resourceURIs)
		req.params["scope"] = clientConfig.scope
		req.params["requested_token_type"] = OAuth2TokenTypeIdentifiers.accessToken
		req.params["subject_token"] = accessToken
		req.params["subject_token_type"] = OAuth2TokenTypeIdentifiers.accessToken
		req.add(params: params)

		return req
	}
	
	/**
	Exchanges the access token for resource access token.

	- parameter params: Optional key/value pairs to pass during token exchange
	- returns: Exchanged access token
	*/
	open func doExchangeAccessTokenForResource(params: OAuth2StringDict? = nil) async throws -> String {
		/// Wait for all running rotations to finish
		await self.refreshTokenRotationSemaphore?.wait()
		defer {
			self.refreshTokenRotationSemaphore?.signal()
		}
		
		do {
			guard let resourceURIs = clientConfig.resourceURIs, !resourceURIs.isEmpty else {
				throw OAuth2Error.noResourceURI
			}
			
			let post = try tokenRequestForExchangeAccessTokenForResource(params: params).asURLRequest(for: self)
			logger?.debug("OAuth2", msg: "Exchanging access token for resource(s) \(resourceURIs) from \(post.url?.description ?? "nil")")

			let response = await perform(request: post)
			let data = try response.responseData()
			let json = try self.parseAccessTokenResponse(data: data)
			if response.response.statusCode >= 400 {
				self.clientConfig.accessToken = nil
				throw OAuth2Error.generic("Failed with status \(response.response.statusCode)")
			}
			guard let exchangedAccessToken = json["access_token"] as? String else {
				throw OAuth2Error.generic("Exchange access token for resource didn't return exchanged access token (response.access_token)")
			}
			return exchangedAccessToken
		} catch let error {
			self.logger?.debug("OAuth2", msg: "Error exchanging access token for resource(s): \(error)")
			throw error.asOAuth2Error
		}
	}
	
	// MARK: - Registration
	
	/**
	Use OAuth2 dynamic client registration to register the client, if needed.
	
	Returns immediately if the receiver's `clientId` is nil (with error = nil) or if there is no registration URL (with error). Otherwise
	calls `onBeforeDynamicClientRegistration()` -- if it is non-nil -- and uses the returned `OAuth2DynReg` instance -- if it is non-nil.
	If both are nil, instantiates a blank `OAuth2DynReg` instead, then attempts client registration.
	
	- returns: JSON dictionary or nil if no registration was attempted;
	*/
	public func registerClientIfNeeded() async throws -> OAuth2JSON? {
		if nil != clientId || !type(of: self).clientIdMandatory {
			return nil
		}
		else if let url = clientConfig.registrationURL {
			let dynreg = onBeforeDynamicClientRegistration?(url as URL) ?? OAuth2DynReg()
			return try await dynreg.register(client: self)
		}
		else {
			throw OAuth2Error.noRegistrationURL
		}
	}
}
