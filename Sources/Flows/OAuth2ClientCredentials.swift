//
//  OAuth2ClientCredentials.swift
//  OAuth2
//
//  Created by Pascal Pfiffner on 5/27/15.
//  Copyright 2015 Pascal Pfiffner
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

#if !NO_MODULE_IMPORT
import Base
import Constants
#endif


/**
Class to handle two-legged OAuth2 requests of the "client_credentials" type.
*/
open class OAuth2ClientCredentials: OAuth2 {
	
	override open class var grantType: String {
		return OAuth2GrantTypes.clientCredentials
	}
	
	override open func doAuthorize(params inParams: OAuth2StringDict? = nil) async throws -> OAuth2JSON? {
		do {
			let result = try await self.obtainAccessToken()
			self.didAuthorize(withParameters: result)
			return result
		} catch {
			self.didFail(with: error.asOAuth2Error)
			return nil
		}
	}
	
	/**
	Creates a POST request with x-www-form-urlencoded body created from the supplied URL's query part.
	*/
	open func accessTokenRequest(params: OAuth2StringDict? = nil) throws -> OAuth2AuthRequest {
		guard let clientId = clientConfig.clientId, !clientId.isEmpty else {
			throw OAuth2Error.noClientId
		}
		guard nil != clientConfig.clientSecret else {
			throw OAuth2Error.noClientSecret
		}
		
		let req = OAuth2AuthRequest(url: (clientConfig.tokenURL ?? clientConfig.authorizeURL))
		req.params["grant_type"] = type(of: self).grantType
		if let scope = clientConfig.scope {
			req.params["scope"] = scope
		}
		req.add(params: params)
		
		return req
	}
	
	/**
	Use the client credentials to retrieve a fresh access token.
	
	Uses `accessTokenRequest(params:)` to create the request, which you can subclass to change implementation specifics.
	
	- returns: OAuth2 JSON dictionary
	*/
	public func obtainAccessToken(params: OAuth2StringDict? = nil) async throws -> OAuth2JSON {
		do {
			let post = try accessTokenRequest(params: params).asURLRequest(for: self)
			logger?.debug("Requesting new access token from \(post.url?.description ?? "nil")")
			
			let response = await perform(request: post)
			let data = try response.responseData()
			let params = try self.parseAccessTokenResponse(data: data)
			self.logger?.debug("Did get access token [\(nil != self.clientConfig.accessToken)]")
			return params
		}
		catch {
			 throw error.asOAuth2Error
		}
	}
}

