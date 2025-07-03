//
//  OAuth2Tests.swift
//  OAuth2 Tests
//
//  Created by Pascal Pfiffner on 6/6/14.
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

import XCTest

#if !NO_MODULE_IMPORT
@testable
import Base
@testable
import Flows
@testable
import TestUtils
#else
@testable
import OAuth2
#endif


@OAuth2Actor
class OAuth2Tests: XCTestCase {
	
	func genericOAuth2() -> OAuth2 {
		return OAuth2(settings: [
			"client_id": "abc",
			"authorize_uri": "https://auth.ful.io",
			"token_uri": "https://token.ful.io",
			"scope": "login",
			"verbose": true,
			"keychain": false,
		])
	}

	func refreshOAuth2() -> OAuth2 {
		return OAuth2(settings: [
			"client_id": "abc",
			"authorize_uri": "https://auth.ful.io",
			"token_uri": "https://token.ful.io",
			"refresh_uri": "https://refresh.ful.io",
			"scope": "login",
			"verbose": true,
			"keychain": false,
		])
	}
	
	func testInit() {
		var oauth = OAuth2(settings: ["client_id": "def"])
		XCTAssertFalse(oauth.verbose, "Non-verbose by default")
		XCTAssertEqual(oauth.clientId, "def", "Must init `client_id`")
		
		oauth = genericOAuth2()
		XCTAssertEqual(oauth.authURL, URL(string: "https://auth.ful.io")!, "Must init `authorize_uri`")
		XCTAssertEqual(oauth.scope!, "login", "Must init `scope`")
		XCTAssertTrue(oauth.verbose, "Must init `verbose`")
		XCTAssertFalse(oauth.useKeychain, "Must not use keychain")
	}
	
	func testAuthorizeURL() {
		let oa = genericOAuth2()
		oa.verbose = false
		let auth = try! oa.authorizeURL(withRedirect: "oauth2app://callback", scope: "launch", params: ["extra": "param"])
		
		let comp = URLComponents(url: auth, resolvingAgainstBaseURL: true)!
		XCTAssertEqual("https", comp.scheme!, "Need correct scheme")
		XCTAssertEqual("auth.ful.io", comp.host!, "Need correct host")
		
		let params = OAuth2.params(fromQuery: comp.percentEncodedQuery!)
		XCTAssertEqual(params["redirect_uri"]!, "oauth2app://callback", "Expecting correct `redirect_uri` in query")
		XCTAssertEqual(params["scope"]!, "launch", "Expecting `scope` in query")
		XCTAssertNotNil(params["state"], "Expecting `state` in query")
		XCTAssertNotNil(params["extra"], "Expecting `extra` parameter in query")
		XCTAssertEqual("param", params["extra"])
	}
	
	func testTokenRequest() {
		let oa = genericOAuth2()
		oa.verbose = false
		oa.clientConfig.refreshToken = "abc"
		let req = try! oa.tokenRequestForTokenRefresh().asURLRequest(for: oa)
		let auth = req.url!
		
		let comp = URLComponents(url: auth, resolvingAgainstBaseURL: true)!
		XCTAssertEqual("https", comp.scheme!, "Need correct scheme")
		XCTAssertEqual("token.ful.io", comp.host!, "Need correct host")
		
		let params = OAuth2.params(fromQuery: comp.percentEncodedQuery ?? "")
		//XCTAssertEqual(params["redirect_uri"]!, "oauth2app://callback", "Expecting correct `redirect_uri` in query")
		XCTAssertNil(params["state"], "Expecting no `state` in query")
	}

	func testTokenRefreshRequest() {
		let oa = refreshOAuth2()
		oa.verbose = false
		oa.clientConfig.refreshToken = "abc"
		let req = try! oa.tokenRequestForTokenRefresh().asURLRequest(for: oa)
		let auth = req.url!

		let comp = URLComponents(url: auth, resolvingAgainstBaseURL: true)!
		XCTAssertEqual("https", comp.scheme!, "Need correct scheme")
		XCTAssertEqual("refresh.ful.io", comp.host!, "Need correct host")

		let params = OAuth2.params(fromQuery: comp.percentEncodedQuery ?? "")
		//XCTAssertEqual(params["redirect_uri"]!, "oauth2app://callback", "Expecting correct `redirect_uri` in query")
		XCTAssertNil(params["state"], "Expecting no `state` in query")
	}
	
	func testAuthorizeCall() async {
		let oa = genericOAuth2()
		oa.verbose = false
		XCTAssertFalse(oa.authConfig.authorizeEmbedded)
		
		do {
			let params = try await oa.authorize()
			XCTAssertNil(params, "Should not have auth parameters")
		} catch {
			XCTAssertEqual(error.asOAuth2Error, OAuth2Error.noRedirectURL)
		}
		
		XCTAssertFalse(oa.authConfig.authorizeEmbedded)
		
		// embedded
		#if false
		oa.redirect = "myapp://oauth"
		oa.authorizeEmbedded(from: NSString()) { parameters, error in
			XCTAssertNotNil(error)
			XCTAssertEqual(error, OAuth2Error.invalidAuthorizationContext)
		}
		XCTAssertTrue(oa.authConfig.authorizeEmbedded)
		#endif
	}
	
	func testQueryParamParsing() {
		let params1 = OAuth2.params(fromQuery: "access_token=xxx&expires=2015-00-00&more=stuff")
		XCTAssert(3 == params1.count, "Expecting 3 URL params")
		
		XCTAssertEqual(params1["access_token"]!, "xxx")
		XCTAssertEqual(params1["expires"]!, "2015-00-00")
		XCTAssertEqual(params1["more"]!, "stuff")
		
		let params2 = OAuth2.params(fromQuery: "access_token=x%26x&expires=2015-00-00&more=spacey%20stuff")
		XCTAssert(3 == params1.count, "Expecting 3 URL params")
		
		XCTAssertEqual(params2["access_token"]!, "x&x")
		XCTAssertEqual(params2["expires"]!, "2015-00-00")
		XCTAssertEqual(params2["more"]!, "spacey stuff")
		
		let params3 = OAuth2.params(fromQuery: "access_token=xxx%3D%3D&expires=2015-00-00&more=spacey+stuff+with+a+%2B")
		XCTAssert(3 == params1.count, "Expecting 3 URL params")
		
		XCTAssertEqual(params3["access_token"]!, "xxx==")
		XCTAssertEqual(params3["expires"]!, "2015-00-00")
		XCTAssertEqual(params3["more"]!, "spacey stuff with a +")
		
		let params4 = OAuth2.params(fromQuery: "access_token=xxx&expires=2015-00-00&more=stuff1&more=stuff2")
		XCTAssert(3 == params4.count, "Expecting 3 URL params") // Query parameters with the same key are treated as a single multi-value parameter
		
		XCTAssertEqual(params4["access_token"]!, "xxx")
		XCTAssertEqual(params4["expires"]!, "2015-00-00")
		XCTAssertEqual(params4["more"]!, "stuff1\nstuff2")
	}
	
	func testQueryParamConversion() {
		let qry = OAuth2RequestParams.formEncodedQueryStringFor(["a": "AA", "b": "BB", "x": "y\nz"])
		XCTAssertEqual(17, qry.count, "Expecting a 17 character string")
		
		let dict = OAuth2.params(fromQuery: qry)
		XCTAssertEqual(dict["a"]!, "AA", "Must unpack `a`")
		XCTAssertEqual(dict["b"]!, "BB", "Must unpack `b`")
		XCTAssertEqual(dict["x"]!, "y\nz", "Must unpack `x`")
	}
	
	func testQueryParamEncoding() {
		let qry = OAuth2RequestParams.formEncodedQueryStringFor(["uri": "https://api.io", "str": "a string: cool!", "num": "3.14159"])
		XCTAssertEqual(60, qry.count, "Expecting a 60 character string")
		
		let dict = OAuth2.params(fromQuery: qry)
		XCTAssertEqual(dict["uri"]!, "https://api.io", "Must correctly unpack `uri`")
		XCTAssertEqual(dict["str"]!, "a string: cool!", "Must correctly unpack `str`")
		XCTAssertEqual(dict["num"]!, "3.14159", "Must correctly unpack `num`")
	}
	
	func testSessionConfiguration() {
		final class SessDelegate: NSObject, URLSessionDelegate {
		}
		
		let oauth = OAuth2(settings: [:])
		XCTAssertEqual(0, oauth.session.configuration.httpCookieStorage?.cookies?.count ?? 0, "Expecting ephemeral session configuration by default")
		
		// custom configuration
		oauth.sessionConfiguration = URLSessionConfiguration.default
		oauth.sessionConfiguration?.timeoutIntervalForRequest = 5.0
		XCTAssertEqual(5, oauth.session.configuration.timeoutIntervalForRequest)
		
		// custom delegate
		oauth.sessionDelegate = SessDelegate()
		XCTAssertTrue(oauth.sessionDelegate === oauth.session.delegate)
		XCTAssertEqual(5, oauth.session.configuration.timeoutIntervalForRequest)
	}
	
	func testDoExchangeRefreshToken() async throws {
		let oauth = OAuth2(settings: [:])
		oauth.clientConfig.refreshToken = "abc"
		
		oauth.requestPerformer = OAuth2MockPerformer { reqParams in
			let audience = reqParams?["audience"] ?? "unknown"
			
			return .init(
				json: [
					"access_token": "refresh_token_for_\(audience)",
					"issued_token_type": "urn:ietf:params:oauth:token-type:refresh_token",
					"refresh_token": "def",
					"token_type": "Bearer"
				],
				delayMs: 100
			)
		}
		
		let client1RefreshToken = try await oauth.doExchangeRefreshToken(audienceClientId: "client1", traceId: "")
		let client2RefreshToken = try await oauth.doExchangeRefreshToken(audienceClientId: "client2", traceId: "")
			
		XCTAssertEqual("refresh_token_for_client1", client1RefreshToken)
		XCTAssertEqual("refresh_token_for_client2", client2RefreshToken)
		XCTAssertEqual("def", oauth.refreshToken)
	}
	
	func testDoExchangeRefreshTokenInParallel() async throws {
		let oauth = OAuth2(settings: [:])
		oauth.clientConfig.refreshToken = "abc"
		
		oauth.requestPerformer = OAuth2MockPerformer { reqParams in
			let audience = reqParams?["audience"] ?? "unknown"
			
			return .init(
				json: [
					"access_token": "refresh_token_for_\(audience)",
					"issued_token_type": "urn:ietf:params:oauth:token-type:refresh_token",
					"refresh_token": "def",
					"token_type": "Bearer"
				],
				delayMs: 1000
			)
		}
		
		async let exchange1 = oauth.doExchangeRefreshToken(audienceClientId: "client1", traceId: "")
		async let exchange2 = oauth.doExchangeRefreshToken(audienceClientId: "client2", traceId: "")
		async let exchange3 = oauth.doExchangeRefreshToken(audienceClientId: "client3", traceId: "")
			
		let tokens = try await [exchange1, exchange2, exchange3]
		
		XCTAssertEqual("refresh_token_for_client1", tokens[0])
		XCTAssertEqual("refresh_token_for_client2", tokens[1])
		XCTAssertEqual("refresh_token_for_client3", tokens[2])
		XCTAssertEqual("def", oauth.refreshToken)
	}

}

