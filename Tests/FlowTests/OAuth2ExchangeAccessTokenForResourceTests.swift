//
//  OAuth2ExchangeAccessTokenForResourceTests.swift
//  OAuth2
//
//  Created by Tomas Ondrejka on 17/11/23.
//  Copyright 2023 Cisco Systems, Inc. All rights reserved.
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
class OAuth2ExchangeAccessTokenForResourceTests: XCTestCase {
	
	lazy var baseSettings: OAuth2JSON = [
			"client_id": "abc",
			"authorize_uri": "https://auth.ful.io",
			"token_uri": "https://token.ful.io",
			"scope": "login and more",
			"resource_uris": [
				"https://resource.ful.io/resources/558fca91-002d-4fca-a274-6031dd3119d9"
			]
		]
	
	func testInit() {
		let oauth = OAuth2(settings: baseSettings)
		XCTAssertEqual(oauth.clientId, "abc", "Must init `client_id`")
		XCTAssertEqual(oauth.scope, "login and more")
		
		XCTAssertEqual(oauth.authURL, URL(string: "https://auth.ful.io")!, "Must init `authorize_uri`")
		XCTAssertEqual(oauth.tokenURL!, URL(string: "https://token.ful.io")!, "Must init `token_uri`")
	}

	func testExchangeAccessTokenForResourceRequest() throws {
		let oauth = OAuth2(settings: baseSettings)
		
		oauth.verbose = false
		oauth.clientConfig.accessToken = "access_token"
		
		let req = try! oauth.tokenRequestForExchangeAccessTokenForResource().asURLRequest(for: oauth)
		
		let httpBody = String(data: req.httpBody!, encoding: .utf8)
		let params = OAuth2.params(fromQuery: httpBody!)
	
		XCTAssertEqual(params["resource"]!, "https://resource.ful.io/resources/558fca91-002d-4fca-a274-6031dd3119d9", "Expecting correct `resource`")
		assertParams(params: params)
	}
	
	func testExchangeAccessTokenForMultipleResourcesRequest() throws {
		let oauth = OAuth2(settings: baseSettings)
		
		oauth.verbose = false
		oauth.clientConfig.accessToken = "access_token"
		oauth.clientConfig.resourceURIs = [
			"https://resource.ful.io/resources/1",
			"https://resource.ful.io/resources/2"
		]
		
		let req = try! oauth.tokenRequestForExchangeAccessTokenForResource().asURLRequest(for: oauth)
		
		let httpBody = String(data: req.httpBody!, encoding: .utf8)
		let params = OAuth2.params(fromQuery: httpBody!)
		
		XCTAssertEqual(params["resource"]!, "https://resource.ful.io/resources/1\nhttps://resource.ful.io/resources/2", "Expecting correct `resource`")
		assertParams(params: params)
	}
	
	func testExchangeAccessTokenForResource() async throws {
		let oauth = OAuth2(settings: baseSettings)

		oauth.accessToken = "current_access_token"
		
		let performer = OAuth2MockPerformer([
			"access_token": "resource_aware_access_token",
			"issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
			"token_type": "Bearer",
			"expires_in": 600,
			"scope": "login and more",
			"cluster_id": "eu1"
		])
		oauth.requestPerformer = performer
		
		let token = try await oauth.doExchangeAccessTokenForResource()
		XCTAssertEqual(token, "resource_aware_access_token", "Expecting correct accessToken")
		XCTAssertEqual(oauth.accessToken, "resource_aware_access_token", "Expecting correct accessToken is set")
		self.assertDatesWithBuffer(date1: oauth.accessTokenExpiry!, date2: Date(timeIntervalSinceNow: 600), bufferInSeconds: 5)
	}
	
	func testExchangeAccessTokenForResourceAccessTokenNotAvailable() async throws {
		let oauth = OAuth2(settings: baseSettings)

		do {
			_ = try await oauth.doExchangeAccessTokenForResource()
		} catch {
			XCTAssertEqual(error.asOAuth2Error, OAuth2Error.noAccessToken)
		}
	}
	
	private func assertParams(params: OAuth2StringDict) {
		XCTAssertEqual(params["grant_type"], "urn:ietf:params:oauth:grant-type:token-exchange", "Expecting correct `grant_type`")
		// TODO: check specs, if the `client_id` should be part of the params. Currently, it is set to `nil`
		// XCTAssertEqual(params["client_id"], "abc", "Expecting correct `client_id`")
		XCTAssertEqual(params["requested_token_type"], "urn:ietf:params:oauth:token-type:access_token", "Expecting correct `requested_token_type`")
		XCTAssertEqual(params["subject_token"], "access_token", "Expecting correct `subject_token`")
		XCTAssertEqual(params["subject_token_type"], "urn:ietf:params:oauth:token-type:access_token", "Expecting correct `subject_token_type`")
		XCTAssertEqual(params["scope"]!, "login and more", "Expecting correct `scope`")
	}
	
	private func assertDatesWithBuffer(date1: Date, date2: Date, bufferInSeconds: Int) {
		let difference = abs(date1.timeIntervalSince(date2))
		let isWithinBuffer = difference <= Double(bufferInSeconds)

		XCTAssertTrue(isWithinBuffer, "The dates are not within \(bufferInSeconds) seconds of each other")
	}
}
