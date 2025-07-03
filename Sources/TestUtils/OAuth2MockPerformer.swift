//
//  OAuth2MockPerformer.swift
//  OAuth2
//
//  Created by Dominik Paľo on 02/07/25.
//  Copyright © 2023 Cisco Systems, Inc. All rights reserved.
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
#else
import OAuth2
#endif

/**
A mock performer for OAuth2 network requests, useful for testing and simulating server responses.
You can configure the mock performer to return specific JSON payloads, HTTP status codes, and simulate delays.
*/
class OAuth2MockPerformer: OAuth2RequestPerformer {

	/// Type alias for a closure that generates a mocked response based on request parameters.
	typealias ResponseDelegate = ((_ reqParams: OAuth2StringDict?) throws -> MockedResponse)
	
	/// The closure used to generate a mocked response for each request.
	private let responseDelegate: ResponseDelegate

	/**
	Initializes the mock performer with a custom response delegate.
	
	- parameter responseDelegate: A closure that returns a `MockedResponse` based on request parameters. Defaults to a 200 OK response with no JSON body and no delay.
	*/
	init(_ responseDelegate: @escaping ResponseDelegate = { _ in MockedResponse() }) {
		self.responseDelegate = responseDelegate
	}
	
	/**
	Convenience initializer to always return the same mocked response configured throught the `MockedResponse` confguration.
	
	- parameter response: The response configuration.
	*/
	convenience init(_ response: MockedResponse) {
		self.init { _ in response }
	}
	
	/**
	Convenience initializer to always return the same JSON payload with a 200 OK status and no delay.
	
	- parameter responseJson: The JSON object to return in the response.
	*/
	convenience init(_ responseJson: OAuth2JSON) {
		self.init { _ in .init(json: responseJson) }
	}
	
	func perform(request: URLRequest) async throws -> (Data?, URLResponse) {
		var params: OAuth2StringDict?
		
		/// Parse request body as URL-encoded parameters if present
		if let reqBody = request.httpBody,let reqQuery = String(data: reqBody, encoding: .utf8) {
			params = OAuth2Requestable.params(fromQuery: reqQuery)
		}

		let response = try responseDelegate(params)
		
		let http = HTTPURLResponse(
			url: request.url!,
			statusCode: response.statusCode,
			httpVersion: nil,
			headerFields: nil
		)!
		
		if let delay = response.delayMs {
			try await Task.sleep(nanoseconds: delay * NSEC_PER_MSEC)
		}
				
		guard let json = response.json else {
			throw OAuth2Error.noDataInResponse
		}
		
		let data = try JSONSerialization.data(withJSONObject: json)
		return (data, http)
	}
	
	/**
	A structure representing a configuration of a mocked HTTP response
	*/
	struct MockedResponse {
		/// The JSON payload to be returned in the mocked response. Defaults to `nil` (empty response).
		var json: OAuth2JSON?
		
		/// The HTTP status code of the mocked response. Defaults to `200` (OK).
		var statusCode = 200
		
		/// An optional artificial delay (in milliseconds) before the response is delivered. Defaults to `nil` (no delay is applied).
		var delayMs: UInt64?
	}
}


