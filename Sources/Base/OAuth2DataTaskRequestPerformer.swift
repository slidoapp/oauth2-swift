//
//  OAuth2DataTaskRequestPerformer.swift
//  OAuth2
//
//  Created by Dominik Paľo on 24/07/2025.
//  Copyright © 2025 Pascal Pfiffner. All rights reserved.
//


import Foundation

/**
Simple implementation of `OAuth2RequestPerformer`, using `URLSession.dataTask()` to perform requests.
*/
open class OAuth2DataTaskRequestPerformer: OAuth2RequestPerformer {
	
	/// The URLSession that should be used.
	public var session: URLSession
	
	/**
	Designated initializer.
	*/
	public init(session: URLSession) {
		self.session = session
	}
	
	/**
	This method should execute the given request asynchronously.
	
	- parameter request: An URLRequest object that provides the URL, cache policy, request type, body data or body stream, and so on.
	- returns: Data and response.
	*/
	open func perform(request: URLRequest) async throws -> (Data, URLResponse) {
		try await session.data(for: request)
	}
}