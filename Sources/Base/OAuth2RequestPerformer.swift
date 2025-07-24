//
//  OAuth2RequestPerformer.swift
//  OAuth2
//
//  Created by Pascal Pfiffner on 9/12/16.
//  Copyright © 2016 Pascal Pfiffner. All rights reserved.
//

import Foundation


/**
Protocol for types that can perform `URLRequest`s.

The class `OAuth2DataTaskRequestPerformer` implements this protocol and is by default used by all `OAuth2` classes to perform requests.
*/
@OAuth2Actor
public protocol OAuth2RequestPerformer {
	
	/**
	This method should execute the given request asynchronously.
	
	- parameter request: An URLRequest object that provides the URL, cache policy, request type, body data or body stream, and so on.
	- returns: Data and response.
	*/
	func perform(request: URLRequest) async throws -> (Data, URLResponse)
}




