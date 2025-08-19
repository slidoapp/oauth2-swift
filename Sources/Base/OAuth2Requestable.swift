//
//  OAuth2Requestable.swift
//  OAuth2
//
//  Created by Pascal Pfiffner on 6/2/15.
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


/// Typealias to ease working with JSON dictionaries.
public typealias OAuth2JSON = [String: any Sendable]

/// Typealias to work with dictionaries full of strings.
public typealias OAuth2StringDict = [String: String]

/// Typealias to work with headers.
public typealias OAuth2Headers = [String: String]


/**
Abstract base class for OAuth2 authorization as well as client registration classes.
*/
@OAuth2Actor
open class OAuth2Requestable {
	
	/// Set to `true` to log all the things. `false` by default. Use `"verbose": bool` in settings or assign `logger` yourself.
	open var verbose = false {
		didSet {
			logger = verbose ? OAuth2DebugLogger() : nil
		}
	}
	
	/// The logger being used. Auto-assigned to a debug logger if you set `verbose` to true or false.
	open var logger: OAuth2Logger?
	
	
	/**
	Base initializer.
	*/
	public init(verbose: Bool) {
		self.verbose = verbose
		logger = verbose ? OAuth2DebugLogger() : nil
		logger?.debug("OAuth2", msg: "Initialization finished")
	}
	
	/**
	Designated initializer.
	
	- parameter logger: An optional `OAuth2Logger` instance to use
	*/
	public init(logger: OAuth2Logger?) {
		self.logger = logger
		self.verbose = (nil != logger)
		logger?.debug("OAuth2", msg: "Initialization finished")
	}
	
	
	// MARK: - Requests
	
	/// The instance's current session, creating one by the book if necessary. Defaults to using an ephemeral session, you can use
	/// `sessionConfiguration` and/or `sessionDelegate` to affect how the session is configured.
	open var session: URLSession {
		if nil == _session {
			let config = sessionConfiguration ?? URLSessionConfiguration.ephemeral
			_session = URLSession(configuration: config, delegate: sessionDelegate, delegateQueue: nil)
		}
		return _session!
	}
	
	/// The backing store for `session`.
	private var _session: URLSession? {
		didSet {
			requestPerformer = nil
		}
	}
	
	/// The configuration to use when creating `session`. Uses an `+ephemeralSessionConfiguration()` if nil.
	open var sessionConfiguration: URLSessionConfiguration? {
		didSet {
			_session = nil
		}
	}
	
	/// URL session delegate that should be used for the `NSURLSession` the instance uses for requests.
	open var sessionDelegate: URLSessionDelegate? {
		didSet {
			_session = nil
		}
	}
	
	/// The instance's OAuth2RequestPerformer, defaults to using OAuth2DataTaskRequestPerformer which uses `URLSession.dataTask()`.
	open var requestPerformer: OAuth2RequestPerformer?
	
	/**
	Perform the supplied request and return the response JSON dict or throw an error. This method is intended for authorization
	calls, not for data calls outside of the OAuth2 dance.
	
	This implementation uses the shared `NSURLSession`. If the server responds with an error, this will be
	converted into an error according to information supplied in the response JSON (if available).
	
	- parameter request:  The request to execute
	- returns : OAuth2 response
	*/
	open func perform(request: URLRequest) async -> OAuth2Response {
		self.logger?.trace("OAuth2", msg: "REQUEST\n\(request.debugDescription)\n---")
		let performer = requestPerformer ?? OAuth2DataTaskRequestPerformer(session: session)
		requestPerformer = performer
		
		do {
			// TODO: add support for aborting the request, see https://www.hackingwithswift.com/quick-start/concurrency/how-to-cancel-a-task
			let (sessData, sessResponse) = try await performer.perform(request: request)
			self.logger?.trace("OAuth2", msg: "RESPONSE\n\(sessResponse.debugDescription)\n\n\(String(data: sessData, encoding: String.Encoding.utf8) ?? "no data")\n---")
			
			guard let response = sessResponse as? HTTPURLResponse else {
				throw CommonError.castError(
					from: String(describing: sessResponse.self),
					to: String(describing: HTTPURLResponse.self)
				)
			}

			return OAuth2Response(data: sessData, request: request, response: response, error: nil)
			
		} catch {
			self.logger?.trace("OAuth2", msg: "RESPONSE\nno response\n\nno data\n---")
			
			let http = HTTPURLResponse(url: request.url!, statusCode: 499, httpVersion: nil, headerFields: nil)!
			return OAuth2Response(data: nil, request: request, response: http, error: error)
		}
	}
	
	/// Currently running abortable session task.
	private var abortableTask: URLSessionTask?
	
	/**
	Can be called to immediately abort the currently running authorization request, if it was started by `perform(request:callback:)`.
	
	- returns: A bool indicating whether a task was aborted or not
	*/
	func abortTask() -> Bool {
		guard let task = abortableTask else {
			return false
		}
		logger?.debug("OAuth2", msg: "Aborting request")
		task.cancel()
		return true
	}
	
	
	// MARK: - Utilities
	
	/**
	Parse string-only JSON from NSData.
	
	- parameter data: NSData returned from the call, assumed to be JSON with string-values only.
	- returns: An OAuth2JSON instance
	*/
	open func parseJSON(_ data: Data) throws -> OAuth2JSON {
		do {
			let json = try JSONSerialization.jsonObject(with: data, options: [])
			if let json = json as? OAuth2JSON {
				return json
			}
			if let str = String(data: data, encoding: String.Encoding.utf8) {
				logger?.warn("OAuth2", msg: "JSON did not resolve to a dictionary, was: \(str)")
			}
			throw OAuth2Error.jsonParserError
		}
		catch let error where NSCocoaErrorDomain == error._domain && 3840 == error._code {		// JSON parser error
			if let str = String(data: data, encoding: String.Encoding.utf8) {
				logger?.warn("OAuth2", msg: "Unparsable JSON was: \(str)")
			}
			throw OAuth2Error.jsonParserError
		}
	}
	
	/**
	Parse a query string into a dictionary of String: String pairs.
	
	If you're retrieving a query or fragment from NSURLComponents, use the `percentEncoded##` variant as the others
	automatically perform percent decoding, potentially messing with your query string.
	
	- parameter fromQuery: The query string you want to have parsed
	- returns: A dictionary full of strings with the key-value pairs found in the query
	*/
	public final class func params(fromQuery query: String) -> OAuth2StringDict {
		let parts = query.split(separator: "&")
		var params = OAuth2StringDict(minimumCapacity: parts.count)

		for part in parts {
			let subparts = part.split(separator: "=").map(String.init)
			guard subparts.count == 2 else {
				continue
			}
			
			let (key, value) = (subparts[0], subparts[1].wwwFormURLDecodedString)
			params[key] = [params[key], value].compactMap { $0 }.joined(separator: "\n")
		}

		return params
	}
}


/**
Helper function to ensure that the callback is executed on the main thread.
*/
public func callOnMainThread(_ callback: (() -> Void)) {
	if Thread.isMainThread {
		callback()
	}
	else {
		DispatchQueue.main.sync(execute: callback)
	}
}

// TODO: move to a separate file
enum CommonError: Error {
	case castError(from: String, to: String)
}

extension CommonError: CustomStringConvertible {
	public var description: String {
		switch self {
		case .castError(from: let from, to: let to):
			return "Could not cast \(from) to \(to)"
		}
	}
}
