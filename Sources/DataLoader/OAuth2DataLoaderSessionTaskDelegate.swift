//
//  OAuth2DataLoaderSessionTaskDelegate.swift
//  OAuth2
//
//  Created by Pascal Pfiffner on 03.02.17.
//  Copyright © 2017 Pascal Pfiffner. All rights reserved.
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
#endif


/**
Simple implementation of a session task delegate, which looks at HTTP redirecting, approving redirects in the same domain and re-signing the
redirected request.
*/
final class OAuth2DataLoaderSessionTaskDelegate: NSObject, URLSessionTaskDelegate, @unchecked Sendable {

	private let redirectHandler: @OAuth2Actor @Sendable (URLRequest) -> URLRequest?
	
	/// Only redirects against this host will be approved.
	public let host: String
	
	/**
	Designated initializer.
	
	- parameter loader: The data loader for which the receiver is delegating
	- parameter host:   The host on which HTTP redirecting will be approved; will be run through `URLComponents` to satisfy formatting
	*/
	@OAuth2Actor
	public init(loader: OAuth2DataLoader, host: String) {
		let normalizedHost = URLComponents(string: host)?.host ?? host
		self.host = normalizedHost
		redirectHandler = { [weak loader] request in
			guard request.url?.host == normalizedHost else {
				loader?.logger?.warning("Redirected to «\(request.url?.host ?? "nil")» but only approving HTTP redirection on «\(normalizedHost)», not following redirect: \(request)")
				return nil
			}
			do {
				guard let loader else {
					throw OAuth2Error.generic("no loader instance, cannot re-sign")
				}
				let newRequest = try request.signed(with: loader.oauth2)
				loader.logger?.debug("Following HTTP redirection to «\(request.url?.description ?? "nil")»")
				return newRequest
			} catch {
				loader?.logger?.warning("Failed to re-sign request after HTTP redirection: \(error)")
				return request
			}
		}
	}
	
	
	// MARK: - URLSessionTaskDelegate
	
	func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse, newRequest request: URLRequest, completionHandler: @escaping @Sendable (URLRequest?) -> Void) {
		Task {
			let newRequest = await redirectHandler(request)
			completionHandler(newRequest)
		}
	}
}
