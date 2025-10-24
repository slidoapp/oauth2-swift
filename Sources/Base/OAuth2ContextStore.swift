//
//  OAuth2ContextStore.swift
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
import CommonCrypto

/**
Class, internally used, to store current authorization context, such as state and redirect-url.
*/
open class OAuth2ContextStore {
	
	/// Currently used redirect_url.
	open var redirectURL: String?
	
	/// Current code verifier used for PKCE
	public internal(set) var codeVerifier: String?
	public let codeChallengeMethod = "S256"

	/// The current state.
	internal var _state = ""
	
	/**
	The state sent to the server when requesting a token.
	
	We internally generate a UUID and use the first 8 chars if `_state` is empty.
	*/
	open var state: String {
		if _state.isEmpty {
			_state = UUID().uuidString
			_state = String(_state[_state.startIndex..<_state.index(_state.startIndex, offsetBy: 8)])        // only use the first 8 chars, should be enough
		}
		return _state
	}
	
	/**
	Checks that given state matches the internal state.
	
	- parameter state: The state to check (may be nil)
	- returns: true if state matches, false otherwise or if given state is nil.
	*/
	func matchesState(_ state: String?) -> Bool {
		if let st = state {
			return st == _state
		}
		return false
	}
	
	/**
	Resets current state so it gets regenerated next time it's needed.
	*/
	func resetState() {
		_state = ""
	}
	
	// MARK: - PKCE
	
	/**
	Generates a new code verifier string
	*/
	open func generateCodeVerifier() {
		var buffer = [UInt8](repeating: 0, count: 32)
		_ = SecRandomCopyBytes(kSecRandomDefault, buffer.count, &buffer)
		codeVerifier = Data(buffer).base64EncodedString()
			.replacingOccurrences(of: "+", with: "-")
			.replacingOccurrences(of: "/", with: "_")
			.replacingOccurrences(of: "=", with: "")
			.trimmingCharacters(in: .whitespaces)
	}
	
	
	open func codeChallenge() -> String? {
		guard let verifier = codeVerifier, let data = verifier.data(using: .utf8) else { return nil }
		var buffer = [UInt8](repeating: 0,  count: Int(CC_SHA256_DIGEST_LENGTH))
		data.withUnsafeBytes {
			_ = CC_SHA256($0.baseAddress, CC_LONG(data.count), &buffer)
		}
		let hash = Data(buffer)
		let challenge = hash.base64EncodedString()
			.replacingOccurrences(of: "+", with: "-")
			.replacingOccurrences(of: "/", with: "_")
			.replacingOccurrences(of: "=", with: "")
			.trimmingCharacters(in: .whitespaces)
		return challenge
	}
	
}
