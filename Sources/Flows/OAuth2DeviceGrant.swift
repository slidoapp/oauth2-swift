//
//  OAuth2DeviceGrant.swift
//  OAuth2
//
//  Created by Dominik Paľo on 29/03/23.
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
import Constants
#endif

/// https://www.ietf.org/rfc/rfc8628.html
open class OAuth2DeviceGrant: OAuth2 {
	override open class var grantType: String {
		return OAuth2GrantTypes.deviceCode
	}
	
	override open class var responseType: String? {
		return ""
	}
		
	open func deviceAccessTokenRequest(with deviceCode: String) throws -> OAuth2AuthRequest {
		guard let clientId = clientConfig.clientId, !clientId.isEmpty else {
			throw OAuth2Error.noClientId
		}
		
		let req = OAuth2AuthRequest(url: (clientConfig.tokenURL ?? clientConfig.authorizeURL))
		req.params["device_code"] = deviceCode
		req.params["grant_type"] = type(of: self).grantType
		req.params["client_id"] = clientId
		return req
	}
	
	open func deviceAuthorizationRequest(params: OAuth2StringDict? = nil) throws -> OAuth2AuthRequest {
		guard let clientId = clientConfig.clientId, !clientId.isEmpty else {
			throw OAuth2Error.noClientId
		}
		
		guard let url = clientConfig.deviceAuthorizeURL else {
			throw OAuth2Error.noDeviceCodeURL
		}
		
		let req = OAuth2AuthRequest(url: url)
		req.params["client_id"] = clientId
		if let scope = clientConfig.scope {
			req.params["scope"] = scope
		}
		req.add(params: params)
		
		return req
	}
	
	open func parseDeviceAuthorizationResponse(data: Data) throws -> OAuth2JSON {
		let dict = try parseJSON(data)
		return try parseDeviceAuthorizationResponse(params: dict)
	}
	
	public final func parseDeviceAuthorizationResponse(params: OAuth2JSON) throws -> OAuth2JSON {
		try assureNoErrorInResponse(params)
		
		return params
	}
	
	/**
	Start the device authorization flow.
	
	- parameter params: Optional key/value pairs to pass during authorize device request
	- returns: The device authorization response.
	*/
	public func start(useNonTextualTransmission: Bool = false, params: OAuth2StringDict? = nil) async throws -> DeviceAuthorization {
		do {
			let result = try await authorizeDevice(params: params)
			
			guard let deviceCode = result["device_code"] as? String,
				let userCode = result["user_code"] as? String,
				let verificationUri = result["verification_uri"] as? String,
				let verificationUrl = URL(string: verificationUri),
				let expiresIn = result["expires_in"] as? Int
			else {
				throw OAuth2Error.generic("The response doesn't contain all required fields.")
			}
			
			var verificationUrlComplete: URL?
			if let verificationUriComplete = result["verification_uri_complete"] as? String {
				verificationUrlComplete = URL(string: verificationUriComplete)
			}
			
			if useNonTextualTransmission, let url = verificationUrlComplete {
				try self.authorizer.openAuthorizeURLInBrowser(url)
			}
			
			let pollingInterval = result["interval"] as? TimeInterval ?? 5
			
			Task {
				do {
					let params = try await self.getDeviceAccessToken(deviceCode: deviceCode, interval: pollingInterval)
					self.didAuthorize(withParameters: params)
				} catch {
					self.didFail(with: error.asOAuth2Error)
				}
			}
			
			return DeviceAuthorization(
				userCode: userCode,
				verificationUrl: verificationUrl,
				verificationUrlComplete: verificationUrlComplete,
				expiresIn: expiresIn
			)
			
		} catch {
			self.logger?.warning("Unable to get device code: \(error)") // TODO improve message to cover different scenarios
			throw error
		}
	}
	
	private func authorizeDevice(params: OAuth2StringDict?) async throws -> OAuth2JSON {
		do {
			let post = try deviceAuthorizationRequest(params: params).asURLRequest(for: self)
			logger?.debug("Obtaining device code from \(post.url!)")
			
			let response = await self.perform(request: post)
			let data = try response.responseData()
			return try self.parseDeviceAuthorizationResponse(data: data)
			
		}
		catch let error {
			throw error.asOAuth2Error
		}
	}
	
	private func getDeviceAccessToken(deviceCode: String, interval: TimeInterval) async throws -> OAuth2JSON {
		do {
			let post = try deviceAccessTokenRequest(with: deviceCode).asURLRequest(for: self)
			logger?.debug("Obtaining access token for device with code \(deviceCode) from \(post.url!)")
			
			let response = await self.perform(request: post)
			let data = try response.responseData()
			return try self.parseAccessTokenResponse(data: data)
		}
		catch {
			let oaerror = error.asOAuth2Error
			
			if oaerror == .authorizationPending(nil) {
				self.logger?.debug("AuthorizationPending, repeating in \(interval) seconds.")
				try await Task.sleep(seconds: interval)
				return try await self.getDeviceAccessToken(deviceCode: deviceCode, interval: interval)
			} else if oaerror == .slowDown(nil) {
				let updatedInterval = interval + 5 // The 5 seconds increase is required by the RFC8628 standard (https://www.rfc-editor.org/rfc/rfc8628#section-3.5)
				self.logger?.debug("SlowDown, repeating in \(updatedInterval) seconds.")
				try await Task.sleep(seconds: updatedInterval)
				return try await self.getDeviceAccessToken(deviceCode: deviceCode, interval: updatedInterval)
			}
			
			throw error.asOAuth2Error
		}
	}
}

fileprivate extension Task where Success == Never, Failure == Never {
	static func sleep(seconds: Double) async throws {
		let duration = UInt64(seconds * 1_000_000_000)
		try await Task.sleep(nanoseconds: duration)
	}
}

public struct DeviceAuthorization: Sendable {
	public let userCode: String
	public let verificationUrl: URL
	public let verificationUrlComplete: URL?
	public let expiresIn: Int
}
