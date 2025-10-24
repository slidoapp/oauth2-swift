//
//  OAuth2ServerMetadataLoader.swift
//  OAuth2
//
//  Created by Dominik Paľo on 24/07/2025.
//  Copyright © 2025 Pascal Pfiffner. All rights reserved.
//

import Foundation

@OAuth2Actor
public struct OAuth2ServerMetadataLoader {
	
	/// Default settings
	public var validateIssuerName: Bool = true
	public var wellKnownUriSuffix: String = "oauth-authorization-server"
	
	private let requestPerformer: OAuth2DataTaskRequestPerformer
	
	public init(session: URLSession = URLSession.shared) {
		self.requestPerformer = OAuth2DataTaskRequestPerformer(session: session)
	}
	
	/// Loads OAuth 2.0 Authorization Server Metadata from the issuer's well-known endpoint
	/// - Parameter issuer: Authorization server's issuer identifier
	/// - Returns: The parsed OAuth2ServerMetadataModel
	/// - Throws: OAuth2ServerMetadataError for various failure cases
	public func loadMetadata(issuer: String) async throws -> OAuth2ServerMetadata? {
		guard let issuerUrl = URL(string: issuer) else {
			throw OAuth2ServerMetadataError.invalidIssuerURL
		}
		
		guard let metadataUrl = URL(string: ".well-known/\(self.wellKnownUriSuffix)", relativeTo: issuerUrl) else {
			throw OAuth2ServerMetadataError.invalidMetadataURL
		}
		
		let metadata = try await self.loadMetadata(from: metadataUrl)
		
		/// The "issuer" value returned MUST be identical to the authorization server's issuer identifier value
		/// into which the well-known URI string was inserted to create the URL used to retrieve the metadata.
		/// See: https://datatracker.ietf.org/doc/html/rfc8414#section-3.3
		if self.validateIssuerName, metadata.issuer != issuer {
			throw OAuth2ServerMetadataError.invalidIssuerURL
		}
		
		return metadata
	}
	
	/// Loads OAuth 2.0 Authorization Server Metadata from a specific URL
	/// - Parameter url: The complete metadata endpoint URL
	/// - Returns: The parsed OAuth2ServerMetadataModel
	/// - Throws: OAuth2ServerMetadataError for various failure cases
	private func loadMetadata(from url: URL) async throws -> OAuth2ServerMetadata {
		let request = URLRequest(url: url)
		let (data, response) = try await self.requestPerformer.perform(request: request)
		
		guard let httpResponse = response as? HTTPURLResponse else {
			throw OAuth2ServerMetadataError.invalidResponse
		}
		
		guard httpResponse.statusCode == 200 else {
			throw OAuth2ServerMetadataError.networkError(httpResponse.statusCode)
		}
		
		let decoder = JSONDecoder()
		decoder.keyDecodingStrategy = .convertFromSnakeCase
		
		do {			
			return try decoder.decode(OAuth2ServerMetadata.self, from: data)
		} catch let decodingError as DecodingError {
			throw OAuth2ServerMetadataError.decodingError(decodingError)
		}
	}
}

/// Errors that can occur during OAuth 2.0 server metadata loading
public enum OAuth2ServerMetadataError: Error, LocalizedError {
	case invalidIssuerURL
	case invalidMetadataURL
	case networkError(Int)
	case invalidResponse
	case decodingError(Error)
	
	public var errorDescription: String? {
		switch self {
		case .invalidIssuerURL:
			return "Invalid issuer URL provided"
		case .invalidMetadataURL:
			return "Unable to construct metadata URL from issuer"
		case .networkError(let statusCode):
			return "Network error: HTTP status \(statusCode)"
		case .invalidResponse:
			return "Invalid response from server"
		case .decodingError(let error):
			return "Failed to decode server metadata: \(error)"
		}
	}
}
