import Foundation
import Security

/// Sendable Keychain configuration that maps to Core Foundation values only inside the queue-isolated implementation.
public struct OAuth2KeychainConfiguration: Sendable, Equatable {
	public enum Accessibility: Sendable, Equatable {
		case whenUnlocked
		case afterFirstUnlock
		case whenUnlockedThisDeviceOnly
		case afterFirstUnlockThisDeviceOnly
	}

	public let service: String
	public let account: String
	public let accessGroup: String?
	public let accessibility: Accessibility

	public init(
		service: String,
		account: String = "OAuth2Credentials",
		accessGroup: String? = nil,
		accessibility: Accessibility = .whenUnlocked
	) {
		self.service = service
		self.account = account
		self.accessGroup = accessGroup
		self.accessibility = accessibility
	}
}

public enum OAuth2KeychainError: Error, Sendable, Equatable {
	case unexpectedStatus(OSStatus)
}

/// Async credential persistence backed by a dedicated serial queue.
///
/// `SecItem` calls are synchronous. Keeping them on this queue avoids blocking a Swift actor executor, while the
/// audited unchecked conformance is limited to immutable configuration plus the thread-safe `DispatchQueue`.
public final class OAuth2KeychainCredentialStore: OAuth2CredentialStore, @unchecked Sendable {
	private let configuration: OAuth2KeychainConfiguration
	private let queue: DispatchQueue

	public init(configuration: OAuth2KeychainConfiguration) {
		self.configuration = configuration
		queue = DispatchQueue(label: "OAuth2.KeychainCredentialStore.\(configuration.service).\(configuration.account)")
	}

	public func load() async throws -> OAuth2CredentialRecord? {
		let configuration = configuration
		return try await perform {
			var result: CFTypeRef?
			var query = Self.query(for: configuration)
			query[kSecReturnData] = true
			query[kSecMatchLimit] = kSecMatchLimitOne
			let status = SecItemCopyMatching(query as CFDictionary, &result)
			if status == errSecItemNotFound {
				return nil
			}
			guard status == errSecSuccess else {
				throw OAuth2KeychainError.unexpectedStatus(status)
			}
			guard let data = result as? Data else {
				throw OAuth2ClientError.invalidTokenResponse("Keychain returned a non-data credential value")
			}
			return try JSONDecoder().decode(OAuth2CredentialRecord.self, from: data)
		}
	}

	public func save(_ record: OAuth2CredentialRecord) async throws {
		let configuration = configuration
		let data = try JSONEncoder().encode(record)
		try await perform {
			let query = Self.query(for: configuration)
			let update: [CFString: Any] = [kSecValueData: data]
			let updateStatus = SecItemUpdate(query as CFDictionary, update as CFDictionary)
			if updateStatus == errSecSuccess {
				return
			}
			guard updateStatus == errSecItemNotFound else {
				throw OAuth2KeychainError.unexpectedStatus(updateStatus)
			}

			var item = query
			item[kSecValueData] = data
			item[kSecAttrAccessible] = Self.accessibilityValue(configuration.accessibility)
			let addStatus = SecItemAdd(item as CFDictionary, nil)
			guard addStatus == errSecSuccess else {
				throw OAuth2KeychainError.unexpectedStatus(addStatus)
			}
		}
	}

	public func clear() async throws {
		let configuration = configuration
		try await perform {
			let status = SecItemDelete(Self.query(for: configuration) as CFDictionary)
			guard status == errSecSuccess || status == errSecItemNotFound else {
				throw OAuth2KeychainError.unexpectedStatus(status)
			}
		}
	}

	private func perform<T: Sendable>(_ operation: @escaping @Sendable () throws -> T) async throws -> T {
		try await withCheckedThrowingContinuation { continuation in
			queue.async {
				continuation.resume(with: Result { try operation() })
			}
		}
	}

	private static func query(for configuration: OAuth2KeychainConfiguration) -> [CFString: Any] {
		var query: [CFString: Any] = [
			kSecClass: kSecClassGenericPassword,
			kSecAttrService: configuration.service,
			kSecAttrAccount: configuration.account,
		]
		if let accessGroup = configuration.accessGroup {
			query[kSecAttrAccessGroup] = accessGroup
		}
		return query
	}

	private static func accessibilityValue(_ accessibility: OAuth2KeychainConfiguration.Accessibility) -> CFString {
		switch accessibility {
		case .whenUnlocked:
			return kSecAttrAccessibleWhenUnlocked
		case .afterFirstUnlock:
			return kSecAttrAccessibleAfterFirstUnlock
		case .whenUnlockedThisDeviceOnly:
			return kSecAttrAccessibleWhenUnlockedThisDeviceOnly
		case .afterFirstUnlockThisDeviceOnly:
			return kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
		}
	}
}
