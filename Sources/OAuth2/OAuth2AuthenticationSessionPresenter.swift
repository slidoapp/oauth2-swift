#if os(iOS) || os(macOS) || os(visionOS)
import AuthenticationServices
import Foundation

/// Main-actor adapter around `ASWebAuthenticationSession`.
///
/// The framework completion handler and explicit cancellation share one continuation slot, which is cleared
/// before either path resumes it. A late framework callback therefore cannot double-resume the continuation.
@MainActor
public final class OAuth2AuthenticationSessionPresenter: NSObject, OAuth2AuthorizationPresenter {
	private let presentationContextProvider: OAuth2AuthenticationSessionPresentationContextProvider
	private let prefersEphemeralWebBrowserSession: Bool
	private var session: ASWebAuthenticationSession?
	private var continuation: CheckedContinuation<URL, any Error>?

	public init(
		presentationAnchor: ASPresentationAnchor,
		prefersEphemeralWebBrowserSession: Bool = false
	) {
		self.prefersEphemeralWebBrowserSession = prefersEphemeralWebBrowserSession
		presentationContextProvider = OAuth2AuthenticationSessionPresentationContextProvider(
			presentationAnchor: presentationAnchor
		)
	}

	public func authorize(_ request: OAuth2AuthorizationPresentationRequest) async throws -> URL {
		guard continuation == nil else {
			throw OAuth2ClientError.operationSuperseded
		}

		return try await withTaskCancellationHandler {
			try await withCheckedThrowingContinuation { continuation in
				self.continuation = continuation
				let session = ASWebAuthenticationSession(
					url: request.authorizationURL,
					callbackURLScheme: request.callbackURLScheme
				) { [weak self] url, error in
					Task { @MainActor in
						guard let self else { return }
						if let url {
							self.finish(with: .success(url))
						}
						else if let sessionError = error as? ASWebAuthenticationSessionError, sessionError.code == .canceledLogin {
							self.finish(with: .failure(CancellationError()))
						}
						else {
							self.finish(with: .failure(
								OAuth2ClientError.invalidAuthorizationResponse(error?.localizedDescription ?? "The authorization session returned no URL")
							))
						}
					}
				}
				self.session = session
				session.presentationContextProvider = presentationContextProvider
				session.prefersEphemeralWebBrowserSession = prefersEphemeralWebBrowserSession
				if !session.start() {
					finish(with: .failure(OAuth2ClientError.invalidAuthorizationResponse("The authorization session did not start")))
				}
			}
		} onCancel: {
			Task { @MainActor in
				self.cancel()
			}
		}
	}

	public func cancel() {
		let session = session
		let continuation = continuation
		self.session = nil
		self.continuation = nil
		continuation?.resume(throwing: CancellationError())
		session?.cancel()
	}

	private func finish(with result: Result<URL, any Error>) {
		guard let continuation else { return }
		self.continuation = nil
		session = nil
		continuation.resume(with: result)
	}
}

/// Compatibility adapter for the Xcode 15.4 SDK, whose presentation-context protocol requirement is not annotated
/// with `MainActor`. AuthenticationServices invokes this synchronous requirement as part of main-thread presentation;
/// the assertion makes that interoperability assumption explicit without weakening the public presenter's isolation.
private final class OAuth2AuthenticationSessionPresentationContextProvider: NSObject, ASWebAuthenticationPresentationContextProviding {
	private let presentationAnchor: ASPresentationAnchor

	@MainActor
	init(presentationAnchor: ASPresentationAnchor) {
		self.presentationAnchor = presentationAnchor
	}

	func presentationAnchor(for session: ASWebAuthenticationSession) -> ASPresentationAnchor {
		precondition(Thread.isMainThread, "AuthenticationServices requested a presentation anchor off the main thread")
		return presentationAnchor
	}
}
#endif
