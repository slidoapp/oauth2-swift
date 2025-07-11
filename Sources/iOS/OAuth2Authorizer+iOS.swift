//
//  OAuth2Authorizer+iOS.swift
//  OAuth2
//
//  Created by Pascal Pfiffner on 4/19/15.
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
#if os(visionOS) || os(iOS)

import UIKit
import SafariServices
import AuthenticationServices

#if !NO_MODULE_IMPORT
import Base
#endif


/**
This authorizer takes care of iOS-specific tasks when showing the authorization UI.

You can subclass this class and override `willPresent(viewController:naviController:)` in order to further customize presentation of the UI.
*/
open class OAuth2Authorizer: OAuth2AuthorizerUI {
	
	/// The OAuth2 instance this authorizer belongs to.
	public unowned let oauth2: OAuth2Base
	
#if !os(visionOS)
	/// Used to store the `SFSafariViewControllerDelegate` || `UIAdaptivePresentationControllerDelegate`
	private var safariViewDelegate: OAuth2SFViewControllerDelegate?
#endif
	
	/// Used to store the authentication session.
	private var authenticationSession: AnyObject?
	
	/// Used to store the ASWebAuthenticationPresentationContextProvider
	private var webAuthenticationPresentationContextProvider: AnyObject?
	
	public init(oauth2: OAuth2Base) {
		self.oauth2 = oauth2
	}
	
	
	// MARK: - OAuth2AuthorizerUI
	
	/**
	Uses `UIApplication` to open the authorize URL in iOS's browser.
	
	- parameter url: The authorize URL to open
	- throws: UnableToOpenAuthorizeURL on failure
	*/
	public func openAuthorizeURLInBrowser(_ url: URL) throws {
		
		#if !P2_APP_EXTENSIONS && !os(visionOS)
		Task {
			guard await UIApplication.shared.canOpenURL(url) else {
				throw OAuth2Error.unableToOpenAuthorizeURL
			}
			await UIApplication.shared.open(url) { didOpen in
				if !didOpen {
					Task { @OAuth2Actor in
						self.oauth2.logger?.warn("OAuth2", msg: "Unable to open authorize URL")
					}
				}
			}
		}
		#else
		throw OAuth2Error.unableToOpenAuthorizeURL
		#endif
	}
	
	/**
	Tries to use the current auth config context, which on iOS should be a UIViewController, to present the authorization screen.
	
	- throws:         Can throw OAuth2Error if the method is unable to show the authorize screen
	- parameter with: The configuration to be used; usually uses the instance's `authConfig`
	- parameter at:   The authorize URL to open
	*/
	public func authorizeEmbedded(with config: OAuth2AuthConfig, at url: URL) async throws {
		if config.ui.useAuthenticationSession {
			guard let redirect = oauth2.redirect else {
				throw OAuth2Error.noRedirectURL
			}
			
			authenticationSessionEmbedded(at: url, withRedirect: redirect, prefersEphemeralWebBrowserSession: config.ui.prefersEphemeralWebBrowserSession)
		} else {
			#if os(visionOS)
			throw OAuth2Error.invalidAuthorizationConfiguration("visionOS only supports ASWebAuthenticationSession")
			#else
			guard let controller = config.authorizeContext as? UIViewController else {
				throw (nil == config.authorizeContext) ? OAuth2Error.noAuthorizationContext : OAuth2Error.invalidAuthorizationContext
			}
			
			let web = try await authorizeSafariEmbedded(from: controller, at: url)
			if config.authorizeEmbeddedAutoDismiss {
				oauth2.internalAfterAuthorizeOrFail = { wasFailure, error in
					self.safariViewDelegate = nil
					Task {
						await web.dismiss(animated: true)
					}
				}
			}
			#endif
		}
	}
	
	/**
	Called with the view- and (possibly) navigation-controller that is about to be presented. Useful for subclasses, default implementation
	does nothing.
	
	- parameter viewController: The Safari- or web view controller that will be presented
	- parameter naviController: The navigation controller embedding the view controller, if any
	*/
	open func willPresent(viewController: UIViewController, in naviController: UINavigationController?) {
	}
	
	// MARK: - SFAuthenticationSession / ASWebAuthenticationSession
	
	/**
	Use SFAuthenticationSession or ASWebAuthenticationSession to manage authorisation.
	
	On iOS 11, use SFAuthenticationSession. On iOS 12+, use ASWebAuthenticationSession.
	
	The mechanism works just like when you're using Safari itself to log the user in, hence you **need to implement**
	`application(application:openURL:sourceApplication:annotation:)` in your application delegate.
	
	This method dismisses the view controller automatically - this cannot be disabled.
	
	- parameter at:       The authorize URL to open
	- parameter redirect: The full redirect URL to use
	- parameter prefersEphemeralWebBrowserSession: may be passed through to [ASWebAuthenticationSession](https://developer.apple.com/documentation/authenticationservices/aswebauthenticationsession/3237231-prefersephemeralwebbrowsersessio).
	- returns:            A Boolean value indicating whether the web authentication session starts successfully.
	*/
	@available(iOS 11.0, *)
	@discardableResult
	public func authenticationSessionEmbedded(at url: URL, withRedirect redirect: String, prefersEphemeralWebBrowserSession: Bool = false) -> Bool {
		guard let redirectURL = URL(string: redirect) else {
			oauth2.logger?.warn("OAuth2", msg: "Unable to parse redirect URL ”(redirect)“")
			return false
		}
		let completionHandler: (URL?, Error?) -> Void = { url, error in
			if let url = url {
				Task {
					do {
						try await self.oauth2.handleRedirectURL(url as URL)
					}
					catch {
						self.oauth2.logger?.warn("OAuth2", msg: "Cannot intercept redirect URL: \(error)")
					}
				}
			} else {
				if let authenticationSessionError = error as? ASWebAuthenticationSessionError {
					switch authenticationSessionError.code {
					case .canceledLogin:
						self.oauth2.didFail(with: .requestCancelled)
					default:
						self.oauth2.didFail(with: error?.asOAuth2Error)
					}
				}
				else {
					self.oauth2.didFail(with: error?.asOAuth2Error)
				}
			}
			self.authenticationSession = nil
			self.webAuthenticationPresentationContextProvider = nil
		}
		
		authenticationSession = ASWebAuthenticationSession(url: url, callbackURLScheme: redirectURL.scheme, completionHandler: completionHandler)
		if #available(iOS 13.0, macCatalyst 13.1, *) {
			webAuthenticationPresentationContextProvider = OAuth2ASWebAuthenticationPresentationContextProvider(authorizer: self)
			if let session = authenticationSession as? ASWebAuthenticationSession {
				session.presentationContextProvider = webAuthenticationPresentationContextProvider as! OAuth2ASWebAuthenticationPresentationContextProvider
				session.prefersEphemeralWebBrowserSession = prefersEphemeralWebBrowserSession
			}
		}
		return (authenticationSession as! ASWebAuthenticationSession).start()
	}
	
	
	// MARK: - Safari Web View Controller
	#if os(visionOS) // Intentionally blank per Apple documentation
	#elseif os(iOS)
	/**
	Presents a Safari view controller from the supplied view controller, loading the authorize URL.
	
	The mechanism works just like when you're using Safari itself to log the user in, hence you **need to implement**
	`application(application:openURL:sourceApplication:annotation:)` in your application delegate.
	
	This method does NOT dismiss the view controller automatically, you probably want to do this in the callback.
	Simply call this method first, then call `dismissViewController()` on the returned web view controller instance in that closure. Or use
	`authorizeEmbedded(with:at:)` which does all this automatically.
	
	- parameter from: The view controller to use for presentation
	- parameter at:   The authorize URL to open
	- returns:        SFSafariViewController, being already presented automatically
	*/
	@discardableResult
	public func authorizeSafariEmbedded(from controller: UIViewController, at url: URL) async throws -> SFSafariViewController {
		return await Task {
			safariViewDelegate = await OAuth2SFViewControllerDelegate(authorizer: self)
			let web = await SFSafariViewController(url: url)
			Task { @MainActor in
				web.title = await oauth2.authConfig.ui.title
				web.delegate = await safariViewDelegate
			}
			if let barTint = oauth2.authConfig.ui.barTintColor {
				Task { @MainActor in
					web.preferredBarTintColor = barTint
				}
			}
			if let tint = oauth2.authConfig.ui.controlTintColor {
				Task { @MainActor in
					web.preferredControlTintColor = tint
				}
			}
			Task { @MainActor in
				web.modalPresentationStyle = await oauth2.authConfig.ui.modalPresentationStyle
			}
			
			willPresent(viewController: web, in: nil)
			await controller.present(web, animated: true, completion: nil)
			Task { @MainActor in
				web.presentationController?.delegate = await safariViewDelegate
			}
			return web
		}.value
	}
	
	
	/**
	Called from our delegate, which reacts to users pressing "Done". We can assume this is always a cancel as nomally the Safari view
	controller is dismissed automatically.
	*/
	func safariViewControllerDidCancel(_ safari: SFSafariViewController) {
		safariViewDelegate = nil
		oauth2.didFail(with: nil)
	}
	#endif
}


#if os(visionOS) // Intentionally blank per Apple documentation
#elseif os(iOS)
/**
A custom `SFSafariViewControllerDelegate` that we use with the safari view controller.
*/
class OAuth2SFViewControllerDelegate: NSObject, SFSafariViewControllerDelegate, UIAdaptivePresentationControllerDelegate {
	
	weak var authorizer: OAuth2Authorizer?
	
	init(authorizer: OAuth2Authorizer) {
		self.authorizer = authorizer
	}
	
	@available(iOS 9.0, *)
	nonisolated func safariViewControllerDidFinish(_ controller: SFSafariViewController) {
		Task {
			await authorizer?.safariViewControllerDidCancel(controller)
		}
	}

    // called in case ViewController is dismissed via pulling down the presented sheet.
    func presentationControllerDidDismiss(_ presentationController: UIPresentationController) {
        guard let safariViewController = presentationController.presentedViewController as? SFSafariViewController else { return }
		Task {
			await authorizer?.safariViewControllerDidCancel(safariViewController)
		}
    }
}
#endif

@available(iOS 13.0, *)
@OAuth2Actor
class OAuth2ASWebAuthenticationPresentationContextProvider: NSObject, ASWebAuthenticationPresentationContextProviding {
	
	private let authorizer: OAuth2Authorizer
	
	init(authorizer: OAuth2Authorizer) {
		self.authorizer = authorizer
	}
	
	@OAuth2Actor
	public func presentationAnchor(for session: ASWebAuthenticationSession) -> ASPresentationAnchor {
		if let context = authorizer.oauth2.authConfig.authorizeContext as? ASPresentationAnchor {
			return context
		}
		
		if let context = authorizer.oauth2.authConfig.authorizeContext as? UIViewController {
			return context.view.window!
		}
		
		fatalError("Invalid authConfig.authorizeContext, must be an ASPresentationAnchor or UIViewController but is \(type(of: authorizer.oauth2.authConfig.authorizeContext))")
	}
}

#endif
