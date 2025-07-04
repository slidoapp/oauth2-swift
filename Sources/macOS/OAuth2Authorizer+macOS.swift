//
//  OAuth2Authorizer+macOS.swift
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
#if os(macOS)

import Cocoa
#if !NO_MODULE_IMPORT
import Base
#endif

#if canImport(AuthenticationServices)
import AuthenticationServices
#endif

/**
The authorizer to use when on the macOS platform.
	
You can subclass this class and override `presentableAuthorizeViewController(url:)` and/or `windowController(controller:config:)` to further
customize appearance.
*/
open class OAuth2Authorizer: OAuth2AuthorizerUI {
	
	/// The OAuth2 instance this authorizer belongs to.
	public unowned let oauth2: OAuth2Base
	
	/// Stores the default `NSWindowController` created to contain the web view controller.
	var windowController: NSWindowController?
	
	/// Used to store the authentication session.
	var authenticationSession: AnyObject?
	
	var webAuthenticationPresentationContextProvider: AnyObject?
	
	/**
	Designated initializer.
	
	- parameter oauth2: The OAuth2 instance for which to present an authorization UI
	*/
	public init(oauth2: OAuth2Base) {
		self.oauth2 = oauth2
	}
	
	
	// MARK: - OAuth2AuthorizerUI
	
	
	/**
	Uses `NSWorkspace` to open the authorize URL in the OS browser.
	
	- parameter url: The authorize URL to open
	- throws:        UnableToOpenAuthorizeURL on failure
	*/
	public func openAuthorizeURLInBrowser(_ url: URL) throws {
		if !NSWorkspace.shared.open(url) {
			throw OAuth2Error.unableToOpenAuthorizeURL
		}
	}
	
	/**
	Tries to use the given context, which on OS X should be a NSWindow, to present the authorization screen. In this case will forward to
	`authorizeEmbedded(from:with:at:)`, if the context is empty will create a new NSWindow by calling `authorizeInNewWindow(with:at:)`.
	
	- parameter with: The configuration to be used; usually uses the instance's `authConfig`
	- parameter at:   The authorize URL to open
	- throws:         Can throw OAuth2Error if the method is unable to show the authorize screen
	*/
	public func authorizeEmbedded(with config: OAuth2AuthConfig, at url: URL) async throws {
		if #available(macOS 10.15, *), config.ui.useAuthenticationSession {
			guard let redirect = oauth2.redirect else {
				throw OAuth2Error.noRedirectURL
			}
			
			try await startAuthenticationSession(at: url,
												withRedirect: redirect,
												prefersEphemeralWebBrowserSession: config.ui.prefersEphemeralWebBrowserSession)
			return
		}
		
		// present as sheet
		if let window = config.authorizeContext as? NSWindow {
			let sheet = try await authorizeEmbedded(from: window, at: url)
			if config.authorizeEmbeddedAutoDismiss {
				oauth2.internalAfterAuthorizeOrFail = { wasFailure, error in
					Task { @MainActor in
						window.endSheet(sheet)
					}
				}
			}
		}
		
		// present in new window (or with custom block)
		else {
			windowController = try await authorizeInNewWindow(at: url)
			if config.authorizeEmbeddedAutoDismiss {
				oauth2.internalAfterAuthorizeOrFail = { wasFailure, error in
					Task { @MainActor in
						await self.windowController?.window?.close()
					}
					self.windowController = nil
				}
			}
		}
	}
	
	#if canImport(AuthenticationServices)
	@available(macOS 10.15, *)
	@discardableResult
	public func startAuthenticationSession(
		at url: URL,
		withRedirect redirect: String,
		prefersEphemeralWebBrowserSession: Bool = false
	) async throws -> Bool {
		guard let redirectURL = URL(string: redirect) else {
			throw OAuth2Error.invalidRedirectURL(redirect)
		}
		
		let completionHandler: (URL?, Error?) -> Void = { url, error in
			if let url {
				Task {
					do {
						try await self.oauth2.handleRedirectURL(url)
					} catch let err {
						self.oauth2.logger?.warn("OAuth2", msg: "Cannot intercept redirect URL: \(err)")
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
				} else {
					self.oauth2.didFail(with: error?.asOAuth2Error)
				}
			}
			self.authenticationSession = nil
			self.webAuthenticationPresentationContextProvider = nil
		}
		
		authenticationSession = ASWebAuthenticationSession(url: url,
														   callbackURLScheme: redirectURL.scheme,
														   completionHandler: completionHandler)
		webAuthenticationPresentationContextProvider = await OAuth2ASWebAuthenticationPresentationContextProvider(authorizer: self)
		if let session = authenticationSession as? ASWebAuthenticationSession {
			session.presentationContextProvider = webAuthenticationPresentationContextProvider as! OAuth2ASWebAuthenticationPresentationContextProvider
			session.prefersEphemeralWebBrowserSession = prefersEphemeralWebBrowserSession
		}
		return (authenticationSession as! ASWebAuthenticationSession).start()
	}
	#endif
	
	
	// MARK: - Window Creation
	
	/**
	Presents a modal sheet from the given window.
	
	- parameter from: The window from which to present the sheet
	- parameter at:   The authorize URL to open
	- returns:        The sheet that is being queued for presentation
	*/
	@available(macOS 10.10, *)
	@discardableResult
	public func authorizeEmbedded(from window: NSWindow, at url: URL) async throws -> NSWindow {
		let controller = try await presentableAuthorizeViewController(at: url)
		controller.willBecomeSheet = true
		let sheet = await windowController(forViewController: controller, with: oauth2.authConfig).window!
		
		await window.makeKeyAndOrderFront(nil)
		await window.beginSheet(sheet, completionHandler: nil)
		
		return sheet
	}
	
	/**
	Creates a new window, containing our `OAuth2WebViewController`, and centers it on the screen.
	
	- parameter at:   The authorize URL to open
	- returns:        The window that is being shown on screen
	*/
	@available(macOS 10.10, *)
	@discardableResult
	open func authorizeInNewWindow(at url: URL) async throws -> NSWindowController {
		let controller = try await presentableAuthorizeViewController(at: url)
		let wc = await windowController(forViewController: controller, with: oauth2.authConfig)
		
		await wc.window?.center()
		await wc.showWindow(nil)
		
		return wc
	}
	
	/**
	Instantiates and configures an `OAuth2WebViewController`, ready to be used in a window.
	
	- parameter at: The authorize URL to open
	- returns:      A web view controller that you can present to the user for login
	*/
	@available(macOS 10.10, *)
	open func presentableAuthorizeViewController(at url: URL) async throws -> OAuth2WebViewController {
		let controller = await OAuth2WebViewController()
		controller.oauth = oauth2
		controller.startURL = url
		controller.interceptURLString = oauth2.redirect!
	
		controller.onIntercept = { url in
			do {
				try await self.oauth2.handleRedirectURL(url)
				return true
			}
			catch let error {
				self.oauth2.logger?.warn("OAuth2", msg: "Cannot intercept redirect URL: \(error)")
			}
			return false
		}
		controller.onWillCancel = {
			Task {
				await self.oauth2.didFail(with: nil)
			}
		}
		return controller
	}
	
	/**
	Prepares a window controller with the given web view controller as content.
	
	- parameter forViewController: The web view controller to use as content
	- parameter with: The auth config to use
	- returns:                     A window controller, ready to be presented
	*/
	@available(macOS 10.10, *)
	@MainActor
	open func windowController(forViewController controller: OAuth2WebViewController, with config: OAuth2AuthConfig) -> NSWindowController {
		let rect = NSMakeRect(0, 0, OAuth2WebViewController.webViewWindowWidth, OAuth2WebViewController.webViewWindowHeight)
		let window = NSWindow(contentRect: rect, styleMask: [.titled, .closable, .resizable, .fullSizeContentView], backing: .buffered, defer: false)
		window.backgroundColor = NSColor.white
		window.isMovableByWindowBackground = true
		window.titlebarAppearsTransparent = true
		window.titleVisibility = .hidden
		window.animationBehavior = .alertPanel
		if let title = config.ui.title {
			window.title = title
		}
		
		let windowController = NSWindowController(window: window)
		windowController.contentViewController = controller
		
		return windowController
	}
}

#if canImport(AuthenticationServices)
@available(macOS 10.15, *)
class OAuth2ASWebAuthenticationPresentationContextProvider: NSObject, ASWebAuthenticationPresentationContextProviding {
	
	private let authorizer: OAuth2Authorizer
	
	init(authorizer: OAuth2Authorizer) {
		self.authorizer = authorizer
	}
	
	@OAuth2Actor /// For Xcode 15, we need to specify the `@OAuth2Actor` explicitly, but in Xcode 16 this is no longer necessary. 🤷‍♂️
	public func presentationAnchor(for session: ASWebAuthenticationSession) -> ASPresentationAnchor {
		if let context = authorizer.oauth2.authConfig.authorizeContext as? ASPresentationAnchor {
			return context
		}
		fatalError("Invalid authConfig.authorizeContext, must be an ASPresentationAnchor but is \(type(of: authorizer.oauth2.authConfig.authorizeContext))")
	}
}
#endif

#endif
