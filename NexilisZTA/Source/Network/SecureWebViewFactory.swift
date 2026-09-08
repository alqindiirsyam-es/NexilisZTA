//
//  SecureWebViewFactory.swift
//  Nexilis iOS ZTA — J3 WKWebView hardening
//
//  The bundle has many WKWebViews (WebView3–6, BNIBookingWebView, the tab
//  controllers). With ATS re-enabled (see guide §1) the cleartext risk drops; this
//  closes the remaining bridge/navigation discipline:
//    - JavaScript OFF unless a first-party page needs it
//    - non-persistent data store (no cookie/cache residue)
//    - fraudulent-website warning ON
//    - no auto-opened windows
//    - navigation restricted to an HTTPS host allow-list
//    - a script-message handler ONLY on first-party pages, validated
//

import WebKit

public enum SecureWebViewFactory {

    /// Hardened config for a WebView that loads arbitrary / partner URLs — NO bridge.
    public static func hardenedConfig() -> WKWebViewConfiguration {
        let cfg = WKWebViewConfiguration()
        let prefs = WKWebpagePreferences()
        prefs.allowsContentJavaScript = false
        cfg.defaultWebpagePreferences = prefs
        cfg.preferences.isFraudulentWebsiteWarningEnabled = true
        cfg.preferences.javaScriptCanOpenWindowsAutomatically = false
        cfg.websiteDataStore = .nonPersistent()
        return cfg
    }

    /// Config for a FIRST-PARTY in-app page that needs JS + a named, validated bridge.
    public static func firstPartyConfig(messageHandler: WKScriptMessageHandler,
                                        name: String) -> WKWebViewConfiguration {
        let cfg = hardenedConfig()
        let prefs = WKWebpagePreferences()
        prefs.allowsContentJavaScript = true
        cfg.defaultWebpagePreferences = prefs
        cfg.userContentController.add(messageHandler, name: name) // handler must validate body
        return cfg
    }

    // MARK: - First-party pages that carry the app's own bridge
    //
    // `hardenedConfig` above is for a WebView that loads arbitrary or partner URLs, and it turns
    // JavaScript off. The tab controllers and WebView3-6 are not that: each one installs around
    // twenty script-message handlers, injects cookies and runs jQuery against the page. Handing
    // them `hardenedConfig` would not harden them, it would blank them.
    //
    // So they get the parts of the same hardening that a bridge page can actually keep: the
    // fraudulent-website warning on, no window the page opens by itself, and JavaScript on because
    // without it there is no page. The bridge itself stays the caller's job - each handler must
    // still validate its own message body, which no configuration can do for it.
    public static func firstPartyBridgeConfig() -> WKWebViewConfiguration {
        let cfg = WKWebViewConfiguration()
        let prefs = WKWebpagePreferences()
        prefs.allowsContentJavaScript = true
        cfg.defaultWebpagePreferences = prefs
        cfg.preferences.isFraudulentWebsiteWarningEnabled = true
        cfg.preferences.javaScriptCanOpenWindowsAutomatically = false
        if usesNonPersistentDataStoreForBridgePages {
            cfg.websiteDataStore = .nonPersistent()
        }
        return cfg
    }

    /// Whether first-party bridge pages also get a non-persistent data store.
    ///
    /// Off by default, and deliberately a switch rather than a decision baked into the function
    /// above. A non-persistent store is the one piece of this hardening that changes what the page
    /// can do rather than what it is allowed to do: cookies, localStorage and any session the page
    /// keeps for itself are gone the moment the WebView is released. That is correct for a browser
    /// tab and wrong for a signed-in page that expects to still be signed in tomorrow, and which
    /// of those these pages are is a question the app's own testing answers, not this file.
    public static var usesNonPersistentDataStoreForBridgePages = false

    /// Attach to restrict navigation to an explicit HTTPS host allow-list.
    public static func makeNavigationGuard(allowedHosts: Set<String>) -> WKNavigationDelegate {
        return NavigationGuard(allowedHosts: allowedHosts)
    }

    private final class NavigationGuard: NSObject, WKNavigationDelegate {
        let allowed: Set<String>
        init(allowedHosts: Set<String>) { self.allowed = allowedHosts }

        func webView(_ webView: WKWebView,
                     decidePolicyFor navigationAction: WKNavigationAction,
                     decisionHandler: @escaping (WKNavigationActionPolicy) -> Void) {
            guard let url = navigationAction.request.url,
                  url.scheme?.lowercased() == "https",
                  let host = url.host, allowed.contains(host) else {
                decisionHandler(.cancel)
                return
            }
            decisionHandler(.allow)
        }
    }
}
