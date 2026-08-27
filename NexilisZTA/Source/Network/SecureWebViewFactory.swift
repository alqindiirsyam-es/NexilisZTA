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
