// The Swift Programming Language
// https://docs.swift.org/swift-book

import Auth0
import ConvexMobile
import Foundation

private let SCOPES = "openid profile email offline_access"

protocol CredentialsManaging: Sendable {
  func credentials() async throws -> Credentials
  func renew() async throws -> Credentials
  func store(credentials: Credentials) -> Bool
  func clear() async
}

private struct WrappedCredentialsManager: CredentialsManaging {
  private let manager: CredentialsManager

  init(_ manager: CredentialsManager) {
    self.manager = manager
  }

  func credentials() async throws -> Credentials { try await manager.credentials() }
  func renew() async throws -> Credentials { try await manager.renew() }
  func store(credentials: Credentials) -> Bool { manager.store(credentials: credentials) }
  func clear() async { await manager.clear() }
}

/// An ``AuthProvider`` implementation that authenticates Convex requests using Auth0.
///
/// `Auth0Provider` handles the Auth0 login flow and supplies the resulting ID token to Convex.
/// Because Convex uses the ID token (not the access token) for authentication, it manages
/// ID token expiry independently of the session lifetime tracked by Auth0's own
/// `CredentialsManager`. When `loginFromCache` is called, the ID token's expiry is checked
/// and a proactive renewal is performed if it falls within the grace period, ensuring Convex
/// never receives a stale token.
///
/// ### Setting `idTokenGracePeriod`
///
/// Auth0 issues ID tokens with a 10-hour expiry by default, while sessions can last much
/// longer. The grace period controls how far ahead of expiry a renewal is triggered.
///
/// - Use a longer grace period (e.g. the default 30 minutes) when sessions are long-lived
///   and token refreshes are cheap — this gives a comfortable buffer and avoids serving a
///   token that expires mid-request.
/// - Shorten it only if your Auth0 tenant is configured with shorter ID token lifetimes
///   (e.g. a 15-minute token lifetime warrants a grace period no larger than a few minutes).
/// - Never set it to zero: a token that appears valid at check time can expire before it
///   reaches Convex.
///
/// The grace period can be configured at init time:
/// ```swift
/// let auth0 = Auth0Provider(idTokenGracePeriod: 15 * 60) // 15-minute buffer
/// ```
public class Auth0Provider: AuthProvider {
  private let credentialsManager: any CredentialsManaging
  private let idTokenGracePeriod: TimeInterval

  /// Creates an `Auth0Provider`.
  ///
  /// - Parameter idTokenGracePeriod: How many seconds before the ID token expires a renewal
  ///   should be triggered proactively. Defaults to 1800 seconds (30 minutes), which is
  ///   appropriate for Auth0's default 10-hour ID token lifetime. Lower this value only if
  ///   your tenant is configured with shorter ID token lifetimes.
  public init(idTokenGracePeriod: TimeInterval = 30 * 60) {
    credentialsManager = WrappedCredentialsManager(
      CredentialsManager(authentication: Auth0.authentication()))
    self.idTokenGracePeriod = idTokenGracePeriod
  }

  init(credentialsManager: any CredentialsManaging, idTokenGracePeriod: TimeInterval = 30 * 60) {
    self.credentialsManager = credentialsManager
    self.idTokenGracePeriod = idTokenGracePeriod
  }

  public func login(onIdToken: @escaping @Sendable (String?) -> Void) async throws -> Credentials {
    let credentials = try await Auth0.webAuth().scope(SCOPES).start()
    _ = credentialsManager.store(credentials: credentials)
    return credentials
  }

  public func loginFromCache(onIdToken: @escaping @Sendable (String?) -> Void) async throws
    -> Credentials
  {
    let credentials = try await credentialsManager.credentials()
    if let expiry = idTokenExpiry(from: credentials.idToken),
      expiry.timeIntervalSinceNow < idTokenGracePeriod
    {
      return try await credentialsManager.renew()
    }
    return credentials
  }

  public func extractIdToken(from authResult: Credentials) -> String {
    return authResult.idToken
  }

  public typealias T = Credentials

  public func logout() async throws {
    try await Auth0.webAuth().clearSession()
    await credentialsManager.clear()
  }

  func idTokenExpiry(from idToken: String) -> Date? {
    let segments = idToken.split(separator: ".", omittingEmptySubsequences: false)
    guard segments.count == 3 else { return nil }
    var payload = String(segments[1])
    payload =
      payload
      .replacingOccurrences(of: "-", with: "+")
      .replacingOccurrences(of: "_", with: "/")
    let padded = payload.padding(
      toLength: ((payload.count + 3) / 4) * 4, withPad: "=", startingAt: 0)
    guard let data = Data(base64Encoded: padded),
      let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
      let exp = json["exp"] as? TimeInterval
    else { return nil }
    return Date(timeIntervalSince1970: exp)
  }
}
