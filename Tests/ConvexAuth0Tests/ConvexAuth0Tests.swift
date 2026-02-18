import Auth0
import Foundation
import Testing

@testable import ConvexAuth0

// MARK: - Helpers

private func makeJWT(exp: Date) -> String {
  let header = #"{"alg":"RS256","typ":"JWT"}"#
  let payload = "{\"sub\":\"test\",\"exp\":\(Int(exp.timeIntervalSince1970))}"

  func base64url(_ string: String) -> String {
    Data(string.utf8)
      .base64EncodedString()
      .replacingOccurrences(of: "+", with: "-")
      .replacingOccurrences(of: "/", with: "_")
      .replacingOccurrences(of: "=", with: "")
  }

  return "\(base64url(header)).\(base64url(payload)).fakesig"
}

private func makeCredentials(idToken: String) -> Credentials {
  Credentials(
    accessToken: "access_token",
    tokenType: "Bearer",
    idToken: idToken,
    refreshToken: "refresh_token",
    expiresIn: Date().addingTimeInterval(3600)
  )
}

// MARK: - Mock

final class MockCredentialsManager: CredentialsManaging, @unchecked Sendable {
  let storedCredentials: Credentials
  let renewedCredentials: Credentials
  private(set) var renewCallCount = 0

  init(idToken: String, renewedIdToken: String = "renewed_id_token") {
    storedCredentials = makeCredentials(idToken: idToken)
    renewedCredentials = makeCredentials(idToken: renewedIdToken)
  }

  func credentials() async throws -> Credentials { storedCredentials }
  func renew() async throws -> Credentials {
    renewCallCount += 1
    return renewedCredentials
  }
  func store(credentials: Credentials) -> Bool { true }
  func clear() async {}
}

// MARK: - idTokenExpiry tests

@Suite("idTokenExpiry")
struct IdTokenExpiryTests {
  // idTokenExpiry is internal, accessible via @testable import
  let provider = Auth0Provider(
    credentialsManager: MockCredentialsManager(idToken: "placeholder"))

  @Test func parsesExpiryFromValidToken() {
    let expected = Date(timeIntervalSince1970: 9_999_999_999)
    let result = provider.idTokenExpiry(from: makeJWT(exp: expected))
    #expect(result != nil)
    #expect(abs(result!.timeIntervalSince1970 - expected.timeIntervalSince1970) < 1)
  }

  @Test func parsesPastExpiryFromExpiredToken() {
    let expired = Date(timeIntervalSinceNow: -3600)
    let result = provider.idTokenExpiry(from: makeJWT(exp: expired))
    #expect(result != nil)
    #expect(result! < Date())
  }

  @Test func returnsNilForTooFewSegments() {
    #expect(provider.idTokenExpiry(from: "onlyone") == nil)
    #expect(provider.idTokenExpiry(from: "") == nil)
  }

  @Test func returnsNilForTooManySegments() {
    #expect(provider.idTokenExpiry(from: "a.b.c.d") == nil)
  }

  @Test func returnsNilWhenExpClaimMissing() {
    func base64url(_ s: String) -> String {
      Data(s.utf8).base64EncodedString()
        .replacingOccurrences(of: "+", with: "-")
        .replacingOccurrences(of: "/", with: "_")
        .replacingOccurrences(of: "=", with: "")
    }
    let jwt =
      "\(base64url(#"{"alg":"RS256"}"#)).\(base64url(#"{"sub":"test"}"#)).fakesig"
    #expect(provider.idTokenExpiry(from: jwt) == nil)
  }
}

// MARK: - loginFromCache tests

@Suite("loginFromCache")
struct LoginFromCacheTests {
  @Test func returnsCachedCredentialsWhenIdTokenIsFresh() async throws {
    let freshJWT = makeJWT(exp: Date(timeIntervalSinceNow: 3600))  // 60 min left
    let mock = MockCredentialsManager(idToken: freshJWT)
    let provider = Auth0Provider(credentialsManager: mock, idTokenGracePeriod: 30 * 60)

    let result = try await provider.loginFromCache(onIdToken: { _ in })

    #expect(result.idToken == freshJWT)
    #expect(mock.renewCallCount == 0)
  }

  @Test func renewsWhenIdTokenIsExpired() async throws {
    let expiredJWT = makeJWT(exp: Date(timeIntervalSinceNow: -60))
    let mock = MockCredentialsManager(idToken: expiredJWT, renewedIdToken: "renewed_token")
    let provider = Auth0Provider(credentialsManager: mock, idTokenGracePeriod: 30 * 60)

    let result = try await provider.loginFromCache(onIdToken: { _ in })

    #expect(mock.renewCallCount == 1)
    #expect(result.idToken == "renewed_token")
  }

  @Test func renewsWhenIdTokenIsWithinGracePeriod() async throws {
    let soonJWT = makeJWT(exp: Date(timeIntervalSinceNow: 10 * 60))  // 10 min left
    let mock = MockCredentialsManager(idToken: soonJWT, renewedIdToken: "renewed_token")
    let provider = Auth0Provider(credentialsManager: mock, idTokenGracePeriod: 30 * 60)

    let result = try await provider.loginFromCache(onIdToken: { _ in })

    #expect(mock.renewCallCount == 1)
    #expect(result.idToken == "renewed_token")
  }

  @Test func doesNotRenewWhenIdTokenExpiresAfterGracePeriod() async throws {
    let jwt = makeJWT(exp: Date(timeIntervalSinceNow: 45 * 60))  // 45 min left
    let mock = MockCredentialsManager(idToken: jwt)
    let provider = Auth0Provider(credentialsManager: mock, idTokenGracePeriod: 30 * 60)

    _ = try await provider.loginFromCache(onIdToken: { _ in })

    #expect(mock.renewCallCount == 0)
  }

  @Test func respectsCustomGracePeriod() async throws {
    // 5 min remaining, custom grace period of 10 min → should renew
    let jwt = makeJWT(exp: Date(timeIntervalSinceNow: 5 * 60))
    let mock = MockCredentialsManager(idToken: jwt, renewedIdToken: "renewed_token")
    let provider = Auth0Provider(credentialsManager: mock, idTokenGracePeriod: 10 * 60)

    let result = try await provider.loginFromCache(onIdToken: { _ in })

    #expect(mock.renewCallCount == 1)
    #expect(result.idToken == "renewed_token")
  }

  @Test func returnsCachedCredentialsWhenTokenIsUnparseable() async throws {
    let mock = MockCredentialsManager(idToken: "not_a_real_jwt")
    let provider = Auth0Provider(credentialsManager: mock, idTokenGracePeriod: 30 * 60)

    let result = try await provider.loginFromCache(onIdToken: { _ in })

    #expect(result.idToken == "not_a_real_jwt")
    #expect(mock.renewCallCount == 0)
  }
}
