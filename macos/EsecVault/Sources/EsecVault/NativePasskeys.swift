import AppKit
import AuthenticationServices
import CryptoKit
import Security

// This process has no custom authentication window. Credential selection,
// security-key PINs, biometrics and cancellation belong to macOS.
@MainActor
enum NativePasskeyHelper {
    struct Input: Codable {
        let credentialID: Data
        let salt: Data
    }
    struct Request: Decodable {
        let operation: String
        let rpID: String
        let provider: String?
        let name: String?
        let userID: Data?
        let salt: Data?
        let credentials: [Input]?
    }
    struct Response: Encodable {
        var credentialID: Data?
        var prf: Data?
        var error: String?
    }
    struct Failure: LocalizedError {
        let message: String
        var errorDescription: String? { message }
    }

    static func run() {
        let app = NSApplication.shared
        app.setActivationPolicy(.accessory)
        Task { @MainActor in
            do {
                guard #available(macOS 15.0, *) else {
                    throw Failure(message: "Passkey encryption requires macOS 15 or later.")
                }
                var data = Data()
                while let chunk = try FileHandle.standardInput.read(upToCount: 4096), !chunk.isEmpty {
                    data.append(chunk)
                    guard data.count <= 65536 else { throw Failure(message: "Passkey request is too large.") }
                }
                let request = try JSONDecoder().decode(Request.self, from: data)
                guard Bundle.main.object(forInfoDictionaryKey: "EsecPasskeysEnabled") as? Bool == true else {
                    throw Failure(message: "Native passkeys require a signed esec Vault app with its Associated Domains provisioning profile.")
                }
                guard request.rpID == Bundle.main.object(forInfoDictionaryKey: "EsecPasskeyRelyingParty") as? String else {
                    throw Failure(message: "This passkey belongs to a domain this app is not configured to use.")
                }
                let sheet = NativePasskeySheet()
                let response = try await sheet.perform(request)
                finish(response)
            } catch {
                // The native API error contains no credential secrets. Never
                // print request/response objects or a PRF result to stderr.
                finish(Response(error: error.localizedDescription))
            }
        }
        app.run()
    }

    private static func finish(_ response: Response) {
        if let data = try? JSONEncoder().encode(response) {
            FileHandle.standardOutput.write(data)
        }
        exit(0)
    }
}

@available(macOS 15.0, *)
@MainActor
private final class NativePasskeySheet: NSObject, ASAuthorizationControllerDelegate, ASAuthorizationControllerPresentationContextProviding {
    private var continuation: CheckedContinuation<any ASAuthorizationCredential, any Error>?
    private var controller: ASAuthorizationController?
    // A transparent anchor lets AuthenticationServices present its own sheet
    // when launched by the CLI or daemon, without showing a second app UI.
    private let anchor = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 1, height: 1), styleMask: .borderless, backing: .buffered, defer: false)

    func perform(_ request: NativePasskeyHelper.Request) async throws -> NativePasskeyHelper.Response {
        anchor.isOpaque = false
        anchor.backgroundColor = .clear
        anchor.center()
        anchor.orderFrontRegardless()
        NSApp.activate()
        if request.operation == "register" { return try await register(request) }
        guard request.operation == "assert" else { throw failure("Unknown passkey operation.") }
        return try await assert(request.rpID, inputs: request.credentials ?? [])
    }

    private func register(_ input: NativePasskeyHelper.Request) async throws -> NativePasskeyHelper.Response {
        guard let salt = input.salt, salt.count == 32, let userID = input.userID, userID.count == 32,
              let name = input.name, !name.isEmpty, name.utf8.count <= 256 else { throw failure("Invalid passkey registration.") }
        let request: ASAuthorizationRequest
        if input.provider == "security-key" {
            guard #available(macOS 26.4, *) else { throw failure("Native YubiKey passkey encryption requires macOS 26.4 or later.") }
            let provider = ASAuthorizationSecurityKeyPublicKeyCredentialProvider(relyingPartyIdentifier: input.rpID)
            let registration = provider.createCredentialRegistrationRequest(challenge: try challenge(), displayName: name, name: name, userID: userID)
            registration.credentialParameters = [ASAuthorizationPublicKeyCredentialParameters(algorithm: .ES256)]
            registration.residentKeyPreference = .required
            registration.userVerificationPreference = .required
            registration.prf = .inputValues(.init(saltInput1: salt))
            request = registration
        } else {
            guard input.provider == "platform" else { throw failure("Choose a password-manager passkey or a security key.") }
            let provider = ASAuthorizationPlatformPublicKeyCredentialProvider(relyingPartyIdentifier: input.rpID)
            let registration = provider.createCredentialRegistrationRequest(challenge: try challenge(), name: name, userID: userID)
            registration.userVerificationPreference = .required
            registration.prf = .inputValues(.init(saltInput1: salt))
            request = registration
        }
        let credential = try await authorize([request])
        let id: Data
        let supported: Bool
        if let registration = credential as? ASAuthorizationPlatformPublicKeyCredentialRegistration {
            id = registration.credentialID
            supported = registration.prf?.isSupported == true
        } else if #available(macOS 26.4, *), let registration = credential as? ASAuthorizationSecurityKeyPublicKeyCredentialRegistration {
            id = registration.credentialID
            supported = registration.prf?.isSupported == true
        } else { throw failure("Unexpected passkey registration response.") }
        guard supported else { throw failure("This passkey provider does not support encryption (WebAuthn PRF). No vault keys were changed.") }
        // Confirm PRF works during a real unlock before registering a key as
        // a reader. Some providers only return it from an assertion.
        return try await assert(input.rpID, inputs: [.init(credentialID: id, salt: salt)])
    }

    private func assert(_ rpID: String, inputs: [NativePasskeyHelper.Input]) async throws -> NativePasskeyHelper.Response {
        guard !inputs.isEmpty, inputs.count <= 20,
              inputs.allSatisfy({ !$0.credentialID.isEmpty && $0.credentialID.count <= 1024 && $0.salt.count == 32 }),
              Set(inputs.map(\.credentialID)).count == inputs.count else { throw failure("Invalid passkey unlock request.") }
        let challenge = try challenge()
        let salts = Dictionary(uniqueKeysWithValues: inputs.map { ($0.credentialID, ASAuthorizationPublicKeyCredentialPRFAssertionInput.InputValues(saltInput1: $0.salt)) })
        let platform = ASAuthorizationPlatformPublicKeyCredentialProvider(relyingPartyIdentifier: rpID).createCredentialAssertionRequest(challenge: challenge)
        platform.userVerificationPreference = .required
        platform.allowedCredentials = inputs.map { ASAuthorizationPlatformPublicKeyCredentialDescriptor(credentialID: $0.credentialID) }
        platform.prf = .perCredentialInputValues(salts)
        var requests: [ASAuthorizationRequest] = [platform]
        if #available(macOS 26.4, *) {
            let hardware = ASAuthorizationSecurityKeyPublicKeyCredentialProvider(relyingPartyIdentifier: rpID).createCredentialAssertionRequest(challenge: challenge)
            hardware.userVerificationPreference = .required
            hardware.allowedCredentials = inputs.map { ASAuthorizationSecurityKeyPublicKeyCredentialDescriptor(credentialID: $0.credentialID, transports: [.usb, .nfc, .bluetooth]) }
            hardware.prf = .perCredentialInputValues(salts)
            requests.append(hardware)
        }
        let credential = try await authorize(requests)
        let id: Data
        let prf: ASAuthorizationPublicKeyCredentialPRFAssertionOutput?
        let authenticatorData: Data
        if let assertion = credential as? ASAuthorizationPlatformPublicKeyCredentialAssertion {
            id = assertion.credentialID
            prf = assertion.prf
            authenticatorData = assertion.rawAuthenticatorData
        } else if #available(macOS 26.4, *), let assertion = credential as? ASAuthorizationSecurityKeyPublicKeyCredentialAssertion {
            id = assertion.credentialID
            prf = assertion.prf
            authenticatorData = assertion.rawAuthenticatorData
        } else { throw failure("Unexpected passkey unlock response.") }
        guard inputs.contains(where: { $0.credentialID == id }), authenticatorData.count >= 37,
              authenticatorData[32] & 0x05 == 0x05,
              Data(authenticatorData.prefix(32)) == Data(SHA256.hash(data: Data(rpID.utf8))) else {
            throw failure("The passkey did not verify the requested account and user.")
        }
        guard let prf else { throw failure("This passkey provider did not return an encryption secret (WebAuthn PRF).") }
        return NativePasskeyHelper.Response(credentialID: id, prf: prf.first.withUnsafeBytes { Data($0) })
    }

    private func authorize(_ requests: [ASAuthorizationRequest]) async throws -> any ASAuthorizationCredential {
        guard continuation == nil else { throw failure("Another passkey request is already active.") }
        return try await withCheckedThrowingContinuation { continuation in
            self.continuation = continuation
            let controller = ASAuthorizationController(authorizationRequests: requests)
            self.controller = controller
            controller.delegate = self
            controller.presentationContextProvider = self
            controller.performRequests()
        }
    }

    func presentationAnchor(for controller: ASAuthorizationController) -> ASPresentationAnchor { anchor }
    func authorizationController(controller: ASAuthorizationController, didCompleteWithAuthorization authorization: ASAuthorization) {
        let pending = continuation
        continuation = nil
        self.controller = nil
        pending?.resume(returning: authorization.credential)
    }
    func authorizationController(controller: ASAuthorizationController, didCompleteWithError error: any Error) {
        let pending = continuation
        continuation = nil
        self.controller = nil
        pending?.resume(throwing: error)
    }
    private func challenge() throws -> Data {
        var bytes = [UInt8](repeating: 0, count: 32)
        guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess else { throw failure("Could not generate a passkey challenge.") }
        return Data(bytes)
    }
    private func failure(_ message: String) -> NativePasskeyHelper.Failure { .init(message: message) }
}
