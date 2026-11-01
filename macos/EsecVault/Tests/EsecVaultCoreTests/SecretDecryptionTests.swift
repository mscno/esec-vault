import EsecVaultCore
import Foundation
import Testing

@Test func decryptionMetadataIsOptionalAndUnknownRoutesStayUnknown() throws {
    let old = #"{"file":{"path":"/test/.env.dev","env":"dev","format":".env"},"revision":"x","values":[]}"#
    let document = try JSON.decoder.decode(SecretDocument.self, from: Data(old.utf8))
    #expect(document.decryption == nil)
    let future = try JSON.decoder.decode(SecretDecryption.self, from: Data(#"{"source":"future_route","guard":"future_guard"}"#.utf8))
    #expect(future.title == "Route unavailable")
    #expect(!future.explanation.contains("broker was not used"))
}

@Test func brokerTooltipExplainsSessionAndForwardingWithoutClaimingFreshApproval() throws {
    let broker = try JSON.decoder.decode(SecretDecryption.self, from: Data(#"{"source":"forwarded_broker","guard":"session"}"#.utf8))
    #expect(broker.title == "Forwarded broker")
    #expect(broker.explanation.contains("connected machine"))
    #expect(broker.explanation.contains("existing unlocked session may be reused"))
    #expect(broker.explanation.contains("Last successful decryption"))
}
