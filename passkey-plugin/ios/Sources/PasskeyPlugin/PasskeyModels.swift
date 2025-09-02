//
//  PasskeyModels.swift
//  Pods
//
//  Created by Bence Nagy on 06.07.2025.
//

import AuthenticationServices

@available(iOS 15.0, *)
typealias Base64URLString = String

@available(iOS 15.0, *)
internal struct PasskeyRegistrationOptions: Decodable {
    var rp: PasskeyRpEntity
    var user: PasskeyUserEntity
    var challenge: Base64URLString
    var pubKeyCredParams: [PasskeyCredentialParameters]
    var timeout: Int
    var excludeCredentials: [PasskeyCredentialDescriptor]?
    var authenticatorSelection: PasskeyAuthSelectionCriteria?
    var attestation: PasskeyAttestationConveyancePref?
    var extensions: PasskeyAuthExtensions?
}

@available(iOS 15.0, *)
internal struct PasskeyAuthenticationOptions: Decodable {
    var challenge: Base64URLString
    var rpId: String
    var timeout: Int? = 60000
    var allowCredentials: [PasskeyCredentialDescriptor]?
    var userVerification: PasskeyUserVerificationReq?
    var extensions: PasskeyAuthExtensions?
}

extension Array {
    var pkData: Data { withUnsafeBytes { .init($0) } }
}

@available(iOS 15.0, *)
internal struct PasskeyUserEntity: Decodable {
    var name: String
    var displayName: String
    var id: String
}

@available(iOS 15.0, *)
internal struct PasskeyRpEntity: Decodable {
    var name: String
    var id: String?
}

@available(iOS 15.0, *)
internal struct PasskeyCredentialParameters: Decodable {
    var alg: ASCOSEAlgorithmIdentifier = .ES256
    var type: PasskeyCredentialType = .publicKey
    
    func toAppleParams() -> ASAuthorizationPublicKeyCredentialParameters {
        return ASAuthorizationPublicKeyCredentialParameters.init(algorithm: ASCOSEAlgorithmIdentifier(self.alg.rawValue))
    }
    
    enum CodingKeys: String, CodingKey {
        case alg
        case type
    }
    
   
//    init(from decoder: any Decoder) throws {
//        let container = try decoder.container(keyedBy: CodingKeys.self);
//        
//        let algVal = try container.decodeIfPresent(Int.self, forKey: .alg);
//        if let algInt = algVal {
//            alg = ASCOSEAlgorithmIdentifier(algInt);
//        }
//        
//        let typeValue = try container.decodeIfPresent(String.self, forKey: .type);
//        if let typeString = typeValue {
//            type = PasskeyCredentialType(rawValue: typeString) ?? .publicKey;
//        }
//    }
    
    init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        if let algVal = try container.decodeIfPresent(Int.self, forKey: .alg) {
            alg = ASCOSEAlgorithmIdentifier(algVal)
        }
        if let typeVal = try container.decodeIfPresent(String.self, forKey: .type) {
            type = PasskeyCredentialType(rawValue: typeVal) ?? .publicKey
        }
    }
}

internal enum PasskeyCredentialType: String, Codable {
    case publicKey = "public-key"
}

@available(iOS 15.0, *)
internal struct PasskeyCredentialDescriptor: Decodable {
    var id: Base64URLString
    var transports: [PasskeyAuthTransport]?
    var type: PasskeyCredentialType = .publicKey
    
    func asPlatformDescriptor() -> ASAuthorizationPlatformPublicKeyCredentialDescriptor {
        return ASAuthorizationPlatformPublicKeyCredentialDescriptor.init(credentialID: Data(base64URLEncoded: self.id)!)
    }
    
    func asCrossPlatformDescriptor() -> ASAuthorizationSecurityKeyPublicKeyCredentialDescriptor {
        var trList = ASAuthorizationSecurityKeyPublicKeyCredentialDescriptor.Transport.allSupported
        if self.transports?.isEmpty == false {
            trList = self.transports!.compactMap { $0.toAppleTransport() }
        }
        return ASAuthorizationSecurityKeyPublicKeyCredentialDescriptor.init(credentialID: Data(base64URLEncoded: self.id)!,
                                                                            transports: trList)
    }
    
    enum CodingKeys: String, CodingKey {
        case id
        case transports
        case type
    }
    
    
//    init(from decoder: any Decoder) throws {
//        let container = try decoder.container(keyedBy: CodingKeys.self);
//        id = try container.decodeIfPresent(String.self, forKey: .id)!;
//        transports = try container.decodeIfPresent([PasskeyAuthTransport].self, forKey: .transports);
//        let typeVal = try container.decodeIfPresent(String.self, forKey: .type);
//        if let typeString = typeVal {
//            type = PasskeyCredentialType(rawValue: typeString) ?? .publicKey
//        }
//    }
    
    init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        id = try container.decodeIfPresent(String.self, forKey: .id)!
        transports = try container.decodeIfPresent([PasskeyAuthTransport].self, forKey: .transports)
        if let typeVal = try container.decodeIfPresent(String.self, forKey: .type) {
            type = PasskeyCredentialType(rawValue: typeVal) ?? .publicKey
        }
    }
}

@available(iOS 15.0, *)
internal enum PasskeyAuthTransport: String, Codable {
    case ble
    case hybrid
    case nfc
    case usb
    
    func toAppleTransport() -> ASAuthorizationSecurityKeyPublicKeyCredentialDescriptor.Transport? {
        switch self {
        case .ble:
            return ASAuthorizationSecurityKeyPublicKeyCredentialDescriptor.Transport.bluetooth
        case .nfc:
            return ASAuthorizationSecurityKeyPublicKeyCredentialDescriptor.Transport.nfc
        case .usb:
            return ASAuthorizationSecurityKeyPublicKeyCredentialDescriptor.Transport.usb
        default:
            return nil
        }
    }
}


@available(iOS 15.0, *)
internal struct PasskeyAuthSelectionCriteria: Decodable {
    var authenticatorAttachment: PasskeyAuthAttachment?
    var residentKey: PasskeyResidentKeyReq?
    var requireResidentKey: Bool? = false;
    var userVerification: PasskeyUserVerificationReq? = PasskeyUserVerificationReq.preferred;
    
    enum CodingKeys: String, CodingKey {
        case authenticatorAttachment
        case residentKey
        case requireResidentKey
        case userVerification
    }
    
    
//    init(from decoder: any Decoder) throws {
//        let container = try decoder.container(keyedBy: CodingKeys.self);
//        let attachStr = try container.decodeIfPresent(String.self, forKey: .authenticatorAttachment);
//        if let authenticatorAttachmentString = attachStr {
//            authenticatorAttachment = PasskeyAuthAttachment(rawValue: authenticatorAttachmentString);
//        }
//        
//        let residentKeyStr = try container.decodeIfPresent(String.self, forKey: .residentKey);
//        if let residentKeyString = residentKeyStr {
//            residentKey = PasskeyResidentKeyReq(rawValue: residentKeyString);
//        }
//        
//        requireResidentKey = try container .decodeIfPresent(Bool.self, forKey: .requireResidentKey);
//        
//        let userVerificationValue = try container.decodeIfPresent(String.self, forKey: .userVerification);
//        if let userVerifStr = userVerificationValue {
//            userVerification = PasskeyUserVerificationReq(rawValue: userVerifStr);
//        }
//    }
    
    init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        if let attachStr = try c.decodeIfPresent(String.self, forKey: .authenticatorAttachment) {
            authenticatorAttachment = PasskeyAuthAttachment(rawValue: attachStr)
        }
        if let residentKeyStr = try c.decodeIfPresent(String.self, forKey: .residentKey) {
            residentKey = PasskeyResidentKeyReq(rawValue: residentKeyStr)
        }
        requireResidentKey = try c.decodeIfPresent(Bool.self, forKey: .requireResidentKey)
        if let userVerifStr = try c.decodeIfPresent(String.self, forKey: .userVerification) {
            userVerification = PasskeyUserVerificationReq(rawValue: userVerifStr)
        }
    }
}

internal enum PasskeyAuthAttachment: String, Codable {
    case platform
    // When that the user prefers to select a security key
    case crossPlatform = "cross-platform"
}

@available(iOS 15.0, *)
internal enum PasskeyUserVerificationReq: String, Codable {
    case discouraged
    case preferred
    case required
    
    func toApple () -> ASAuthorizationPublicKeyCredentialUserVerificationPreference {
        switch self {
        case .discouraged:
            return ASAuthorizationPublicKeyCredentialUserVerificationPreference.discouraged
        case .preferred:
            return ASAuthorizationPublicKeyCredentialUserVerificationPreference.preferred
        case .required:
            return ASAuthorizationPublicKeyCredentialUserVerificationPreference.required
        default:
            return ASAuthorizationPublicKeyCredentialUserVerificationPreference.preferred
        }
    }
}

@available(iOS 15.0, *)
internal enum PasskeyResidentKeyReq: String, Decodable {
    case discouraged
    case preferred
    case required
    
    func toApple() -> ASAuthorizationPublicKeyCredentialResidentKeyPreference {
        switch self {
        case .discouraged:
            return ASAuthorizationPublicKeyCredentialResidentKeyPreference.discouraged
        case .preferred:
            return ASAuthorizationPublicKeyCredentialResidentKeyPreference.preferred
        case .required:
            return ASAuthorizationPublicKeyCredentialResidentKeyPreference.required
        default:
            return ASAuthorizationPublicKeyCredentialResidentKeyPreference.preferred
        }
    }
}


@available(iOS 15.0, *)
internal enum PasskeyAttestationConveyancePref: String, Decodable {
    case direct
    case enterprise
    case indirect
    case none
    
    func toApple() -> ASAuthorizationPublicKeyCredentialAttestationKind {
        switch self {
        case .direct:
            return ASAuthorizationPublicKeyCredentialAttestationKind.direct
        case .indirect:
            return ASAuthorizationPublicKeyCredentialAttestationKind.indirect
        case .enterprise:
            return ASAuthorizationPublicKeyCredentialAttestationKind.enterprise
        default:
            return ASAuthorizationPublicKeyCredentialAttestationKind.direct
        }
    }
}

@available(iOS 15.0, *)
internal struct PasskeyAuthExtensions: Decodable {
    var largeBlob: PasskeyLargeBlobInputs?
}

@available(iOS 15.0, *)
internal struct PasskeyLargeBlobInputs: Decodable {
    var support: PasskeyLargeBlobSupport?
    var read: Bool?
    var write: Data?
    
    enum CodingKeys: String, CodingKey {
        case support
        case read
        case write
    }
        
//    init(from decoder: any Decoder) throws {
//        let container = try decoder.container(keyedBy: CodingKeys.self);
//        
//        let supportValue = try container.decodeIfPresent(String.self, forKey: .support);
//        if let supportString = supportValue {
//            support = PasskeyLargeBlobSupport(rawValue: supportString);
//        }
//        
//        read = try container.decodeIfPresent(Bool.self, forKey: .read);
//        
//        
//        let writeDict = try container.decodeIfPresent([String : Int].self, forKey: .write);
//        
//        write = writeDict?.sorted(by: { $0.key < $1.key }).map({ $0.value }).pkData;
//    }
    
    init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        if let supStr = try c.decodeIfPresent(String.self, forKey: .support) {
            support = PasskeyLargeBlobSupport(rawValue: supStr)
        }
        read = try c.decodeIfPresent(Bool.self, forKey: .read)
        let writeDict = try c.decodeIfPresent([String: Int].self, forKey: .write)
        write = writeDict?.sorted(by: { $0.key < $1.key }).map { $0.value }.pkData
    }
}

@available(iOS 15.0, *)
internal enum PasskeyLargeBlobSupport: String {
    case preferred
    case required
    
    @available(iOS 17.0, *)
    func toApple() -> ASAuthorizationPublicKeyCredentialLargeBlobRegistrationInput? {
        switch self {
        case .preferred:
            return ASAuthorizationPublicKeyCredentialLargeBlobRegistrationInput.supportPreferred
        case .required:
            return ASAuthorizationPublicKeyCredentialLargeBlobRegistrationInput.supportRequired
        default:
            return nil
        }
    }
}
