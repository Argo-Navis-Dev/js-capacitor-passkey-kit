export interface PublicKeyCreationOptions {
  challenge: string; //base64url
  rp: PublicKeyCredentialRpEntity;
  user: {
    id: string; //base64url
    name: string;
    displayName: string;
  };
  pubKeyCredParams: PublicKeyCredentialParameters[];
  authenticatorSelection?: AuthenticatorSelectionCriteria;
  timeout?: number;
  attestation?: AttestationConveyancePreference;
  extensions?: AuthenticationExtensionsClientInputs;
  excludeCredentials?: Array<{
    id: string; // base64url
    type: string;
    transports?: AuthenticatorTransport[];
  }>;
}

export interface PasskeyCreateOptions {
  publicKey: PublicKeyCreationOptions;
}

export interface PublicKeyAuthenticationOptions {
  challenge: string; // base64url
  allowCredentials?: Array<{
    id: string; // base64url
    type: "public-key";
    transports?: AuthenticatorTransport[];
  }>;
  rpId?: string;
  timeout?: number;
  userVerification?: "required" | "preferred" | "discouraged";
  extensions?: AuthenticationExtensionsClientInputs;
}

export interface PasskeyAuthenticationOptions {
  publicKey: PublicKeyAuthenticationOptions;
}

export interface PasskeyCreateResult {
  id: string;
  rawId: string; // base64url string;
  response: {
    attestationObject: string; // base64url string;
    clientDataJSON: string; // base64url string;
  };
}

export interface PasskeyAuthResult {
  id: string;
  rawId: string; // base64url
  type: string;
  response: any; // Structure depends on attestation/authenticator data
}


export interface PasskeyPlugin {
  createPasskey(options: PasskeyCreateOptions): Promise<PasskeyCreateResult>;
  authenticate(options: PasskeyAuthenticationOptions): Promise<PasskeyAuthResult>;
}
