import { WebPlugin } from '@capacitor/core';
import type { PasskeyPlugin, PasskeyCreateOptions, PasskeyCreateResult, PublicKeyCreationOptions, PasskeyAuthResult, PasskeyAuthenticationOptions, PublicKeyAuthenticationOptions } from './definitions';

export class WebPasskeyPlugin extends WebPlugin implements PasskeyPlugin {

  async createPasskey(options: PasskeyCreateOptions): Promise<PasskeyCreateResult> {
    try {
      if (!('credentials' in navigator) || typeof navigator.credentials.create !== 'function') {
        throw new Error('PasskeyPlugin not supported in this browser');
      }
      const crossPlatformOptions = options.publicKey as PublicKeyCreationOptions;
      const webPasskeyOptions = this.toPublicKeyCredentialCreationOptions(crossPlatformOptions);

      const credential = await navigator.credentials.create({
        publicKey: webPasskeyOptions
      }) as PublicKeyCredential;

      if (!credential) {
        throw new Error('Credential creation failed');
      }
      const attestationResponse = credential.response as AuthenticatorAttestationResponse;
      if (credential.response instanceof AuthenticatorAttestationResponse) {
        return {
          id: credential.id,
          rawId: this.toBase64url(new Uint8Array(credential.rawId)),
          response: {
            attestationObject: this.toBase64url(new Uint8Array(attestationResponse.attestationObject)),
            clientDataJSON: this.toBase64url(new Uint8Array(attestationResponse.clientDataJSON))
          }
        };
      } else {
        throw new Error('Unsupported response type');
      }

    } catch (error) {
      console.error('Passkey registration failed:', error);
      throw error;
    }
  }

  async authenticate(options: PasskeyAuthenticationOptions): Promise<PasskeyAuthResult> {
    if (!('credentials' in navigator) || typeof navigator.credentials.create !== 'function') {
      throw new Error('PasskeyPlugin not supported in this browser');
    }
    const crossPlatformOptions = options.publicKey as PublicKeyAuthenticationOptions;
    const nativeOptions = this.toPublicKeyCredentialRequestOptions(crossPlatformOptions) as PublicKeyCredentialRequestOptions;
    const publicKeyCredential = await navigator.credentials.get({
      publicKey: nativeOptions
    }) as PublicKeyCredential;
    if (!publicKeyCredential) {
      throw new Error('No credential found');
    }
    const assertionResponse = publicKeyCredential.response as AuthenticatorAssertionResponse;
    return {
      id: publicKeyCredential.id,
      rawId: this.toBase64url(new Uint8Array(publicKeyCredential.rawId)),
      type: publicKeyCredential.type,
      response: {
        clientDataJSON: this.toBase64url(new Uint8Array(assertionResponse.clientDataJSON)),
        authenticatorData: this.toBase64url(new Uint8Array(assertionResponse.authenticatorData)),
        signature: this.toBase64url(new Uint8Array(assertionResponse.signature)),
        userHandle: assertionResponse.userHandle ? this.toBase64url(new Uint8Array(assertionResponse.userHandle)) : undefined
      }
    }
  }

  toPublicKeyCredentialCreationOptions(
    safe: PublicKeyCreationOptions
  ): PublicKeyCredentialCreationOptions {

    return {
      challenge: this.base64urlToUint8Array(safe.challenge),
      rp: safe.rp,
      user: {
        id: this.base64urlToUint8Array(safe.user.id),
        name: safe.user.name,
        displayName: safe.user.displayName
      },
      pubKeyCredParams: safe.pubKeyCredParams,
      authenticatorSelection: safe.authenticatorSelection,
      timeout: safe.timeout,
      attestation: safe.attestation,
      extensions: safe.extensions,
      excludeCredentials: safe.excludeCredentials?.map(cred => ({
        id: this.base64urlToUint8Array(cred.id),
        type: "public-key" as const,
        transports: cred.transports
      }))
    };
  }

  base64urlToUint8Array(base64url: string): Uint8Array {
    const base64 = base64url
      .replace(/-/g, "+")
      .replace(/_/g, "/")
      .padEnd(Math.ceil(base64url.length / 4) * 4, "=");
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }

  toBase64url(bytes: Uint8Array): string {
    return btoa(String.fromCharCode(...bytes))
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=/g, "");
  }

  toPublicKeyCredentialRequestOptions(crossPlatform: PublicKeyAuthenticationOptions): PublicKeyCredentialRequestOptions {
    return {
      challenge: this.base64urlToUint8Array(crossPlatform.challenge),
      allowCredentials: crossPlatform.allowCredentials?.map(cred => ({
        id: this.base64urlToUint8Array(cred.id),
        type: "public-key",
        transports: cred.transports
      })),
      rpId: crossPlatform.rpId,
      timeout: crossPlatform.timeout,
      userVerification: crossPlatform.userVerification,
      extensions: crossPlatform.extensions
    };
  }
}
