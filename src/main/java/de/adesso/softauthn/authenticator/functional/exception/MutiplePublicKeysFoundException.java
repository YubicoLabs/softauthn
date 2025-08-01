package de.adesso.softauthn.authenticator.functional.exception;

import com.yubico.webauthn.data.AuthenticatorAssertionResponse;
import com.yubico.webauthn.data.ClientAssertionExtensionOutputs;
import com.yubico.webauthn.data.PublicKeyCredential;

import java.util.Collection;

/**
 * Exception to be caught, in case multiple public keys where selected for retrieval.
 */
public class MutiplePublicKeysFoundException extends Exception {
    private final Collection<PublicKeyCredential<AuthenticatorAssertionResponse, ClientAssertionExtensionOutputs>> keys;

    public MutiplePublicKeysFoundException(Collection<PublicKeyCredential<AuthenticatorAssertionResponse, ClientAssertionExtensionOutputs>> keys) {
        this.keys = keys;
    }

    public Collection<PublicKeyCredential<AuthenticatorAssertionResponse, ClientAssertionExtensionOutputs>> getPublicKeys() {
        return keys;
    }
}
