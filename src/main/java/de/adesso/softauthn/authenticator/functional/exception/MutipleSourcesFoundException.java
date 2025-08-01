package de.adesso.softauthn.authenticator.functional.exception;

import de.adesso.softauthn.PublicKeyCredentialSource;

import java.util.Collection;

/**
 * Exception to be caught, in case multiple credentials where selected for retrieval.
 */
public class MutipleSourcesFoundException extends Exception {
    private final Collection<PublicKeyCredentialSource> sources;

    public MutipleSourcesFoundException(Collection<PublicKeyCredentialSource> sources) {
        this.sources = sources;
    }

    public Collection<PublicKeyCredentialSource> getSources() {
        return sources;
    }
}
