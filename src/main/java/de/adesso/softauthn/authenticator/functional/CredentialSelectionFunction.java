package de.adesso.softauthn.authenticator.functional;

import de.adesso.softauthn.PublicKeyCredentialSource;
import de.adesso.softauthn.authenticator.functional.exception.MutipleSourcesFoundException;

import java.util.Set;

/**
 * Function that selects a given credential source, or throws a MultipleSourcesFoundException, incase several ones match.
 */
public class CredentialSelectionFunction implements CheckedFunction<Set<PublicKeyCredentialSource>, PublicKeyCredentialSource, MutipleSourcesFoundException> {
    @Override
    public PublicKeyCredentialSource apply(Set<PublicKeyCredentialSource> publicKeyCredentialSources) throws MutipleSourcesFoundException {
        if (publicKeyCredentialSources.size() > 1) {
            throw new MutipleSourcesFoundException(publicKeyCredentialSources);
        } else {
            return publicKeyCredentialSources.iterator().next();
        }
    }
}
