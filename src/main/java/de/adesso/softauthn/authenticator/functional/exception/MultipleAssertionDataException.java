package de.adesso.softauthn.authenticator.functional.exception;

import de.adesso.softauthn.AuthenticatorAssertionData;

import java.util.Collection;

/**
 * Exception to be caught, in case multiple assertionData where selected for retrieval.
 */
public class MultipleAssertionDataException extends Exception {
    private final Collection<AuthenticatorAssertionData> assertionDatas;

    public MultipleAssertionDataException(Collection<AuthenticatorAssertionData> assertionDatas) {
        this.assertionDatas = assertionDatas;
    }

    public Collection<AuthenticatorAssertionData> getAuthenticatorAssertionData() {
        return assertionDatas;
    }
}
