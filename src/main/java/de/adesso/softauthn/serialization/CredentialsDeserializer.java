package de.adesso.softauthn.serialization;

import com.fasterxml.jackson.core.JacksonException;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;
import com.yubico.webauthn.data.AuthenticatorAttachment;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.COSEAlgorithmIdentifier;
import com.yubico.webauthn.data.exception.Base64UrlException;
import de.adesso.softauthn.Authenticator;
import de.adesso.softauthn.CredentialsContainer;
import de.adesso.softauthn.PublicKeyCredentialSource;
import de.adesso.softauthn.authenticator.WebAuthnAuthenticator;
import de.adesso.softauthn.counter.PerCredentialSignatureCounter;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.NoSuchElementException;
import java.util.stream.Stream;

public class CredentialsDeserializer extends StdDeserializer<CredentialsContainer> {
    public CredentialsDeserializer() {
        super(CredentialsContainer.class);
    }

    @Override
    public CredentialsContainer deserialize(JsonParser p, DeserializationContext ctxt) throws IOException, JacksonException {
        JsonNode jsonNode = p.readValueAsTree();

        final var authenticators = new ArrayList<Authenticator>();
        jsonNode.get("authenticators").elements().forEachRemaining(jsonAuthenticator -> {
            Authenticator authenticator = null;
            if (jsonAuthenticator.get("type").asText().equals("WebAuthnAuthenticator")) {
                final var aaguid = ByteArray.fromBase64(jsonAuthenticator.get("aaguid").asText());

                final var jsonAttachment = jsonAuthenticator.get("attachment").asText();
                final var attachment = Stream.of(AuthenticatorAttachment.values()).filter(v ->
                        v.getValue().equals(jsonAttachment)
                ).findAny().orElse(null);

                final var supportedAlgorithms = new ArrayList<COSEAlgorithmIdentifier>();
                jsonAuthenticator.get("supportedAlgorithms")
                        .elements()
                        .forEachRemaining(jsonAlgorithm ->
                                supportedAlgorithms.add(
                                        COSEAlgorithmIdentifier.fromId(
                                                jsonAlgorithm.asInt()
                                        ).orElse(null)
                                )
                        );

                final var supportsClientSideDiscoverablePublicKeyCredentialSources = jsonAuthenticator
                        .get("supportsClientSideDiscoverablePublicKeyCredentialSources").asBoolean(true);

                final var supportsUserVerification = jsonAuthenticator
                        .get("supportsUserVerification").asBoolean(true);

                final var storedSources = new HashMap<WebAuthnAuthenticator.SourceKey, PublicKeyCredentialSource>();
                jsonAuthenticator.get("storedSources").elements().forEachRemaining(jsonSource -> {
                    try {
                        final var rpId = jsonSource.get("key.rpId").asText();

                        final var userHandle = ByteArray.fromBase64Url(jsonSource.get("key.userHandle").asText());
                        final var userName = jsonSource.get("key.userName").asText();
                        final var userDisplayName = jsonSource.get("key.userDisplayName").asText();

                        final var key = new WebAuthnAuthenticator.SourceKey(rpId, userHandle, userName, userDisplayName);

                        final var value = PublicKeyCredentialSource.deserialize(
                                ByteArray.fromBase64(jsonSource.get("value").asText())
                        ).orElse(null);

                        storedSources.put(key, value);
                    } catch (NoSuchElementException | Base64UrlException e) {
                        throw new RuntimeException(e);
                    }
                });

                final var signatureCounter = new PerCredentialSignatureCounter();
                storedSources.forEach((key, value) -> signatureCounter.increment(value.getId()));

                final var credentialSelection = new Function<Set<PublicKeyCredentialSource>, PublicKeyCredentialSource>() {
                    @Override
                    public PublicKeyCredentialSource apply(Set<PublicKeyCredentialSource> publicKeyCredentialSources) {
                        return null;
                    }
                };

                final var webauth = WebAuthnAuthenticator.builder()
                        .aaguid(aaguid.getBytes())
                        .attachment(attachment)
                        .supportAlgorithms(supportedAlgorithms)
                        .supportClientSideDiscoverablePublicKeyCredentialSources(
                                supportsClientSideDiscoverablePublicKeyCredentialSources
                        )
                        .supportUserVerification(
                                supportsUserVerification
                        )
                        .signatureCounter(
                                signatureCounter
                        )
                        .build();

                webauth.storedSources.clear();
                webauth.storedSources.putAll(storedSources);

                authenticator = webauth;
            }

            if (authenticator != null) {
                authenticators.add(authenticator);
            } else {
                throw new IllegalStateException("Authenticator no webauthnAuthenticator");
            }
        });


        final var result = new CredentialsContainer(authenticators);
        return result;
    }
}
