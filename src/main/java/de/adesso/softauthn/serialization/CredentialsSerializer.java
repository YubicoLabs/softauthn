package de.adesso.softauthn.serialization;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;
import de.adesso.softauthn.CredentialsContainer;
import de.adesso.softauthn.authenticator.WebAuthnAuthenticator;

import java.io.IOException;

public class CredentialsSerializer extends StdSerializer<CredentialsContainer> {
    public CredentialsSerializer() {
        super(CredentialsContainer.class);
    }

    @Override
    public void serialize(CredentialsContainer credentialsContainer, JsonGenerator jsonGenerator, SerializerProvider serializerProvider) throws IOException {
        jsonGenerator.writeStartObject();

        jsonGenerator.writeObjectField("origin.scheme", credentialsContainer.origin.getScheme());
        jsonGenerator.writeObjectField("origin.host", credentialsContainer.origin.getHost());
        if (credentialsContainer.origin.getPort().isPresent()) {
            jsonGenerator.writeObjectField("origin.port", credentialsContainer.origin.getPort());
        }
        if (credentialsContainer.origin.getDomain().isPresent()) {
            jsonGenerator.writeObjectField("origin.domain", credentialsContainer.origin.getDomain());
        }

        jsonGenerator.writeArrayFieldStart("authenticators");
        for (final var authenticator : credentialsContainer.authenticators) {
            if (authenticator instanceof WebAuthnAuthenticator web) {
                jsonGenerator.writeStartObject();
                jsonGenerator.writeStringField("type", authenticator.getClass().getSimpleName());

                jsonGenerator.writeObjectField("aaguid", web.aaguid);
                jsonGenerator.writeObjectField("attachment", web.getAttachment());
                jsonGenerator.writeObjectField("supportedAlgorithms", web.supportedAlgorithms);
                jsonGenerator.writeObjectField("supportsClientSideDiscoverablePublicKeyCredentialSources", web.supportsClientSideDiscoverablePublicKeyCredentialSources);
                jsonGenerator.writeObjectField("supportsUserVerification", web.supportsUserVerification);

                jsonGenerator.writeArrayFieldStart("storedSources");
                for (final var key : web.storedSources.keySet()) {
                    jsonGenerator.writeStartObject();

                    jsonGenerator.writeObjectField("key.rpId", key.rpId);
                    jsonGenerator.writeStringField("key.userHandle", key.userHandle.getBase64());

                    final var value = web.storedSources.get(key);
                    jsonGenerator.writeObjectField("value", value.serialize());

                    jsonGenerator.writeEndObject();
                }
                jsonGenerator.writeEndArray();

                jsonGenerator.writeEndObject();
            }
        }
        jsonGenerator.writeEndArray();
        jsonGenerator.writeEndObject();
    }
}
