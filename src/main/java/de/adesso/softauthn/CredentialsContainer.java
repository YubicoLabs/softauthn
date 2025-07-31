package de.adesso.softauthn;

import com.fasterxml.jackson.core.JacksonException;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;
import com.fasterxml.jackson.databind.module.SimpleModule;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;
import com.upokecenter.cbor.CBORObject;
import com.yubico.webauthn.data.*;
import com.yubico.webauthn.data.exception.Base64UrlException;
import de.adesso.softauthn.authenticator.WebAuthnAuthenticator;
import de.adesso.softauthn.authenticator.WebAuthnAuthenticator.SourceKey;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.stream.Stream;

// TODO: 14/09/2022 remove yubico dependency, write own required data structures with json serialisation support

/**
 * This class emulates the behaviour of the <a href="https://developer.mozilla.org/en-US/docs/Web/API/CredentialsContainer">CredentialsContainer</a>
 * browser API for WebAuthn credentials, allowing you to create and get WebAuthn credentials, similar to how you would use
 * {@code navigator.credentials...} in a browser.
 *
 * @apiNote Not all CredentialsContainer methods are provided:
 * <ul>
 *     <li>{@code store()} <a href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-storeCredential">does not have any functionality in WebAuthn.</a></li>
 *     <li>{@code preventSilentAccess()} has no use in this library's scope.</li>
 * </ul>
 * @see <a href="https://developer.mozilla.org/en-US/docs/Web/API/CredentialsContainer">CredentialsContainer</a>
 */
public class CredentialsContainer {

    final Origin origin;
    final List<Authenticator> authenticators;

    private final ObjectMapper mapper;

    /**
     * Creates a new CredentialsContainer with the specified {@link Origin} and a list of "known" authenticators.
     *
     * @param origin         The origin of the emulated "context".
     * @param authenticators A list of authenticators that are available to this container.
     *                       This list will be queried to create/get WebAuthn credentials.
     */
    public CredentialsContainer(Origin origin, List<? extends Authenticator> authenticators) {
        this.origin = origin;
        this.authenticators = new ArrayList<>(authenticators);
        this.mapper = new ObjectMapper();
    }

    /**
     * Implementation of <a href="https://developer.mozilla.org/en-US/docs/Web/API/CredentialsContainer/create">CredentialsContainer.create()</a>
     * for WebAuthn.
     *
     * @param publicKey The <a href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#dictdef-publickeycredentialcreationoptions">PublicKeyCredentialOptions</a>
     *                  provided by the Relying Party.
     * @return The newly created <a href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#publickeycredential">PublicKeyCredential</a>.
     * @throws IllegalArgumentException if the parameters are malformed in any way or some security check fails
     * @throws IllegalStateException    if an authenticator throws one.
     * @see <a href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-createCredential">Create a New Credential</a>
     */
    public PublicKeyCredential<AuthenticatorAttestationResponse, ClientRegistrationExtensionOutputs> create(
            PublicKeyCredentialCreationOptions publicKey
    ) {
        return create(origin, publicKey, true);
    }

    private PublicKeyCredential<AuthenticatorAttestationResponse, ClientRegistrationExtensionOutputs> create(
            Origin origin,
            PublicKeyCredentialCreationOptions options,
            boolean sameOriginWithAncestors
    ) {

        checkParameters(options.getRp().getId(), origin, sameOriginWithAncestors);
        // 9-10.
        List<PublicKeyCredentialParameters> credTypesAndPubKeyAlgs = options.getPubKeyCredParams().isEmpty()
                ? Arrays.asList(PublicKeyCredentialParameters.builder().alg(COSEAlgorithmIdentifier.ES256).build(),
                PublicKeyCredentialParameters.builder().alg(COSEAlgorithmIdentifier.RS256).build())
                : options.getPubKeyCredParams();

        ClientData clientData = collectClientData("webauthn.create", options.getChallenge(), origin, sameOriginWithAncestors);

        for (Authenticator authenticator : authenticators) {
            if (options.getAuthenticatorSelection()
                    .flatMap(AuthenticatorSelectionCriteria::getAuthenticatorAttachment)
                    .map(authenticator.getAttachment()::equals)
                    .orElse(false)) {
                continue;
            }

            if (!authenticator.supportsClientSideDiscoverablePublicKeyCredentialSources() && options.getAuthenticatorSelection().flatMap(AuthenticatorSelectionCriteria::getResidentKey).map(req -> req == ResidentKeyRequirement.REQUIRED).orElse(false)) {
                continue;
            }

            boolean requireResidentKey = options.getAuthenticatorSelection().flatMap(AuthenticatorSelectionCriteria::getResidentKey)
                    .map(req -> req == ResidentKeyRequirement.REQUIRED || (req == ResidentKeyRequirement.PREFERRED && authenticator.supportsClientSideDiscoverablePublicKeyCredentialSources()))
                    .orElse(false);

            boolean userVerification = options.getAuthenticatorSelection().flatMap(AuthenticatorSelectionCriteria::getUserVerification)
                    .map(req -> req == UserVerificationRequirement.REQUIRED || (req == UserVerificationRequirement.PREFERRED && authenticator.supportsUserVerification()))
                    .orElse(false);

            // skip handling this for now
            boolean enterpriseAttestationPossible = false;

            Set<PublicKeyCredentialDescriptor> excludeCredentials = options.getExcludeCredentials()
                    .orElse(Collections.emptySet());

            CBORObject attestationObject;
            try {
                attestationObject = authenticator.makeCredential(
                        clientData.clientDataHash, options.getRp(), options.getUser(),
                        requireResidentKey, userVerification, credTypesAndPubKeyAlgs,
                        excludeCredentials, enterpriseAttestationPossible, null
                );
            } catch (IllegalStateException e) {
                throw e;
            } catch (RuntimeException e) {
                continue;
            }

            try {
                return constructCredentialAlg(
                        attestationObject,
                        clientData.clientDataJson,
                        options.getAttestation(),
                        ClientRegistrationExtensionOutputs.builder().build()
                );
            } catch (Base64UrlException | IOException e) {
                throw new RuntimeException("Error while constructing credential response", e);
            }
        }
        return null;
    }

    private PublicKeyCredential<AuthenticatorAttestationResponse, ClientRegistrationExtensionOutputs> constructCredentialAlg(
            CBORObject attestationObjectResult,
            byte[] clientDataJsonResult,
            AttestationConveyancePreference preference,
            ClientRegistrationExtensionOutputs clientExtensionResults
    ) throws Base64UrlException, IOException {
        if (preference == AttestationConveyancePreference.NONE) {
            byte[] aaguid = extractAaguid(attestationObjectResult);
            if (!Arrays.equals(aaguid, new byte[16])
                    || !attestationObjectResult.get("fmt").AsString().equals("packed")
                    || attestationObjectResult.get("x5c") != null) {
                censorAaguid(attestationObjectResult);
                attestationObjectResult.Set("fmt", "none");
                attestationObjectResult.Set("attStmt", CBORObject.NewMap());
            }
        }
        return PublicKeyCredential.<AuthenticatorAttestationResponse, ClientRegistrationExtensionOutputs>builder()
                .id(new ByteArray(extractCredentialId(attestationObjectResult)))
                .response(AuthenticatorAttestationResponse.builder()
                        .attestationObject(new ByteArray(attestationObjectResult.EncodeToBytes()))
                        .clientDataJSON(new ByteArray(clientDataJsonResult))
                        .transports(Collections.emptySet())
                        .build())
                .clientExtensionResults(clientExtensionResults)
                .build();
    }

    private byte[] extractAaguid(CBORObject attestationObject) {
        ByteBuffer authenticatorData = ByteBuffer.wrap(attestationObject.get("authData").GetByteString());
        authenticatorData.position(37);
        byte[] aaguid = new byte[16];
        authenticatorData.get(aaguid);
        return aaguid;
    }

    private void censorAaguid(CBORObject attestationObject) {
        ByteBuffer authenticatorData = ByteBuffer.wrap(attestationObject.get("authData").GetByteString());
        authenticatorData.position(37);
        authenticatorData.put(new byte[16]);
    }

    private byte[] extractCredentialId(CBORObject attestationObject) {
        ByteBuffer authenticatorData = ByteBuffer.wrap(attestationObject.get("authData").GetByteString());
        // https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#authenticator-data 37 bytes before attestedCredentialData part, then 16 bytes aaguid
        authenticatorData.position(37 + 16);
        authenticatorData.order(ByteOrder.BIG_ENDIAN);
        short credentialIdLength = authenticatorData.getShort();
        byte[] credentialId = new byte[credentialIdLength];
        authenticatorData.get(credentialId);
        return credentialId;
    }

    /**
     * Implementation of <a href="https://developer.mozilla.org/en-US/docs/Web/API/CredentialsContainer/get">CredentialsContainer.get()</a>
     * for WebAuthn.
     *
     * @param publicKey The <a href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#dictdef-publickeycredentialrequestoptions">PublicKeyCredentialRequestOptions</a>
     *                  provided by the Relying Party.
     * @return The <a href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#publickeycredential">PublicKeyCredential</a> object with the assertion.
     * @throws IllegalArgumentException if any of the parameters are malformed in any way or a security check fails.
     * @throws RuntimeException         if any other unexpected exception occurs during the assertion process.
     * @implNote This implementation does not pre-filter the list of allowed credentials for every authenticator.
     * Instead, it passes the full list of allowed credential to every requested authenticator.
     * Furthermore, it performs no filtering based on available transports because that is not relevant to software authenticators.
     * @see <a href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-getAssertion">Use an Existing Credential to Make an Assertion</a>
     */
    public PublicKeyCredential<AuthenticatorAssertionResponse, ClientAssertionExtensionOutputs> get(
            PublicKeyCredentialRequestOptions publicKey
    ) {
        return discoverFromExternalSource(origin, publicKey, true);
    }

    private PublicKeyCredential<AuthenticatorAssertionResponse, ClientAssertionExtensionOutputs> discoverFromExternalSource(
            Origin origin, PublicKeyCredentialRequestOptions options, boolean sameOriginWithAncestors
    ) {
        checkParameters(options.getRpId(), origin, sameOriginWithAncestors);
        ClientData clientData = collectClientData("webauthn.get", options.getChallenge(), origin, sameOriginWithAncestors);
        for (Authenticator authenticator : authenticators) {
            if (options.getUserVerification()
                    .map(UserVerificationRequirement.REQUIRED::equals)
                    .orElse(false) && !authenticator.supportsUserVerification()) {
                continue;
            }

            boolean userVerification = !options.getUserVerification()
                    .map(UserVerificationRequirement.DISCOURAGED::equals).orElse(false)
                    && authenticator.supportsUserVerification();

            // skip narrowing this list down to this specific authenticator
            List<PublicKeyCredentialDescriptor> allowCredentials = options.getAllowCredentials().orElse(Collections.emptyList());

            ByteArray credentialId = allowCredentials.size() == 1 ? allowCredentials.get(0).getId() : null;

            // skip transport handling (also not relevant for software authenticators)


            AuthenticatorAssertionData assertionData;
            try {
                assertionData = authenticator.getAssertion(
                        options.getRpId(),
                        clientData.clientDataHash,
                        allowCredentials.isEmpty() ? null : allowCredentials,
                        userVerification,
                        null
                );
            } catch (RuntimeException e) {
                continue;
            }

            if (credentialId != null) {
                assertionData.setCredentialId(credentialId);
            }

            try {
                return constructAssertionAlg(assertionData, clientData);
            } catch (Base64UrlException | IOException e) {
                throw new RuntimeException("Error while creating assertion", e);
            }
        }
        return null;
    }

    private PublicKeyCredential<AuthenticatorAssertionResponse, ClientAssertionExtensionOutputs> constructAssertionAlg(
            AuthenticatorAssertionData assertionData,
            ClientData clientData
    ) throws Base64UrlException, IOException {
        return PublicKeyCredential.<AuthenticatorAssertionResponse, ClientAssertionExtensionOutputs>builder()
                .id(assertionData.getCredentialId())
                .response(AuthenticatorAssertionResponse.builder()
                        .authenticatorData(assertionData.getAuthenticatorData())
                        .clientDataJSON(new ByteArray(clientData.clientDataJson))
                        .signature(assertionData.getSignature())
                        .userHandle(Optional.ofNullable(assertionData.getUserHandle()))
                        .build())
                .clientExtensionResults(ClientAssertionExtensionOutputs.builder().build())
                .build();
    }

    private void checkParameters(String rpId, Origin origin, boolean sameOriginWithAncestors) {
        // 2.
        if (!sameOriginWithAncestors) {
            throw new IllegalArgumentException("NotAllowedError (sameOriginWithAncestors)");
        }
        // 4. skip irrelevant timeout steps
        // 5. skip irrelevant user id check
        // 6.
        if (origin == null) {
            throw new IllegalArgumentException("NotAllowedError (opaque origin)");
        }
        // 7.
        String effectiveDomain = origin.effectiveDomain();
        // TODO: 25/08/2022 validate domain
        // 8. skip rpId check, it's always set by Relying Party
    }

    private Map<String, String> processExtensions() {
        // TODO: 25/08/2022 handle extensions
        return new HashMap<>();
    }

    private ClientData collectClientData(String type, ByteArray challenge, Origin origin, boolean sameOriginWithAncestors) {

        ObjectNode collectedClientData = mapper.createObjectNode()
                .put("type", type)
                .put("challenge", challenge.getBase64Url())
                .put("origin", origin.serialized())
                .put("crossOrigin", !sameOriginWithAncestors);

        byte[] clientDataJson;
        try {
            clientDataJson = mapper.writeValueAsBytes(collectedClientData);
        } catch (JsonProcessingException e) {
            throw new AssertionError(e);
        }
        MessageDigest digest;
        try {
            digest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Required algorithm unavailable", e);
        }
        byte[] clientDataHash = digest.digest(clientDataJson);
        return new ClientData(clientDataJson, clientDataHash);
    }

    private static final class ClientData {
        private final byte[] clientDataJson;
        private final byte[] clientDataHash;

        private ClientData(byte[] clientDataJson, byte[] clientDataHash) {
            this.clientDataJson = clientDataJson;
            this.clientDataHash = clientDataHash;
        }
    }

    /**
     * Create a binary representation of this container, to be saved and restored
     *
     * @return
     * @see #deserialize
     */
    public byte[] serialize() {
        final var mapper = new ObjectMapper();
        final var module = new SimpleModule();

        module.addSerializer(CredentialsContainer.class, new CredentialsSerializer());
        mapper.registerModule(module);

        try {
            final var serialized = mapper.writeValueAsString(this);
            return serialized.getBytes(StandardCharsets.UTF_8);
        } catch (JsonProcessingException e) {
            return null;
        }
    }

    /**
     * Load a serialized
     *
     * @param payload
     * @return a CredentialsContainer representing that payload, or null if error happened
     */
    public static CredentialsContainer deserialize(byte[] payload) {
        final var mapper = new ObjectMapper();
        final var module = new SimpleModule();

        module.addDeserializer(CredentialsContainer.class, new CredentialsDeserializer(CredentialsContainer.class));
        mapper.registerModule(module);

        try {
            final var deserialized = mapper.readValue(payload, CredentialsContainer.class);
            return deserialized;
        } catch (IOException e) {
            return null;
        }
    }

    public class CredentialsSerializer extends StdSerializer<CredentialsContainer> {
        public CredentialsSerializer() {
            this(null);
        }

        public CredentialsSerializer(Class<CredentialsContainer> t) {
            super(t);
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
            for (final var authenticator : authenticators) {
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

    public static class CredentialsDeserializer extends StdDeserializer<CredentialsContainer> {
        protected CredentialsDeserializer(Class<?> vc) {
            super(vc);
        }

        @Override
        public CredentialsContainer deserialize(JsonParser p, DeserializationContext ctxt) throws IOException, JacksonException {
            JsonNode jsonNode = p.readValueAsTree();
            final var scheme = jsonNode.get("origin.scheme").asText();
            final var host = jsonNode.get("origin.host").asText();
            final var port = jsonNode.has("origin.port") ? jsonNode.get("origin.port").asInt() : -1;
            final var domain = jsonNode.has("origin.domain") ? jsonNode.get("origin.domain").asText() : null;

            final var origin = new Origin(scheme, host, port, domain);

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

                    final var storedSources = new HashMap<SourceKey, PublicKeyCredentialSource>();
                    jsonAuthenticator.get("storedSources").elements().forEachRemaining(jsonSource -> {
                        try {
                            final var rpId = jsonSource.get("key.rpId").asText();
                            final var userHandle = ByteArray.fromBase64Url(jsonSource.get("key.userHandle").asText());
                            final var key = new SourceKey(rpId, userHandle);

                            final var value = PublicKeyCredentialSource.deserialize(
                                    ByteArray.fromBase64(jsonSource.get("value").asText())
                            ).orElse(null);

                            storedSources.put(key, value);
                        } catch (NoSuchElementException | Base64UrlException e) {
                            throw new RuntimeException(e);
                        }

                    });

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


            final var result = new CredentialsContainer(origin, authenticators);

            return result;
        }
    }
}
