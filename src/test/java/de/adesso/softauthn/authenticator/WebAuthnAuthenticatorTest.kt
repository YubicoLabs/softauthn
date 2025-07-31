package de.adesso.softauthn.authenticator;


import com.yubico.webauthn.data.*
import de.adesso.softauthn.Authenticators
import de.adesso.softauthn.CredentialsContainer
import de.adesso.softauthn.Origin
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertNotNull
import java.net.URL

class WebAuthnAuthenticatorTest {

    @Test
    fun createCredential() {
        val authenticator = Authenticators.yubikey5Nfc().build()
        val origin = URL("https://www.yubico.com").toOrigin()

        val options = PublicKeyCredentialCreationOptions
            .builder()
            .rp(
                RelyingPartyIdentity.builder()
                    .id("id")
                    .name("namme")
                    .build()
            ).user(
                UserIdentity.builder()
                    .name("user")
                    .displayName("display")
                    .id("id".encodeToByteArray().toYubi())
                    .build()
            ).challenge(ByteArray(32) { it.toByte() }.toYubi())
            .pubKeyCredParams(
                listOf(
                    PublicKeyCredentialParameters.builder()
                        .alg(
                            COSEAlgorithmIdentifier.ES256
                        )
                        .build()
                )
            )
            .build()

        val container = CredentialsContainer(origin, listOf(authenticator))
        val credential = container.create(options)

        assertNotNull(credential)
        assertEquals(PublicKeyCredentialType.PUBLIC_KEY, credential.type)
    }
}

private fun URL.toOrigin() = Origin("https", host, -1, null)

private fun ByteArray.toYubi(): com.yubico.webauthn.data.ByteArray = com.yubico.webauthn.data.ByteArray(this)