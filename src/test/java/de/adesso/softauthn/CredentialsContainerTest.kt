package de.adesso.softauthn


import com.yubico.webauthn.data.*
import de.adesso.softauthn.authenticator.WebAuthnAuthenticator
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertNotNull
import java.io.File
import java.net.URL
import com.yubico.webauthn.data.ByteArray as YubiByteArray

class CredentialsContainerTest {
    val authenticator = Authenticators.yubikey5Nfc().build()
    val origin = URL("https://www.yubico.com").toOrigin()
    val options = PublicKeyCredentialCreationOptions
        .builder()
        .rp(
            RelyingPartyIdentity.builder()
                .id("rp id")
                .name("rp name")
                .build()
        ).user(
            UserIdentity.builder()
                .name("usernname")
                .displayName("user display")
                .id("idnumber we don't say".encodeToByteArray().toYubi())
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
        ).authenticatorSelection(
            AuthenticatorSelectionCriteria.builder()
                .residentKey(
                    ResidentKeyRequirement.REQUIRED
                )
                .build()
        )
        .build()

    @Test
    fun createCredential() {
        val container = CredentialsContainer(origin, listOf(authenticator))
        val credential = container.create(options)

        assertNotNull(credential)
        assertEquals(PublicKeyCredentialType.PUBLIC_KEY, credential.type)
    }

    @OptIn(ExperimentalStdlibApi::class)
    @Test
    fun storeAndRestoreContainer() {
        val container = CredentialsContainer(origin, listOf(authenticator))
        container.create(options)

        val blob = container.serialize()

        val container2 = CredentialsContainer.deserialize(blob)

        assertEquals(
            String(container2.serialize()),
            String(container.serialize())
        )
    }

    @Test
    fun load255Credentials() {
        javaClass.classLoader.getResourceAsStream("255-credentials.json").use { stream ->
            val json = stream.readAllBytes().toString(Charsets.UTF_8)
            val container = CredentialsContainer.deserialize(json.toByteArray())

            assertEquals(1, container.authenticators.size)

            val webthenticator = container.authenticators.first() as WebAuthnAuthenticator
            val credentials = webthenticator.storedSources
            assertEquals(0xFF, credentials.size)
        }
    }

    fun createTestData() {
        val container = CredentialsContainer(origin, listOf(authenticator))

        for (i in 0 until 0xFF) {
            val alteredOption =
                options.toBuilder().user(
                    options.user
                        .toBuilder()
                        .id(
                            YubiByteArray(
                                ByteArray(32) {
                                    i.toByte()
                                }
                            )
                        )
                        .name("tester #$i")
                        .displayName("tester number $i")
                        .build()
                ).build();

            container.create(alteredOption)
        }

        val foo = container.serialize()
        val f = File.createTempFile("testdata", "json")
        print("Saved temp data as ${f.absoluteFile}. Enjoy")
        f.writeBytes(foo)

    }
}

// MAIN FOR CREATING SAMPLE DATA
fun main() {
    CredentialsContainerTest().createTestData()
}

private fun URL.toOrigin() = Origin("https", host, -1, null)

private fun ByteArray.toYubi(): YubiByteArray = YubiByteArray(this)