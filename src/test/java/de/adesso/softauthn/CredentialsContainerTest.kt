package de.adesso.softauthn


import com.yubico.webauthn.data.*
import de.adesso.softauthn.authenticator.WebAuthnAuthenticator
import de.adesso.softauthn.authenticator.functional.exception.MutiplePublicKeysFoundException
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertNotNull
import org.junit.jupiter.api.fail
import java.io.File
import java.net.URL
import kotlin.jvm.optionals.getOrNull
import com.yubico.webauthn.data.ByteArray as YubiByteArray

class CredentialsContainerTest {
    val authenticator = Authenticators.yubikey5Nfc().build()
    val options = PublicKeyCredentialCreationOptions
        .builder()
        .rp(
            RelyingPartyIdentity.builder()
                .id("rp id")
                .name("rp name")
                .build()
        ).user(
            UserIdentity.builder()
                .name("username")
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
        val container = CredentialsContainer(listOf(authenticator))
        val credential = container.create(options)

        assertNotNull(credential)
        assertEquals(PublicKeyCredentialType.PUBLIC_KEY, credential.type)
        assertEquals(options.rp.id, credential.response.clientData.origin)
    }

    @Test
    fun createdCredentialsHaveDifferentUserNames() {
        val container = CredentialsContainer(listOf(authenticator))
        container.create(options)
        val peteId = "pete".encodeToByteArray().toYubi()
        container.create(
            options.toBuilder().user(
                options.user.toBuilder()
                    .name("Pete")
                    .displayName("Peg Nose Pete")
                    .id(peteId)
                    .build()
            ).build()
        )

        val blob = container.serialize()

        val newContainer = CredentialsContainer.deserialize(blob)

        val userA = newContainer.getUser(options.user.id)
        val userB = newContainer.getUser(peteId)

        assertNotNull(userA)
        assertNotNull(userB)

        assertNotEquals(userA.name, userB.name)

        assertEquals(userA.name, options.user.name)
        assertEquals(userB.name, "Pete")
    }

    @Test
    fun createdCredentialsHaveDifferentUserNamesInMultipleCredentialResponse() {
        val container = CredentialsContainer(listOf(authenticator))
        container.create(options)

        val peteId = "pete".encodeToByteArray().toYubi()
        container.create(
            options.toBuilder().user(
                options.user.toBuilder()
                    .name("Pete")
                    .displayName("Peg Nose Pete")
                    .id(peteId)
                    .build()
            ).build()
        )

        var thrown = false
        try {
            container.get(
                PublicKeyCredentialRequestOptions.builder()
                    .challenge(options.challenge)
                    .rpId(options.rp.id)
                    .build()
            )
        } catch (e: MutiplePublicKeysFoundException) {
            val names = e.publicKeys.map {
                container.getUser(it.response.userHandle.get()).name
            }

            assertEquals(2, names.size)
            assertTrue("username" in names)
            assertTrue("Pete" in names)
            thrown = true
        }

        assertTrue(thrown)
    }

    @Test
    fun getCreatedCredential() {
        val container = CredentialsContainer(listOf(authenticator))
        val createdCredential = container.create(options)

        val credential = container.get(
            PublicKeyCredentialRequestOptions.builder()
                .challenge(YubiByteArray(ByteArray(32)))
                .allowCredentials(
                    listOf(
                        PublicKeyCredentialDescriptor.builder()
                            .id(createdCredential.id)
                            .build()
                    )
                )
                .rpId(options.rp.id)
                .build()
        )

        assertNotNull(credential)
        assertEquals(PublicKeyCredentialType.PUBLIC_KEY, credential.type)
    }

    @OptIn(ExperimentalStdlibApi::class)
    @Test
    fun storeAndRestoreContainer() {
        val container = CredentialsContainer(listOf(authenticator))
        container.create(options)

        val blob = container.serialize()

        val container2 = CredentialsContainer.deserialize(blob)

        assertEquals(
            String(container2.serialize()),
            String(container.serialize())
        )
    }

    @Test
    fun findUser() {
        javaClass.classLoader.getResourceAsStream("255-credentials.json").use { stream ->
            val json = stream.readAllBytes().toString(Charsets.UTF_8)
            val container = CredentialsContainer.deserialize(json.toByteArray())

            val foundUser =
                container.getUser(YubiByteArray.fromBase64Url("TAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"))
            assertNotNull(foundUser)

            assertEquals(
                76,
                foundUser.id.bytes.sum()
            )
        }
    }

    @Test
    fun findsCredentialForOverspecifiedOptions() {
        javaClass.classLoader.getResourceAsStream("255-credentials.json").use { stream ->
            val json = stream.readAllBytes().toString(Charsets.UTF_8)
            val container = CredentialsContainer.deserialize(json.toByteArray())
            val webAuthnAuthenticator = container.authenticators.first() as WebAuthnAuthenticator
            val sourceKey = webAuthnAuthenticator.storedSources.keys.firstOrNull {
                it.userHandle == YubiByteArray.fromBase64Url("YAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
            }
            assertNotNull(sourceKey)
            val credentialId = webAuthnAuthenticator.storedSources.get(sourceKey)?.id

            val found = container.get(
                PublicKeyCredentialRequestOptions.builder()
                    .challenge(
                        YubiByteArray.fromBase64Url("V0UdyxcYpa6PoKDMYGBvIQ")
                    )
                    .rpId("rp id")
                    .userVerification(
                        UserVerificationRequirement.REQUIRED,
                    )
                    .allowCredentials(
                        listOf(
                            PublicKeyCredentialDescriptor.builder()
                                .id(credentialId)
                                .transports(
                                    setOf(
                                        AuthenticatorTransport.USB,
                                        AuthenticatorTransport.NFC,
                                        AuthenticatorTransport.BLE,
                                        AuthenticatorTransport.HYBRID,
                                        AuthenticatorTransport.INTERNAL,
                                    )
                                )
                                .type(PublicKeyCredentialType.PUBLIC_KEY)
                                .build()

                        )
                    ).build()
            )

            assertNotNull(found)

            assertEquals(
                YubiByteArray.fromBase64Url("YAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
                found.response.userHandle.get()
            )
        }
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

    @Test
    fun return255CredentialsOnGet() {
        javaClass.classLoader.getResourceAsStream("255-credentials.json").use { stream ->
            val json = stream.readAllBytes().toString(Charsets.UTF_8)

            val container = CredentialsContainer.deserialize(json.toByteArray())

            val challenge = ByteArray(32) { it.toByte() }
            val options = PublicKeyCredentialRequestOptions.builder()
                .challenge(YubiByteArray(challenge))
                .rpId("rp id")
                .build()

            try {
                val credentials = container.get(options)
            } catch (e: MutiplePublicKeysFoundException) {
                assertEquals(
                    0xFF, e.publicKeys.size
                )
            } catch (e: Exception) {
                fail(e.message)
            }
        }
    }

    @Test
    fun returnOneOf255CredentialsOnGet() {
        javaClass.classLoader.getResourceAsStream("255-credentials.json").use { stream ->
            val json = stream.readAllBytes().toString(Charsets.UTF_8)

            val container = CredentialsContainer.deserialize(json.toByteArray())
            val webAuthnAuthenticator = container.authenticators.first() as WebAuthnAuthenticator
            val sourceKey = webAuthnAuthenticator.storedSources.keys.firstOrNull {
                it.userHandle == YubiByteArray.fromBase64Url("YAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
            }
            assertNotNull(sourceKey)
            val credentialId = webAuthnAuthenticator.storedSources.get(sourceKey)?.id

            val challenge = ByteArray(32) { it.toByte() }
            val options = PublicKeyCredentialRequestOptions.builder()
                .challenge(YubiByteArray(challenge))
                .rpId("rp id")
                .allowCredentials(
                    listOf(
                        PublicKeyCredentialDescriptor.builder()
                            .id(credentialId)
                            .build()
                    )
                ).build()

            val credential = container.get(options)

            assertNotNull(credential)
            assertEquals(
                YubiByteArray.fromBase64Url("YAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
                credential.response.userHandle.getOrNull(),
            )
        }
    }

    @Test
    fun return10CredentialsOnGet() {
        javaClass.classLoader.getResourceAsStream("10-10-credentials.json").use { stream ->
            val json = stream.readAllBytes().toString(Charsets.UTF_8)

            val container = CredentialsContainer.deserialize(json.toByteArray())

            val challenge = ByteArray(32) { it.toByte() }
            val options = PublicKeyCredentialRequestOptions.builder()
                .challenge(YubiByteArray(challenge))
                .rpId("rp id")
                .build()

            try {
                container.get(options)
            } catch (e: MutiplePublicKeysFoundException) {
                assertEquals(
                    10, e.publicKeys.size
                )
            } catch (e: Exception) {
                fail(e.message)
            }

        }
    }

    @Test
    fun returnNoCredentialsOnGetWithWrongRPID() {
        javaClass.classLoader.getResourceAsStream("255-credentials.json").use { stream ->
            val json = stream.readAllBytes().toString(Charsets.UTF_8)
            val container = CredentialsContainer.deserialize(json.toByteArray())

            val challenge = ByteArray(32) { it.toByte() }

            assertEquals(
                null, container.get(
                    PublicKeyCredentialRequestOptions.builder()
                        .challenge(YubiByteArray(challenge))
                        .rpId("not the right rpid")
                        .build()
                )
            )
        }
    }

    fun create1010TestData() {
        val container = CredentialsContainer(listOf(authenticator))

        for (i in 0 until 10) {
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

            val credential = container.create(alteredOption)
            println("Credential created: $credential.")
        }
        for (i in 0 until 10) {
            val alteredOption =
                options.toBuilder()
                    .rp(
                        options.rp.toBuilder()
                            .id("not that ip")
                            .name("not the right rp")
                            .build()
                    )
                    .user(
                        options.user
                            .toBuilder()
                            .id(
                                YubiByteArray(
                                    ByteArray(32) {
                                        i.toByte()
                                    }
                                )
                            )
                            .name("another tester #$i")
                            .displayName("another tester number $i")
                            .build()
                    ).build();

            container.create(alteredOption)
        }

        val foo = container.serialize()
        val f = File.createTempFile("testdata-10:10-", ".json")
        print("Saved temp data as ${f.absoluteFile}. Enjoy")
        f.writeBytes(foo)
    }

    fun create255TestData() {
        val container = CredentialsContainer(listOf(authenticator))

        for (i in 0 until 255) {
            val alteredOption =
                options.toBuilder().user(
                    options.user
                        .toBuilder()
                        .id(
                            YubiByteArray(
                                ByteArray(32).apply { set(0, i.toByte()) }
                            )
                        )
                        .name("tester #$i")
                        .displayName("tester number $i")
                        .build()
                ).build();

            val credential = container.create(alteredOption)
            println("Credential created: $credential.")
        }

        val foo = container.serialize()
        val f = File.createTempFile("testdata-255-", ".json")
        print("Saved temp data as ${f.absoluteFile}. Enjoy")
        f.writeBytes(foo)
    }
}

// MAIN FOR CREATING SAMPLE DATA
fun main() {
    CredentialsContainerTest().create1010TestData()
    CredentialsContainerTest().create255TestData()
}

private fun ByteArray.toYubi(): YubiByteArray = YubiByteArray(this)