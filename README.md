# softauthn-java

softauthn provides an implementation of the [WebAuthn](https://www.w3.org/TR/2021/REC-webauthn-2-20210408/) API and a software authenticator in Java, 
using the [`java-webauthn-server`](https://developers.yubico.com/java-webauthn-server/) library for data models. This makes it especially well-suited 
to interface with code that uses that same library.

# Status

This is an experimental fork of the [original](https://github.com/adessoSE/softauthn), there is no support added. 

This fork will feature even more experimental additions, use at your own risk.

## Purpose
The primary purpose of this library is to enable developers to test their WebAuthn server implementations.
E.g. you might have a web app that allows users to authenticate via WebAuthn and you want to unit test your 
backend authentication process. This library gives you an API to create arbitrary authenticators that behave
like "real" ones in pure software.

## Installation

Releases of this library can be found in jitpack:

Add it in your settings.gradle.kts at the end of repositories:

	dependencyResolutionManagement {
		repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
		repositories {
			mavenCentral()
			maven { url = uri("https://www.jitpack.io") }
		}
	}

Add the dependency

	dependencies {
        implementation("com.github.yubicolabs:softauthn:main-SNAPSHOT")
    }

That's it! The first time you request a project JitPack checks out the code, builds it and serves the build artifacts (jar, aar).

## Usage

### Creating Credentials
```kotlin
val authenticator = Authenticators.yubikey5Nfc().build()
val origin = URL("https://www.yubico.com").toOrigin()

val options = PublicKeyCredentialCreationOptions
    .builder()
     // add configuration here
    .build()

val container = CredentialsContainer(origin, listOf(authenticator))
val credential = container.create(options)
verifyAssertion(credential)
```

### Creating Assertions

```java
// same environment as above, get request options from your backend somehow
PublicKeyCredentialRequestOptions opts = startAssertion(...);
// will create an appropriate assertion (or null if no matching credential can be found)
PublicKeyCredential<AuthenticatorAssertionResponse, ClientAssertionExtensionsResult> credential = credentials.get(opts);
verifyAssertion(credential);
```

## Completeness

While this library does aim to come close to the WebAuthn specification, it does not implement all of its features.
These aspects are currently unsupported:
- Any type of attestation other than "none"
- Token Binding
- Client Extensions

Additionally, only the algorithms/COSE specifiers supported by `java-webauthn-server` are implemented. 
Currently, those are:
- EdDSA
- ES256
- RS256 (WIP)
- RS1 (WIP)

See [IANA COSE Algorithm Registry](https://www.iana.org/assignments/cose/cose.xhtml#algorithms) for reference.
If this list is out of date because `java-webauthn-server` added a new algorithm, feel free to create an issue in 
this repository and I will do my best to update the library accordingly.

## A note on alternatives
As an alternative to this library, there is the test module of the [`webauthn4j`](https://github.com/webauthn4j/webauthn4j) project. 
This module differs from softauthn in a few ways:

- it is an internal module and not published as a library
- it is undocumented
- it has a hard dependency on Spring Boot
- it currently supports more features
- it uses the webauthn4j data models

The last point on this list may have the biggest impact on your convenience depending on how you 
implemented WebAuthn in your app.

## Licensing

This project is licensed under the [MIT License](./LICENSE), but it depends on projects with different licensing
which may be relevant to you:

- [java-webauthn-server](https://github.com/Yubico/java-webauthn-server/blob/main/COPYING)
- [COSE-JAVA](https://github.com/cose-wg/COSE-JAVA/blob/master/LICENSE)
