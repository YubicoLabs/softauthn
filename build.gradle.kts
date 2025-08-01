plugins {
    `java-library`
    `maven-publish`
    kotlin("jvm")
}

val VERSION = "0.0.1"
val GROUP = "com.github.yubicolabs"
val NAME = "softauthn"

version = VERSION
group = GROUP

dependencies {
    testImplementation(platform("org.junit:junit-bom:5.13.4"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")

    implementation("com.augustcellars.cose:cose-java:1.1.0")
    implementation("com.fasterxml.jackson.core:jackson-databind:2.14.0-rc2")

    api("com.yubico:webauthn-server-core:2.1.0")
}

java {
    withSourcesJar()
    withJavadocJar()
    sourceCompatibility = JavaVersion.VERSION_22
    targetCompatibility = JavaVersion.VERSION_22
}

publishing {
    publications {
        create<MavenPublication>("maven") {
            groupId = GROUP
            artifactId = NAME
            version = VERSION

            from(components["java"])
        }
    }
}

tasks.getByName<Test>("test") {
    useJUnitPlatform()
}

tasks.javadoc {
    (options as StandardJavadocDocletOptions).tags("apiNote:a:API Note:", "implNote:a:Implementation Note:")
}

tasks.test {
    useJUnitPlatform()
    testLogging {
        events("passed", "skipped", "failed")
    }
}
