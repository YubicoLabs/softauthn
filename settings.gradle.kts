rootProject.name = "softauthn"

pluginManagement {
    plugins {
        kotlin("jvm") version "2.0.21"
    }

    repositories {
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositories {
        google()
        mavenCentral()
    }
}

