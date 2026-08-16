plugins {
    base
    alias(libs.plugins.android.application) apply false
    alias(libs.plugins.detekt)
    alias(libs.plugins.kotlin.compose) apply false
    alias(libs.plugins.spotless)
}

detekt {
    buildUponDefaultConfig = true
    config.setFrom(files("config/detekt/detekt.yml"))
    basePath.set(layout.projectDirectory)
    source.setFrom(
        files(
            "build.gradle.kts",
            "settings.gradle.kts",
            "app/build.gradle.kts",
        ),
    )
}

spotless {
    kotlin {
        target("app/src/**/*.kt")
        ktlint(libs.versions.ktlint.get())
    }
    kotlinGradle {
        target("build.gradle.kts", "settings.gradle.kts", "app/build.gradle.kts")
        ktlint(libs.versions.ktlint.get())
    }
}

val rustCrateDirectory = layout.projectDirectory.dir("native/refineid-android-core")
val aospProviderContractVerifier = "Scripts/verify-aosp-provider-contract.sh"
val aospProviderContractPatch =
    "platform/aosp/android-13.0.0_r31/patches/packages-apps-KeyChain/" +
        "0005-Bind-statically-trusted-external-key-provider.patch"
val repositoryShellScripts =
    listOf(
        "Scripts/apply-aosp-patches.sh",
        "Scripts/audit-aosp-patches.sh",
        "Scripts/build-aosp-flame.sh",
        "Scripts/stamp-version.sh",
        "Scripts/stage-aosp-prebuilt.sh",
        aospProviderContractVerifier,
        "Scripts/verify-aosp-flame-device.sh",
    )

val rustFormatCheck =
    tasks.register<Exec>("rustFormatCheck") {
        group = "verification"
        description = "Check Rust formatting."
        workingDir(rustCrateDirectory)
        commandLine("cargo", "fmt", "--check")
    }

val rustTest =
    tasks.register<Exec>("rustTest") {
        group = "verification"
        description = "Run locked Rust tests."
        dependsOn(rustFormatCheck)
        workingDir(rustCrateDirectory)
        commandLine("cargo", "test", "--locked")
    }

val rustClippy =
    tasks.register<Exec>("rustClippy") {
        group = "verification"
        description = "Run Clippy for every Rust target with warnings denied."
        dependsOn(rustTest)
        workingDir(rustCrateDirectory)
        commandLine("cargo", "clippy", "--all-targets", "--locked", "--", "-D", "warnings")
    }

val shellCheck =
    tasks.register<Exec>("shellCheck") {
        group = "verification"
        description = "Run ShellCheck for repository shell scripts."
        inputs.files(repositoryShellScripts)
        commandLine("shellcheck", "--shell=bash", *repositoryShellScripts.toTypedArray())
    }

val verifyAospProviderContract =
    tasks.register<Exec>("verifyAospProviderContract") {
        group = "verification"
        description = "Verify the application and AOSP private provider wire contract."
        inputs.files(
            aospProviderContractVerifier,
            "app/src/main/aidl/com/android/keychain/external/ExternalKeyProviderIdentity.aidl",
            "app/src/main/aidl/com/android/keychain/external/ExternalKeyProviderResult.aidl",
            "app/src/main/aidl/com/android/keychain/external/IExternalKeyProviderService.aidl",
            "app/src/main/java/com/android/keychain/external/ExternalKeyProviderIdentity.java",
            "app/src/main/java/com/android/keychain/external/ExternalKeyProviderResult.java",
            aospProviderContractPatch,
        )
        commandLine(aospProviderContractVerifier)
    }

tasks.named("check") {
    dependsOn(":app:check", rustClippy, shellCheck, verifyAospProviderContract)
}
