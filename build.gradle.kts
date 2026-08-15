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
        target("**/*.kt")
        targetExclude("**/build/**", "**/target/**")
        ktlint(libs.versions.ktlint.get())
    }
    kotlinGradle {
        target("*.gradle.kts", "**/*.gradle.kts")
        targetExclude("**/build/**")
        ktlint(libs.versions.ktlint.get())
    }
}

val rustCrateDirectory = layout.projectDirectory.dir("native/refineid-android-core")

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
        commandLine("shellcheck", "--shell=bash", "Scripts/stamp-version.sh")
    }

tasks.named("check") {
    dependsOn(":app:check", rustClippy, shellCheck)
}
