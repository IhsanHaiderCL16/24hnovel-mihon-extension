plugins {
    id("com.android.application")
    kotlin("android")
    id("kotlinx-serialization")
}

ext {
    extName = "24hNovel"
    extClass = ".TwentyFourHNovel"
    extVersionCode = 1
}

dependencies {
    implementation(project(":core"))
}

apply(from = "$rootDir/common.gradle")
