plugins {
    id("com.android.application")
    kotlin("android")
    id("kotlinx-serialization")
}

ext {
    set("extName", "24hNovel")
    set("extClass", ".TwentyFourHNovel")
    set("extVersionCode", 1)
    set("isNsfw", true)
}

apply(from = "$rootDir/common.gradle")
