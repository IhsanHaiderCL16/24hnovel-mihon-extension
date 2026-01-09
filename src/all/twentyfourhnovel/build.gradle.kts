plugins {
    id("com.android.application")
    kotlin("android")
    id("kotlinx-serialization")
}

ext {
    set("extName", "24hNovel")
    set("extClass", ".TwentyFourHNovel")
    set("extVersionCode", 1)
    set("extVersionName", "1.0.0")
    set("pkgNameSuffix", "en.twentyfourhnovel")
    set("extLib", "")
}

apply(from = "$rootDir/common.gradle")
