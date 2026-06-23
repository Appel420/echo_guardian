plugins {
    id("com.android.library")
    kotlin("android")
}

android {
    namespace = "org.echoguardian"
    compileSdk = 35
    defaultConfig { minSdk = 26 }
}

dependencies {
    testImplementation(kotlin("test"))
}
