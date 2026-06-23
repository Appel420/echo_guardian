# Android Gradle Wrapper

v0.8 includes the wrapper entrypoint and wrapper properties so CI/local execution uses the same Gradle command path:

```sh
cd native/android
./gradlew :echo-guardian-core:testDebugUnitTest
```

This source package does not vendor `gradle-wrapper.jar`; generate it from a trusted Gradle installation or project bootstrap before offline/local execution if your environment requires the JAR.
