# Keep the JNI entry points and the beacon service reachable.
-keepclasseswithmembernames class io.umbra.beacon.SysInfo { native <methods>; }
-keep class io.umbra.beacon.BeaconService { *; }
-keep class io.umbra.beacon.BuildConfig { *; }
-dontwarn org.jetbrains.annotations.**
