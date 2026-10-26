// Minimal JNI helpers for the UmbraC2 Android beacon.
//
// Only the values the Java APIs cannot provide are implemented natively:
// kernel release, machine type, pid and uid. The protocol itself (upk framing,
// HKDF, AES-GCM) lives in Kotlin on top of the platform crypto providers.
//
// The build uses -fvisibility=hidden, so every exported entry point is marked
// explicitly. extern "C" __attribute__((visibility("default"))) also supplies the extern "C" linkage that the JVM looks
// for when resolving Java_io_umbra_beacon_SysInfo_* symbols.

#include <jni.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <unistd.h>


static jstring to_jstring(JNIEnv *env, const char *text) {
    return env->NewStringUTF(text != nullptr ? text : "unknown");
}

extern "C" __attribute__((visibility("default"))) jstring Java_io_umbra_beacon_SysInfo_nativeKernelRelease(JNIEnv *env, jobject self) {
    (void) self;
    struct utsname info;
    if (uname(&info) != 0) {
        return to_jstring(env, "unknown");
    }
    return to_jstring(env, info.release);
}

extern "C" __attribute__((visibility("default"))) jstring Java_io_umbra_beacon_SysInfo_nativeMachine(JNIEnv *env, jobject self) {
    (void) self;
    struct utsname info;
    if (uname(&info) != 0) {
        return to_jstring(env, "unknown");
    }
    return to_jstring(env, info.machine);
}

extern "C" __attribute__((visibility("default"))) jint Java_io_umbra_beacon_SysInfo_nativePid(JNIEnv *env, jobject self) {
    (void) env;
    (void) self;
    return static_cast<jint>(getpid());
}

extern "C" __attribute__((visibility("default"))) jint Java_io_umbra_beacon_SysInfo_nativeUid(JNIEnv *env, jobject self) {
    (void) env;
    (void) self;
    return static_cast<jint>(getuid());
}
