# agent - dexbgd JVMTI agent

C++ JVMTI agent for Android. Thin layer: handles JVMTI callbacks, executes debugger commands, sends JSON events to the server over an abstract Unix socket.

## Key files
- `src/debugger.cpp` (~3500 lines): main agent logic, JVMTI callbacks, command handlers
- `src/agent.cpp`: JNI_OnLoad, agent setup, `__attribute__((constructor))` for ptrace injection
- `src/debugger.h` / `src/protocol.*`: shared types and JSON protocol helpers
- `injector/`: ptrace-based injection (`dexbgd-inject <pid> <so_path>`)
- `scripts/`: build and attach helpers (`build.bat`, `attach.bat`, `resume.bat`)

## Build
```bash
scripts\build.bat   # requires ANDROID_NDK_HOME, uses -G Ninja
```
Then copy `.so` to testapp jniLibs, run `gradlew clean assembleDebug`, `adb install`.

## Deploy
```bash
adb shell cmd activity attach-agent <pkg> libart_jit_tracer.so
```
Use bare library name (avoids base64 path truncation). Agent must be bundled in APK (SELinux).
