cmake_minimum_required(VERSION 3.16)
project(FreeTunnel VERSION 1.1.10 LANGUAGES CXX)

set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(Qt6 COMPONENTS Gui Qml Quick Network Svg REQUIRED)
set(TRUSTTUNNEL_REPO_ROOT "${CMAKE_CURRENT_LIST_DIR}/.." CACHE PATH "Path to TrustTunnelClient repository root")

# QHotkey: cross-platform global (system-wide) hotkeys. Fetched at configure
# time; builds a small static lib linked into the app.
include(FetchContent)
set(QHOTKEY_EXAMPLES OFF CACHE BOOL "" FORCE)
set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
# QHotkey 1.5.0 declares cmake_minimum_required(VERSION 3.1), which modern CMake
# rejects; relax the floor so its subproject configures.
set(CMAKE_POLICY_VERSION_MINIMUM 3.5)
FetchContent_Declare(
    QHotkey
    GIT_REPOSITORY https://github.com/Skycoder42/QHotkey.git
    # Pinned to the immutable commit behind tag 1.5.0 (git ls-remote
    # https://github.com/Skycoder42/QHotkey 1.5.0): this code is compiled into
    # shipped builds, and a tag can be repointed by whoever owns the repo.
    GIT_TAG 34330d6ff5d2ca111c376f6d7da66be9d1817430 # 1.5.0
)
FetchContent_MakeAvailable(QHotkey)

set(FREETUNNEL_GIT_VERSION "unknown")
set(FREETUNNEL_CORE_REF "unknown")
find_package(Git QUIET)
if (GIT_FOUND)
    execute_process(
        COMMAND "${GIT_EXECUTABLE}" rev-parse --short HEAD
        WORKING_DIRECTORY "${CMAKE_CURRENT_LIST_DIR}"
        OUTPUT_VARIABLE FREETUNNEL_GIT_VERSION
        OUTPUT_STRIP_TRAILING_WHITESPACE
        ERROR_QUIET
    )
    # The TrustTunnel core lives in the parent (upstream) checkout. Prefer the
    # nearest *stable* release tag (skip beta/rc/alpha pre-releases), falling
    # back to a short commit when no stable tag is reachable.
    execute_process(
        COMMAND "${GIT_EXECUTABLE}" -C "${TRUSTTUNNEL_REPO_ROOT}" describe --tags --always
                --exclude "*beta*" --exclude "*rc*" --exclude "*alpha*" --exclude "*-dev*"
        OUTPUT_VARIABLE FREETUNNEL_CORE_REF
        OUTPUT_STRIP_TRAILING_WHITESPACE
        ERROR_QUIET
    )
endif()
if (NOT FREETUNNEL_CORE_REF)
    set(FREETUNNEL_CORE_REF "unknown")
endif()

set(APP_ICON_RC)
if (WIN32)
    set(APP_ICON_PATH "${CMAKE_CURRENT_LIST_DIR}/assets/logo.ico")
    set(APP_ICON_RC "${CMAKE_CURRENT_BINARY_DIR}/appicon.rc")
    configure_file(win/appicon.rc.in "${APP_ICON_RC}" @ONLY)
endif ()

# Indirect-branch tracking / shadow stack markers (CET). Harmless on CPUs without
# CET, and required for the loader to enable it on those that do. The linker marks
# an image CET-enabled only when EVERY input object carries the property, so this
# has to be a directory-wide flag rather than one target's option — and therefore
# has to be set BEFORE any target is created, because add_compile_options() only
# applies to targets declared after it.
if(UNIX AND NOT APPLE AND NOT MSVC)
    include(CheckCXXCompilerFlag)
    check_cxx_compiler_flag("-fcf-protection=full" FT_HAS_CF_PROTECTION)
    if(FT_HAS_CF_PROTECTION)
        add_compile_options(-fcf-protection=full)
    endif()
endif()

add_executable(FreeTunnel WIN32 MACOSX_BUNDLE
    main.cpp
    src/app/AppStartup.cpp
    src/app/AppGuiMain.cpp
    include/app/AppStartup.h
    src/app/PlatformAutoStart.cpp
    include/app/PlatformAutoStart.h
    src/app/Backend.cpp
    src/app/BackendHotkeys.cpp
    src/app/BackendUpdates.cpp
    src/app/BackendSettings.cpp
    src/app/BackendLogs.cpp
    src/app/BackendConfig.cpp
    src/app/BackendConfigCreate.cpp
    src/app/BackendConfigImport.cpp
    src/app/BackendConfigShared.cpp
    src/app/BackendConfigShared.h
    src/app/BackendSplit.cpp
    src/app/LogModel.cpp
    include/app/LogModel.h
    include/app/Backend.h
    src/core/AppSettings.cpp
    include/core/AppSettings.h
    src/core/AppRules.cpp
    src/core/AppShortcut.cpp
    src/core/InstalledApps.cpp
    src/core/BypassRules.cpp
    include/core/BypassRules.h
    src/core/ConfigStore.cpp
    include/core/ConfigStore.h
    src/core/DeepLink.cpp
    include/core/DeepLink.h
    src/core/ConfigImport.cpp
    include/core/ConfigImport.h
    src/core/AppImagePath.cpp
    src/core/ConfigPaths.cpp
    include/core/ConfigPaths.h
    src/core/ControlCommand.cpp
    include/core/ControlCommand.h
    src/core/InstanceControl.cpp
    include/core/InstanceControl.h
    src/core/ConfigToml.cpp
    include/core/ConfigToml.h
    src/core/NetBind.cpp
    src/core/ProcessLookup.cpp
    include/core/NetBind.h
    src/core/AppUiUtils.cpp
    include/core/AppUiUtils.h
    src/core/UpdateChecker.cpp
    include/core/UpdateChecker.h
    src/core/VersionCompare.cpp
    include/core/VersionCompare.h
    src/core/CredentialStore.cpp
    include/core/CredentialStore.h
    src/core/ReleaseVerify.cpp
    include/core/ReleaseVerify.h
    src/vpn/qt_trusttunnel_client.cpp
    src/vpn/qt_trusttunnel_corelog.cpp
    src/vpn/qt_trusttunnel_fdwatch.cpp
    src/vpn/qt_trusttunnel_connect.cpp
    src/vpn/qt_trusttunnel_events.cpp
    src/vpn/qt_trusttunnel_events.h
    src/vpn/qt_trusttunnel_platform.cpp
    src/vpn/qt_trusttunnel_platform.h
    include/vpn/qt_trusttunnel_client.h
    src/vpn/vpn_helper_client.cpp
    include/vpn/vpn_helper_client.h
    src/vpn/vpn_helper_launch.cpp
    include/vpn/vpn_helper_launch.h
    src/vpn/vpn_helper_server.cpp
    include/vpn/vpn_helper_server.h
    assets/app.qrc
    qml.qrc
    i18n/i18n.qrc
    ${APP_ICON_RC}
)

target_compile_definitions(FreeTunnel PRIVATE
    FREETUNNEL_VERSION="${PROJECT_VERSION}"
    FREETUNNEL_GIT_VERSION="${FREETUNNEL_GIT_VERSION}"
    FREETUNNEL_CORE_REF="${FREETUNNEL_CORE_REF}"
)

# --- Build hardening -------------------------------------------------------
# Defense-in-depth for a process that parses untrusted network/IPC/TLV input in
# C++. Scoped to the FreeTunnel target only (PRIVATE) so the VPN core, built as a
# parent project, is unaffected. Flags are probed before use so an unusual
# toolchain (e.g. Apple clang lacking -fstack-clash-protection) just skips them.
include(CheckCXXCompilerFlag)
function(ft_add_cxx_flag_if_supported tgt flag)
    string(MAKE_C_IDENTIFIER "FT_HAS${flag}" _var)
    check_cxx_compiler_flag("${flag}" ${_var})
    if(${_var})
        target_compile_options(${tgt} PRIVATE ${flag})
    endif()
endfunction()

if(MSVC)
    target_compile_options(FreeTunnel PRIVATE /W4 /guard:cf /sdl)
    target_link_options(FreeTunnel PRIVATE /guard:cf /DYNAMICBASE /NXCOMPAT /HIGHENTROPYVA)
else()
    target_compile_options(FreeTunnel PRIVATE -Wall -Wextra)
    foreach(_f -fstack-protector-strong -Wformat -Wformat-security)
        ft_add_cxx_flag_if_supported(FreeTunnel ${_f})
    endforeach()
    # Apple clang accepts -fstack-clash-protection but no-ops it (warns per file),
    # so probe it only where it actually does something.
    if(UNIX AND NOT APPLE)
        ft_add_cxx_flag_if_supported(FreeTunnel -fstack-clash-protection)
        # Indirect-branch tracking / shadow stack markers (CET). Harmless on CPUs
        # without CET, and required for the loader to enable it on those that do.
        # The linker only marks the image as CET-enabled when EVERY input object
        # carries the property, so this has to reach the whole compile, not just
        # this target's own sources.
        # Set at the top of this file, before any target exists — see the note there.
        # add_compile_options() only reaches targets created after it runs, and
        # FreeTunnel is created long before this block, so putting it here reached
        # nothing at all: the flag was probed, reported as supported, and dropped.
    endif()
    # _FORTIFY_SOURCE only does anything in an optimizing build, and redefining it
    # (some distros pre-define it) warns — so undefine first, optimized configs only.
    # Level 3 adds the dynamic-size object checks level 2 can't do; fall back to
    # 2 on toolchains that don't know it (probe compiles with -Werror).
    set(_ft_fortify 2)
    check_cxx_compiler_flag("-Werror -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=3" FT_HAS_FORTIFY3)
    if(FT_HAS_FORTIFY3)
        set(_ft_fortify 3)
    endif()
    target_compile_options(FreeTunnel PRIVATE
        $<$<NOT:$<CONFIG:Debug>>:-U_FORTIFY_SOURCE>
        $<$<NOT:$<CONFIG:Debug>>:-D_FORTIFY_SOURCE=${_ft_fortify}>)
    if(UNIX AND NOT APPLE)
        # Full RELRO + non-executable stack on Linux.
        target_link_options(FreeTunnel PRIVATE LINKER:-z,relro LINKER:-z,now LINKER:-z,noexecstack)
    endif()
endif()
# Position-independent executable (explicit; default on macOS, enforced on Linux).
set_target_properties(FreeTunnel PROPERTIES POSITION_INDEPENDENT_CODE ON)

target_include_directories(FreeTunnel PRIVATE
    include
    include/app
    include/core
    include/vpn
)

# The client must be built from inside the TrustTunnelClient tree, where the
# `vpnlibs_trusttunnel` target is defined (see .github/workflows/build.yml).
if (NOT TARGET vpnlibs_trusttunnel)
    message(FATAL_ERROR
        "vpnlibs_trusttunnel target not found.\n"
        "Build FreeTunnel from inside the TrustTunnel/TrustTunnelClient tree "
        "(this directory injected as a subdirectory of the core's root CMake), "
        "so the VPN core library is available to link against.")
endif()
target_link_libraries(FreeTunnel PRIVATE Qt6::Gui Qt6::Qml Qt6::Quick Qt6::Network Qt6::Svg QHotkey::QHotkey vpnlibs_trusttunnel)
include(${CMAKE_CURRENT_LIST_DIR}/cmake/FreetunnelDeps.cmake)
freetunnel_link_linux_secrets(FreeTunnel)
target_include_directories(FreeTunnel PRIVATE
    ${TRUSTTUNNEL_REPO_ROOT}/trusttunnel/include
    ${TRUSTTUNNEL_REPO_ROOT}/common/include
    ${TRUSTTUNNEL_REPO_ROOT}/core/include
    ${TRUSTTUNNEL_REPO_ROOT}/net/include
    ${TRUSTTUNNEL_REPO_ROOT}/tcpip/include
)

set_target_properties(FreeTunnel PROPERTIES
    OUTPUT_NAME "FreeTunnel"
    MACOSX_BUNDLE_BUNDLE_NAME "FreeTunnel"
    MACOSX_BUNDLE_GUI_IDENTIFIER "com.freetunnel.app"
    MACOSX_BUNDLE_ICON_FILE "logo"
    MACOSX_BUNDLE_SHORT_VERSION_STRING "${PROJECT_VERSION}"
    MACOSX_BUNDLE_BUNDLE_VERSION "${PROJECT_VERSION}"
    # Custom Info.plist adds CFBundleURLTypes so macOS routes freetunnel:// and
    # tt:// links to the app (delivered as QFileOpenEvent).
    MACOSX_BUNDLE_INFO_PLIST "${CMAKE_CURRENT_LIST_DIR}/macos/Info.plist.in"
)

if (WIN32)
    # The GUI runs as the normal user (asInvoker, the default). Only the helper
    # process is elevated on demand via ShellExecuteEx "runas", which needs
    # shell32 for ShellExecuteExW.
    # iphlpapi: GetExtendedTcpTable/GetExtendedUdpTable, which is how per-app
    # split tunnelling finds the process behind a connection on Windows.
    # ole32/uuid: IShellLink, which is how a dropped .lnk is followed to its target.
    target_link_libraries(FreeTunnel PRIVATE shell32 iphlpapi ole32 uuid)
endif()

# OpenSSL for in-app Ed25519 verification (UpdateChecker). On Linux the VPN
# core links Conan BoringSSL statically; FindOpenSSL would pick distro libcrypto
# and break HTTP/3 builds (ECH/HPKE live in BoringSSL libssl.a, not in 22.04's
# OpenSSL 3.0). macOS/Windows use the system/Homebrew/MSVC package explicitly.
if (UNIX AND NOT APPLE)
    if (NOT DISABLE_HTTP3)
        # Conan's boringssl package exposes the OpenSSL::SSL/Crypto targets; the
        # find_package used to happen transitively via quiche, which upstream
        # dropped, so ask for it ourselves (resolved from the conan generators
        # dir, not the distro OpenSSL).
        if (NOT TARGET OpenSSL::SSL)
            find_package(OpenSSL REQUIRED)
        endif ()
        # Upstream lists libcrypto before libssl; ECH needs libssl→libcrypto refs.
        target_link_options(FreeTunnel PRIVATE "LINKER:--start-group")
        target_link_libraries(FreeTunnel PRIVATE OpenSSL::SSL OpenSSL::Crypto)
        target_link_options(FreeTunnel PRIVATE "LINKER:--end-group")
    endif ()
    if (NOT OpenSSL_FOUND AND NOT TARGET OpenSSL::Crypto)
        # The HTTP/3-off path is the documented local dev build (CONTRIBUTING),
        # not something we ship, so it stays buildable without OpenSSL — but
        # say so, because the only other symptom is an updater that rejects
        # every release as unsigned.
        message(WARNING
            "Building without OpenSSL: in-app update signature verification will "
            "be inert (verifyEd25519Signature() always returns false). Fine for a "
            "local build, never for one you distribute.")
    endif ()
else ()
    # REQUIRED, not QUIET. macOS and Windows are release platforms — together
    # most of the downloads — and this used to be optional, which meant a build
    # machine without OpenSSL produced a perfectly healthy-looking binary whose
    # updater silently rejected every update forever. Nothing caught it: the
    # tests that exercise signature verification are compiled out by the same
    # __has_include that disables the feature, so they disappear precisely when
    # they would have fired. Fail the configure instead.
    find_package(OpenSSL REQUIRED)
    target_link_libraries(FreeTunnel PRIVATE OpenSSL::Crypto)
endif ()

if (APPLE)
    # Place macOS icon into the bundle Resources dir
    set_source_files_properties(assets/logo.icns PROPERTIES MACOSX_PACKAGE_LOCATION "Resources")
    target_sources(FreeTunnel PRIVATE assets/logo.icns)
    # Unified title bar (transparent bar + full-size content) needs a tiny bit of
    # Objective-C++ talking to AppKit.
    target_sources(FreeTunnel PRIVATE src/app/MacWindow.mm include/app/MacWindow.h)
    target_link_libraries(FreeTunnel PRIVATE "-framework AppKit" "-framework Security")
endif()

# Bundle assets
add_custom_command(TARGET FreeTunnel POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        ${CMAKE_CURRENT_LIST_DIR}/assets/logo.png
        $<TARGET_FILE_DIR:FreeTunnel>/assets/logo.png
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        ${TRUSTTUNNEL_REPO_ROOT}/LICENSE
        $<TARGET_FILE_DIR:FreeTunnel>/assets/LICENSE
)

# Lightweight, core-independent unit tests (off by default; the standalone
# tests/CMakeLists.txt is what CI builds directly).
option(BUILD_FREETUNNEL_TESTS "Build FreeTunnel unit tests" OFF)
if (BUILD_FREETUNNEL_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()
