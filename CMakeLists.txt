cmake_minimum_required(VERSION 3.23)

project(QQuickGit VERSION 0.1 LANGUAGES CXX)

#Add address sanitizer for clang build only
if (CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    add_compile_options($<$<CONFIG:Debug>:-fsanitize=address>)
    add_link_options($<$<CONFIG:Debug>:-fsanitize=address>)
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(QT_QML_GENERATE_QMLLS_INI ON CACHE BOOL "Generate QMLLS INI file")

if (NOT TARGET monad)
    add_subdirectory(monad)
endif()

if (NOT TARGET asyncfuture)
    add_subdirectory(asyncfuture)
endif()

if (NOT TARGET SignalSpyChecker)
    add_subdirectory(SignalSpyChecker)
endif()

find_package(Qt6
    REQUIRED COMPONENTS
    Core
    Quick
    Test
    Concurrent
    Network
)

qt_standard_project_setup(REQUIRES 6.8)

find_package(libgit2)
find_package(Catch2 REQUIRED)
find_package(openssl)

# Collect source files qquickgitLib
file(GLOB qquickgit_CPP_FILES "src/*.cpp")
file(GLOB qquickgit_H_FILES "src/*.h")

# Make the file paths relative to the project directory
set(qquickgit_RELATIVE_CPP_FILES "")
foreach(file ${qquickgit_CPP_FILES})
    file(RELATIVE_PATH relFile "${CMAKE_CURRENT_SOURCE_DIR}" "${file}")
    list(APPEND qquickgit_RELATIVE_CPP_FILES "${relFile}")
endforeach()

set(qquickgit_RELATIVE_H_FILES "")
foreach(file ${qquickgit_H_FILES})
    file(RELATIVE_PATH relFile "${CMAKE_CURRENT_SOURCE_DIR}" "${file}")
    list(APPEND qquickgit_RELATIVE_H_FILES "${relFile}")
endforeach()

# Get all QML and JS files
file(GLOB qquickgit_QML_FILES "qml/*.qml" "qml/*.js")

# Define the list of QML singletons
set(qml_singletons
    # "UnitDefaults.qml"
)

# Remove the singleton files from the regular QML file list
foreach(singleton ${qml_singletons})
    list(REMOVE_ITEM qquickgit_QML_FILES "${CMAKE_CURRENT_SOURCE_DIR}/qml/${singleton}")
endforeach()

# Make the remaining QML files relative to the project directory
set(qquickgit_RELATIVE_QML_FILES "")
foreach(file ${qquickgit_QML_FILES})
    file(RELATIVE_PATH relFile "${CMAKE_CURRENT_SOURCE_DIR}" "${file}")
    message(STATUS "Adding QML file: ${relFile}")
    list(APPEND qquickgit_RELATIVE_QML_FILES "${relFile}")
endforeach()

qt_add_qml_module(qquickgit
    URI QQuickGit
    VERSION 1.0
    STATIC
    OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/QQuickGit
    DEPENDENCIES
        QtQuick
    SOURCES
        ${qquickgit_RELATIVE_CPP_FILES}
        ${qquickgit_RELATIVE_H_FILES}
    QML_FILES
        ${qquickgit_RELATIVE_QML_FILES}
        ${qml_singletons}
)

set_target_properties(qquickgit PROPERTIES POSITION_INDEPENDENT_CODE ON)

target_sources(qquickgit PRIVATE ${cavewherelib_CPP_FILES} ${cavewherelib_H_FILES})

target_link_libraries(qquickgit
    PUBLIC
    Qt6::Quick
    Qt6::Core
    Qt6::Concurrent
    Qt6::Network
    monad
    asyncfuture
    libgit2::libgit2
    openssl::openssl
)

target_include_directories(qquickgit
    PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

# Collect source files qquickgitLib
file(GLOB qquickgit-test_CPP_FILES "tests/*.cpp")
file(GLOB qquickgit-testlib_H_FILES "tests/*.h")

add_library(qquickgit-lfs-test-server STATIC
    tests/lfs/LfsServer.cpp
    tests/lfs/LfsServer.h
)

target_link_libraries(qquickgit-lfs-test-server
    PUBLIC
    Qt6::Core
    Qt6::Network
)

target_include_directories(qquickgit-lfs-test-server
    PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/tests/lfs
)

qt_add_executable(qquickgit-test
    ${qquickgit-test_CPP_FILES}
    ${qquickgit-test_H_FILES}
)

target_link_libraries(qquickgit-test
    PRIVATE
    qquickgit
    qquickgit-lfs-test-server
    Catch2::Catch2
    Qt6::Test
    SignalSpyChecker
)
