cmake_minimum_required(VERSION 3.10)

include(FetchContent)
FetchContent_Declare(hacl
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE
    GIT_REPOSITORY https://github.com/cryspen/hacl-packages/
    GIT_TAG main
)
FetchContent_MakeAvailable(hacl)

project(hacl-blake-example)

add_executable(example blake-example.cc)

# Add includes from HACL
target_include_directories(example PRIVATE
    ${hacl_SOURCE_DIR}/include
    ${hacl_SOURCE_DIR}/build
    ${hacl_SOURCE_DIR}/karamel/include
    ${hacl_SOURCE_DIR}/karamel/krmllib/dist/minimal
    ${hacl_SOURCE_DIR}/vale/include
)
# Link the HACL library
target_link_libraries(example PRIVATE hacl)
