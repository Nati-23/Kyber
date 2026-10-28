cmake_minimum_required(VERSION 3.10)
project(myoqs VERSION 1.0.0 LANGUAGES C)

set(CMAKE_C_STANDARD 99)

# ---------------------------------------------------------------
# Include paths
# ---------------------------------------------------------------
include_directories(include src/kem)

# ---------------------------------------------------------------
# Core library source files
# ---------------------------------------------------------------
set(MYOQS_SOURCES
    src/myoqs.c

    # Kyber reference implementation
    src/kem/kem.c
    src/kem/indcpa.c
    src/kem/poly.c
    src/kem/polyvec.c
    src/kem/ntt.c
    src/kem/reduce.c
    src/kem/cbd.c
    src/kem/fips202.c
    src/kem/symmetric.c
    src/kem/verify.c
    src/kem/symmetric-shake.c

    # Randomness
    src/kem/randombytes.c
)
# ---------------------------------------------------------------
# Build static library: libmyoqs.a
# ---------------------------------------------------------------
add_library(myoqs STATIC ${MYOQS_SOURCES})
target_include_directories(myoqs PUBLIC include src/kem)

# Link bcrypt on Windows for BCryptGenRandom
if(WIN32)
    target_link_libraries(myoqs bcrypt)
endif()

# ---------------------------------------------------------------
# Build test executable
# ---------------------------------------------------------------
add_executable(test_kyber tests/test_kyber.c)
target_link_libraries(test_kyber myoqs)

add_executable(test_vector_kyber tests/test_vector_kyber.c)
target_link_libraries(test_vector_kyber myoqs)

# ---------------------------------------------------------------
# Build demo executable (your kyber_kem style demo)
# ---------------------------------------------------------------
# add_executable(demo_kyber tests/demo_kyber.c)
# target_link_libraries(demo_kyber myoqs)

# ---------------------------------------------------------------
# Interactive CLI — user input + file save/load
# ---------------------------------------------------------------
add_executable(kyber_interactive tests/kyber_interactive.c)
target_link_libraries(kyber_interactive myoqs)

message(STATUS "MyOQS Library v${PROJECT_VERSION}")
message(STATUS "Sources: ${MYOQS_SOURCES}")