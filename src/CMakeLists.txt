set(CMAKE_INCLUDE_CURRENT_DIR ON)

set(VENOM_SRC utils.c serpent.c omac-serpent.c eax-serpent.c sha256.c pbkdf2-hmac-sha256.c readpass.c venom.c)

add_executable(venom ${VENOM_SRC})

