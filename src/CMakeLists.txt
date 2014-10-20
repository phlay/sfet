set(CMAKE_INCLUDE_CURRENT_DIR ON)

set(VENOM_SRC utils.c serpent.c omac-serpent.c eax-serpent.c pbkdf2-omac-serpent.c venom.c)

add_executable(venom ${VENOM_SRC})

