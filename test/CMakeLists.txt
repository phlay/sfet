include_directories("../src")

add_executable(test-pbkdf2 test-pbkdf2.c printvec.c ../src/sha256.c ../src/pbkdf2-hmac-sha256.c)
add_test(NAME test-pbkdf2 COMMAND test-pbkdf2)

