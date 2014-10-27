include_directories("../src")

add_executable(test-sha512 test-sha512.c ../src/sha512.c)
add_test(NAME test-sha512 COMMAND test-sha512)

add_executable(test-pbkdf2 test-pbkdf2.c printvec.c ../src/sha512.c ../src/pbkdf2-hmac-sha512.c)
add_test(NAME test-pbkdf2 COMMAND test-pbkdf2)

