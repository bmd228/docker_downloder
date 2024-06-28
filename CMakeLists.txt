# CMakeList.txt: проект CMake для docker_downloder; включите исходный код и определения,
# укажите здесь логику для конкретного проекта.
#
cmake_minimum_required (VERSION 3.17)

project ("docker_downloder")
find_package(OpenSSL REQUIRED)
find_package(LibArchive REQUIRED)
find_package(CLI11 CONFIG REQUIRED)
# Добавьте источник в исполняемый файл этого проекта.
add_executable (docker_downloder "docker_downloder.cpp" "docker_downloder.h" "httplib.h" "json.hpp")
target_link_libraries(docker_downloder PRIVATE OpenSSL::SSL)
target_link_libraries(docker_downloder PRIVATE OpenSSL::Crypto)
target_link_libraries(docker_downloder PRIVATE LibArchive::LibArchive)
target_link_libraries(docker_downloder PRIVATE CLI11::CLI11)
add_compile_definitions(CPPHTTPLIB_OPENSSL_SUPPORT=ON)
target_compile_features(docker_downloder PRIVATE cxx_std_17)
# TODO: Добавьте тесты и целевые объекты, если это необходимо.
