cmake_minimum_required(VERSION 3.16)

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(esphole)

# Empaqueta firmware/www/ en una imagen SPIFFS para la partición `www` y la
# flashea junto con la app (spec 003, W13). spiffsgen viene en IDF core.
spiffs_create_partition_image(www ${CMAKE_CURRENT_SOURCE_DIR}/www FLASH_IN_PROJECT)
