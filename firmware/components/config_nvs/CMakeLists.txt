idf_component_register(SRCS "config_nvs.c"
                       INCLUDE_DIRS include
                       REQUIRES common
                       PRIV_REQUIRES nvs_flash esp_common log)
