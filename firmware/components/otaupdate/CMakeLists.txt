idf_component_register(SRCS "otaupdate.c"
                       INCLUDE_DIRS include
                       REQUIRES common
                       PRIV_REQUIRES app_update esp_app_format esp_timer esp_system log
                                     esp_https_ota esp_http_client esp-tls mbedtls)
