idf_component_register(SRCS "webapi.c"
                       INCLUDE_DIRS include
                       REQUIRES common config_nvs webapi_logic metrics cache net_dns upstream listupdate otaupdate net_dhcp net_dot
                       PRIV_REQUIRES esp_http_server spiffs mbedtls esp_timer esp_hw_support esp_system log)
