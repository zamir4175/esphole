idf_component_register(SRCS "listupdate.c"
                       INCLUDE_DIRS include
                       REQUIRES common blocklist blocklist_store config_nvs net_dns
                       PRIV_REQUIRES domain hostlist esp_http_client esp-tls mbedtls esp_timer log)
