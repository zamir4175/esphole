idf_component_register(SRCS "net_dot.c"
                       INCLUDE_DIRS include
                       REQUIRES common dns_wire dot_frame config_nvs net_dns cache
                       PRIV_REQUIRES esp-tls mbedtls esp_timer esp_wifi log lwip)
