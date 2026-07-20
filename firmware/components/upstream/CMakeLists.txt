idf_component_register(SRCS "pending.c" "upstream.c"
                       INCLUDE_DIRS include
                       REQUIRES common dns_wire cache config_nvs metrics net_dns
                       PRIV_REQUIRES lwip esp_timer log esp_hw_support heap)
