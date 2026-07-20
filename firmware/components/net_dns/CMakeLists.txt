idf_component_register(SRCS "net_dns.c" "tcp_dns.c"
                       INCLUDE_DIRS include
                       REQUIRES common dns_wire domain blocklist cache clients ratelimit policy config_nvs metrics
                       PRIV_REQUIRES lwip esp_timer log)
