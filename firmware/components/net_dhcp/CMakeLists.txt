idf_component_register(SRCS "net_dhcp.c"
                       INCLUDE_DIRS include
                       REQUIRES common dhcp_wire dhcp_lease config_nvs
                       PRIV_REQUIRES lwip esp_netif esp_timer esp_wifi log)
