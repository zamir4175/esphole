idf_component_register(SRCS "prov_button.c" "prov_portal.c" "provisioning.c"
                       INCLUDE_DIRS include
                       REQUIRES common config_nvs provision_logic dns_wire
                       PRIV_REQUIRES esp_wifi esp_netif esp_event esp_http_server esp_driver_gpio lwip esp_timer log nvs_flash esp_hw_support)
