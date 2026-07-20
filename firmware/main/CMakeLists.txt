idf_component_register(SRCS "app_main.c" "bench.c"
                       REQUIRES common config_nvs metrics net_dns upstream provisioning blocklist blocklist_store listupdate otaupdate net_dhcp net_dot cache domain policy webapi nvs_flash
                                esp_wifi esp_netif esp_event esp_partition esp_timer)
