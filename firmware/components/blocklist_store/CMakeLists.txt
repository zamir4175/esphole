idf_component_register(SRCS "blocklist_load.c"
                       INCLUDE_DIRS include
                       REQUIRES blocklist
                       PRIV_REQUIRES esp_partition esp_timer log)
