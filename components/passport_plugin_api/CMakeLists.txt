idf_component_register(
    SRCS "passport_plugin.c"
    INCLUDE_DIRS "include"
    REQUIRES bsp esp_http_server lvgl__lvgl
)
