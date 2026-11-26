set(FMO_SRCS "")
set(FMO_EMBED_TXTFILES "")
if(CONFIG_PASSPORT_PLUGIN_FMO)
    set(FMO_SRCS
        "src/fmo_wire.cc"
        "src/fmo_crypto.cc"
        "src/fmo_store.cc"
        "src/fmo_book.cc"
        "src/fmo_favorites.cc"
        "src/fmo_stamp.cc"
        "src/fmo_beep.cc"
        "src/fmo_aprs.cc"
        "src/fmo_aprs_store.cc"
        "src/fmo_crl_store.cc"
        "src/fmo_revocation_service.cc"
        "src/fmo_http.cc"
        "src/fmo_sentinel.cc"
        "src/app_fmo.cc"
    )
    set(FMO_EMBED_TXTFILES "src/passport_root.json")
endif()

idf_component_register(
    SRCS ${FMO_SRCS}
    INCLUDE_DIRS "include"
    PRIV_INCLUDE_DIRS "src"
    EMBED_TXTFILES ${FMO_EMBED_TXTFILES}
    REQUIRES
        passport_plugin_api
        bsp
        esp-wifi-connect
        mqtt
        espressif__libsodium
        esp_http_client
        esp_http_server
        esp_audio_codec
        esp_codec_dev
        lvgl__lvgl
        json
        mbedtls
        nvs_flash
        spiffs
        lwip
        esp_timer
)

if(CONFIG_PASSPORT_PLUGIN_FMO AND NOT CMAKE_BUILD_EARLY_EXPANSION)
    # Standalone FMO mobile config page: gzip at build time (mtime 0, reproducible)
    idf_build_get_property(python PYTHON)
    set(fmo_setup_html "${CMAKE_CURRENT_SOURCE_DIR}/fmo_setup.html")
    set(fmo_setup_gz "${CMAKE_CURRENT_BINARY_DIR}/fmo_setup.html.gz")
    add_custom_command(
        OUTPUT "${fmo_setup_gz}"
        COMMAND "${python}" -c "import gzip,sys;open(sys.argv[2],'wb').write(gzip.compress(open(sys.argv[1],'rb').read(),9,mtime=0))"
            "${fmo_setup_html}" "${fmo_setup_gz}"
        DEPENDS "${fmo_setup_html}"
        COMMENT "Compressing FMO plugin setup page"
        VERBATIM
    )
    add_custom_target(passport_fmo_setup_page_gz DEPENDS "${fmo_setup_gz}")
    add_dependencies(${COMPONENT_LIB} passport_fmo_setup_page_gz)
    target_add_binary_data(${COMPONENT_LIB} "${fmo_setup_gz}" BINARY)

    if(PASSPORT_FMO_DISCOVERY_ROOT OR PASSPORT_FMO_DISCOVERY_INTERMEDIATE)
        if(NOT IS_ABSOLUTE "${PASSPORT_FMO_DISCOVERY_ROOT}" OR NOT IS_ABSOLUTE "${PASSPORT_FMO_DISCOVERY_INTERMEDIATE}")
            message(FATAL_ERROR "Set both FMO discovery certificate paths to absolute paths")
        endif()
        foreach(kind ROOT INTERMEDIATE)
            set(cert "${PASSPORT_FMO_DISCOVERY_${kind}}")
            if(NOT EXISTS "${cert}")
                message(FATAL_ERROR "Missing FMO discovery certificate: ${cert}")
            endif()
            file(SIZE "${cert}" cert_size)
            if(cert_size EQUAL 0 OR cert_size GREATER 4096)
                message(FATAL_ERROR "FMO discovery certificate must be between 1 and 4096 bytes")
            endif()
            string(TOLOWER "${kind}" kind_lower)
            set(embedded "${CMAKE_CURRENT_BINARY_DIR}/fmo_discovery_${kind_lower}.json")
            configure_file("${cert}" "${embedded}" COPYONLY)
            target_add_binary_data(${COMPONENT_LIB} "${embedded}" TEXT)
        endforeach()
        target_compile_definitions(${COMPONENT_LIB} PRIVATE PASSPORT_FMO_EXTRA_DISCOVERY_CHAIN=1)
    endif()
endif()
