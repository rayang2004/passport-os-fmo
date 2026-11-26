#include "apps/home/home_background.h"
#include "apps/home/home_storage.h"
#include "esp_spiffs.h"
#include "esp_partition.h"
#include "nvs.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "src/libs/tjpgd/tjpgd.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#ifndef BACKGROUND_BASE
#define BACKGROUND_BASE "/storage"
#endif
static const char *const paths[] = {BACKGROUND_BASE "/background-a.jpg", BACKGROUND_BASE "/background-b.jpg"};
static StaticSemaphore_t mutex_buffer;
static SemaphoreHandle_t mutex;
static portMUX_TYPE init_mux = portMUX_INITIALIZER_UNLOCKED;
static bool mounted;
static FILE *upload;
static size_t written, expected;
static int upload_bank = -1;

static void lock(void) {
    portENTER_CRITICAL(&init_mux);
    if (!mutex) mutex = xSemaphoreCreateMutexStatic(&mutex_buffer);
    portEXIT_CRITICAL(&init_mux);
    xSemaphoreTake(mutex, portMAX_DELAY);
}
static void unlock(void) { xSemaphoreGive(mutex); }
static bool storage_is_erased(void) {
    const esp_partition_t *partition = esp_partition_find_first(ESP_PARTITION_TYPE_DATA, ESP_PARTITION_SUBTYPE_DATA_SPIFFS, "storage");
    if (!partition) return false;
    uint8_t block[512];
    for (size_t offset = 0; offset < partition->size; offset += sizeof(block)) {
        const size_t count = partition->size - offset < sizeof(block) ? partition->size - offset : sizeof(block);
        if (esp_partition_read(partition, offset, block, count) != ESP_OK) return false;
        for (size_t i = 0; i < count; ++i) if (block[i] != 0xFF) return false;
    }
    return true;
}
static esp_err_t mount_storage(bool initialize_blank) {
    if (mounted) return ESP_OK;
    esp_vfs_spiffs_conf_t config = {
        .base_path = BACKGROUND_BASE, .partition_label = "storage", .max_files = 2,
        .format_if_mount_failed = false,
    };
    esp_err_t result = esp_vfs_spiffs_register(&config);
    // Only an explicit user write may initialize a verified blank partition.
    // Existing portraits/cards and unknown firmware data are never auto-formatted.
    if (result != ESP_OK && initialize_blank && storage_is_erased()) {
        config.format_if_mount_failed = true;
        result = esp_vfs_spiffs_register(&config);
    }
    if (result == ESP_OK) mounted = true;
    return result;
}
esp_err_t home_storage_acquire(bool initialize_blank) {
    lock();
    const esp_err_t result = mount_storage(initialize_blank);
    if (result != ESP_OK) unlock();
    return result;
}
void home_storage_release(void) { unlock(); }
static esp_err_t active_bank(int *out) {
    nvs_handle_t handle;
    uint8_t bank = 255;
    *out = -1;
    esp_err_t result = nvs_open("home_bg", NVS_READONLY, &handle);
    if (result == ESP_ERR_NVS_NOT_FOUND) return ESP_OK;
    if (result == ESP_OK) {
        result = nvs_get_u8(handle, "bank", &bank);
        nvs_close(handle);
    }
    if (result == ESP_ERR_NVS_NOT_FOUND) return ESP_OK;
    if (result != ESP_OK) return result;
    if (bank > 1) return ESP_ERR_INVALID_STATE;
    *out = bank;
    return ESP_OK;
}
static esp_err_t info_locked(bool *present, size_t *bytes) {
    *present = false; *bytes = 0;
    int bank;
    esp_err_t result = active_bank(&bank);
    if (result != ESP_OK) return result;
    if (bank < 0) return ESP_OK;
    result = mount_storage(false);
    if (result != ESP_OK) return result;
    struct stat st;
    if (bank >= 0 && stat(paths[bank], &st) == 0 && st.st_size > 0 && st.st_size <= HOME_BACKGROUND_MAX_BYTES) {
        *present = true; *bytes = (size_t)st.st_size;
    }
    return ESP_OK;
}
esp_err_t home_background_info(bool *present, size_t *bytes) {
    if (!present || !bytes) return ESP_ERR_INVALID_ARG;
    lock(); const esp_err_t result = info_locked(present, bytes); unlock(); return result;
}
esp_err_t home_background_load(uint8_t **data, size_t *bytes) {
    if (!data || !bytes) return ESP_ERR_INVALID_ARG;
    *data = NULL; *bytes = 0;
    lock();
    bool present;
    esp_err_t result = info_locked(&present, bytes);
    if (result == ESP_OK && !present) result = ESP_ERR_NOT_FOUND;
    if (result == ESP_OK) {
        int bank;
        result = active_bank(&bank);
        FILE *fp = result == ESP_OK && bank >= 0 ? fopen(paths[bank], "rb") : NULL;
        if (!fp) result = ESP_FAIL;
        else {
            *data = malloc(*bytes);
            if (!*data) result = ESP_ERR_NO_MEM;
            else if (fread(*data, 1, *bytes, fp) != *bytes) result = ESP_FAIL;
            fclose(fp);
        }
    }
    if (result != ESP_OK) { free(*data); *data = NULL; *bytes = 0; }
    unlock(); return result;
}
static size_t jpeg_input(JDEC *decoder, uint8_t *buffer, size_t count) {
    FILE *fp = decoder->device;
    if (buffer) return fread(buffer, 1, count, fp);
    return fseek(fp, (long)count, SEEK_CUR) == 0 ? count : 0;
}
static int jpeg_discard(JDEC *decoder, void *pixels, JRECT *area) {
    (void)decoder; (void)pixels; (void)area; return 1;
}
static bool valid_jpeg(const char *path) {
    FILE *fp = fopen(path, "rb");
    if (!fp) return false;
    // LVGL's in-memory TJPGD path expects a JFIF JPEG (canvas.toBlob output).
    static const uint8_t signature[] = {0xFF,0xD8,0xFF,0xE0,0,0x10,'J','F','I','F'};
    uint8_t header[sizeof(signature)];
    bool ok = fread(header, 1, sizeof(header), fp) == sizeof(header) && !memcmp(header, signature, sizeof(header));
    rewind(fp);
    void *work = ok ? malloc(4096) : NULL;
    if (!work) ok = false;
    if (ok) {
        JDEC decoder;
        ok = jd_prepare(&decoder, jpeg_input, work, 4096, fp) == JDR_OK &&
             decoder.width == HOME_BACKGROUND_W && decoder.height == HOME_BACKGROUND_H;
        if (ok) ok = jd_decomp(&decoder, jpeg_discard, 0) == JDR_OK;
    }
    free(work); fclose(fp); return ok;
}
static void abort_locked(void) {
    if (upload) { fclose(upload); upload = NULL; }
    if (upload_bank >= 0) remove(paths[upload_bank]);
    upload_bank = -1; written = expected = 0;
}
void home_background_abort(void) { lock(); abort_locked(); unlock(); }
esp_err_t home_background_write(const uint8_t *data, size_t len, bool first, bool last, size_t total) {
    if (!data || !len || !total || total > HOME_BACKGROUND_MAX_BYTES) return ESP_ERR_INVALID_SIZE;
    lock();
    esp_err_t result = ESP_OK;
    if (first) {
        abort_locked();
        result = mount_storage(true);
        if (result == ESP_OK) {
            int active;
            result = active_bank(&active);
            if (result == ESP_OK) {
                upload_bank = active == 0 ? 1 : 0; expected = total;
                upload = fopen(paths[upload_bank], "wb");
                if (!upload) result = ESP_FAIL;
            }
        }
    }
    if (result == ESP_OK && (!upload || expected != total || written > expected || len > expected - written)) result = ESP_ERR_INVALID_SIZE;
    if (result == ESP_OK && fwrite(data, 1, len, upload) != len) result = ESP_FAIL;
    if (result == ESP_OK) written += len;
    if (result == ESP_OK && last) {
        const int closed = fclose(upload); upload = NULL;
        if (closed || written != expected) result = ESP_FAIL;
        else if (!valid_jpeg(paths[upload_bank])) result = ESP_ERR_INVALID_ARG;
        if (result == ESP_OK) {
            nvs_handle_t handle;
            result = nvs_open("home_bg", NVS_READWRITE, &handle);
            if (result == ESP_OK) {
                result = nvs_set_u8(handle, "bank", (uint8_t)upload_bank);
                if (result == ESP_OK) {
                    // set_u8 may already have reached flash even if commit later fails.
                    // Keep this fully validated bank so either persisted pointer remains readable.
                    upload_bank = -1;
                    result = nvs_commit(handle);
                }
                nvs_close(handle);
            }
        }
        if (result == ESP_OK) { upload_bank = -1; written = expected = 0; }
    }
    if (result != ESP_OK) abort_locked();
    unlock(); return result;
}
esp_err_t home_background_clear(void) {
    lock();
    nvs_handle_t handle;
    esp_err_t result = nvs_open("home_bg", NVS_READWRITE, &handle);
    if (result == ESP_OK) {
        result = nvs_erase_key(handle, "bank");
        if (result == ESP_ERR_NVS_NOT_FOUND) result = ESP_OK;
        if (result == ESP_OK) result = nvs_commit(handle);
        nvs_close(handle);
    }
    // Only our new background files may be removed, after pointer persistence succeeds.
    if (result == ESP_OK) {
        abort_locked();
        if (mount_storage(false) == ESP_OK) { remove(paths[0]); remove(paths[1]); }
    }
    unlock(); return result;
}
