#pragma once
#include <stdbool.h>
#include "esp_err.h"
#ifdef __cplusplus
extern "C" {
#endif
// Serialize short file operations with background uploads/reads. A successful
// acquire holds the shared storage mutex until release. Failure releases it.
// Reads/startup must pass false. True is reserved for an explicit user write;
// initialization still requires every byte of the partition to be erased.
// Never hold this across network requests. At most one extra file may be open
// because a streaming background upload may already own the other descriptor.
esp_err_t home_storage_acquire(bool initialize_blank);
void home_storage_release(void);
#ifdef __cplusplus
}
#endif
