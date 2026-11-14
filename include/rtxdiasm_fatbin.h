#ifndef RTXDIASM_FATBIN_H
#define RTXDIASM_FATBIN_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum rtxdiasm_fatbin_status {
    RTXDIASM_FATBIN_OK = 0,
    RTXDIASM_FATBIN_NOT_FOUND = 1,
    RTXDIASM_FATBIN_INVALID = 2,
    RTXDIASM_FATBIN_UNSUPPORTED = 3,
    RTXDIASM_FATBIN_IO = 4,
    RTXDIASM_FATBIN_NOMEM = 5
} rtxdiasm_fatbin_status_t;

/* Returns 1 if buffer looks like PTX text (starts with .version or // after ws). */
int rtxdiasm_fatbin_looks_like_ptx(const char *text, size_t len);

/*
 * Extract the first loadable PTX member from a fatbin data blob.
 * Supports NVIDIA fatbin magic 0xBA55ED50 (version 1), including PTX entries
 * stored raw, LZ4-compressed (flags 0x2000), or ZSTD-compressed (flags 0x8000).
 *
 * data/cap must cover the blob (at least header + files_size as declared).
 * On success, *ptx_out receives a malloc'd NUL-terminated buffer and
 * *ptx_len_out its length (excluding NUL). Caller frees *ptx_out.
 *
 * Returns RTXDIASM_FATBIN_OK on success, RTXDIASM_FATBIN_NOT_FOUND if no PTX
 * member can be extracted, or another error for malformed/unsupported cases.
 */
rtxdiasm_fatbin_status_t rtxdiasm_fatbin_extract_first_ptx(
    const unsigned char *data, size_t cap,
    char **ptx_out, size_t *ptx_len_out);

#ifdef __cplusplus
}
#endif

#endif /* RTXDIASM_FATBIN_H */
