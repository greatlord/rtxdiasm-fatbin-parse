#include "rtxdiasm_fatbin.h"

#include <lz4.h>
#include <zstd.h>

#include <stdlib.h>
#include <string.h>

static uint16_t rd16le(const unsigned char *p) {
    return (uint16_t)(p[0] | ((uint16_t)p[1] << 8));
}

static uint32_t rd32le(const unsigned char *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint64_t rd64le(const unsigned char *p) {
    uint64_t lo = rd32le(p), hi = rd32le(p + 4);
    return lo | (hi << 32);
}

int rtxdiasm_fatbin_looks_like_ptx(const char *text, size_t len) {
    size_t i = 0;
    while (i < len && (text[i] == ' ' || text[i] == '\t' || text[i] == '\n' ||
                       text[i] == '\r' || text[i] == '\f' || text[i] == '\v'))
        i++;
    if (i + 8 <= len && memcmp(text + i, ".version", 8) == 0)
        return 1;
    if (i + 1 < len && text[i] == '/' && text[i + 1] == '/')
        return 1;
    return 0;
}

static int decompress_member(const unsigned char *src, size_t slen,
                             unsigned char *dst, size_t dcap, uint64_t flags,
                             size_t *dlen_out) {
    size_t got = 0;
    if (flags & 0x8000ull) {
        size_t n = ZSTD_decompress(dst, dcap, src, slen);
        if (ZSTD_isError(n))
            return -1;
        got = n;
    } else if (flags & 0x2000ull) {
        int n = LZ4_decompress_safe((const char *)src, (char *)dst,
                                    (int)slen, (int)dcap);
        if (n < 0)
            return -1;
        got = (size_t)n;
    } else {
        return -1;
    }
    if (dlen_out)
        *dlen_out = got;
    return 0;
}

rtxdiasm_fatbin_status_t rtxdiasm_fatbin_extract_first_ptx(
    const unsigned char *data, size_t cap,
    char **ptx_out, size_t *ptx_len_out) {
    if (!ptx_out || !ptx_len_out)
        return RTXDIASM_FATBIN_INVALID;
    *ptx_out = NULL;
    *ptx_len_out = 0;
    if (!data || cap < 16)
        return RTXDIASM_FATBIN_INVALID;
    if (rd32le(data) != 0xBA55ED50u || rd16le(data + 4) != 1)
        return RTXDIASM_FATBIN_INVALID;

    uint64_t files_size = rd64le(data + 8);
    if (files_size > (uint64_t)512 << 20)
        return RTXDIASM_FATBIN_INVALID;
    size_t pos = 16, end = pos + (size_t)files_size;
    if (end < pos || end > cap)
        return RTXDIASM_FATBIN_INVALID;

    while (pos + 64 <= end) {
        const unsigned char *e = data + pos;
        uint16_t kind = rd16le(e);
        uint32_t header_size = rd32le(e + 4);
        uint32_t payload_size = rd32le(e + 8);
        uint32_t compressed_size = rd32le(e + 16);
        uint64_t flags = rd64le(e + 40);
        uint64_t uncompressed_size = rd64le(e + 56);

        if (header_size < 64 || header_size > 4096)
            return RTXDIASM_FATBIN_INVALID;
        size_t pay = pos + header_size;
        size_t disk = payload_size > compressed_size ? payload_size : compressed_size;
        if (pay < pos || pay + disk < pay || pay + disk > end)
            return RTXDIASM_FATBIN_INVALID;

        if (kind == 1 && payload_size > 0) {
            if ((flags & (0x2000ull | 0x8000ull)) && compressed_size > 0 &&
                compressed_size <= disk && uncompressed_size > 0 &&
                uncompressed_size <= ((uint64_t)256 << 20)) {
                size_t raw = compressed_size < disk ? compressed_size : disk;
                unsigned char *dec = malloc((size_t)uncompressed_size + 1);
                if (!dec)
                    return RTXDIASM_FATBIN_NOMEM;
                size_t got = 0;
                if (decompress_member(data + pay, raw, dec,
                                      (size_t)uncompressed_size, flags, &got) == 0 &&
                    got == (size_t)uncompressed_size) {
                    dec[got] = '\0';
                    if (rtxdiasm_fatbin_looks_like_ptx((const char *)dec, got)) {
                        *ptx_out = (char *)dec;
                        *ptx_len_out = got;
                        return RTXDIASM_FATBIN_OK;
                    }
                }
                free(dec);
                /* undecodable/not-ptx: keep scanning */
            } else if (!(flags & (0x2000ull | 0x8000ull))) {
                size_t n = payload_size;
                while (n > 0 && data[pay + n - 1] == 0)
                    n--;
                char *out = malloc(n + 1);
                if (!out)
                    return RTXDIASM_FATBIN_NOMEM;
                memcpy(out, data + pay, n);
                out[n] = '\0';
                if (rtxdiasm_fatbin_looks_like_ptx(out, n)) {
                    *ptx_out = out;
                    *ptx_len_out = n;
                    return RTXDIASM_FATBIN_OK;
                }
                free(out);
            }
        }

        size_t step = header_size + disk;
        if (step == 0 || pos + step < pos || pos + step > end)
            return RTXDIASM_FATBIN_INVALID;
        pos += step;
    }

    return RTXDIASM_FATBIN_NOT_FOUND;
}
