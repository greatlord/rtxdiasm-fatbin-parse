#ifndef RTXDIASM_CUBIN_H
#define RTXDIASM_CUBIN_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---- Texrefs (.nv.constant0 relocations, C# ExtractTextureRefs) ---- */
typedef struct rtxdiasm_texref_entry {
    int descriptor_index; /* relocation offset / 4 (SASS TLD/TLDS immediate) */
    char *name;           /* texture symbol name, malloc'd */
} rtxdiasm_texref_entry_t;

typedef struct rtxdiasm_texref_map {
    rtxdiasm_texref_entry_t *entries;
    size_t count;
} rtxdiasm_texref_map_t;

void rtxdiasm_texref_map_free(rtxdiasm_texref_map_t *map);

int rtxdiasm_cubin_extract_texrefs(const unsigned char *cubin, size_t size,
                                   const char *entry,
                                   rtxdiasm_texref_map_t *out);

int rtxdiasm_image_extract_texrefs(const unsigned char *data, size_t size,
                                   const char *entry,
                                   rtxdiasm_texref_map_t *out);

/* ---- Constant bank globals/images (C# ExtractConstantBankGlobals) ---- */
/* Materializes c[bank][offset] slots relocated against module data symbols. */
typedef struct rtxdiasm_global_image {
    int offset;        /* relocation offset in constant bank section */
    char *name;        /* symbol name, malloc'd */
    long long addend;  /* relocation addend */
    unsigned char *data; /* copied bytes (size = image_size), malloc'd */
    size_t size;
} rtxdiasm_global_image_t;

typedef struct rtxdiasm_global_image_map {
    rtxdiasm_global_image_t *entries;
    size_t count;
} rtxdiasm_global_image_map_t;

void rtxdiasm_global_image_map_free(rtxdiasm_global_image_map_t *map);

/* ---- Section/blob results ---- */
typedef struct rtxdiasm_blob {
    unsigned char *data; /* malloc'd copy */
    size_t size;
} rtxdiasm_blob_t;

void rtxdiasm_blob_free(rtxdiasm_blob_t *b);

/* ---- Constant banks (C# ExtractConstantBank) ---- */
/* Returns malloc'd copy of .nv.constant{bank}(.<entry>) data, or -1 if not found. */
int rtxdiasm_cubin_extract_constant_bank(const unsigned char *cubin, size_t size,
                                         const char *entry, int bank,
                                         rtxdiasm_blob_t *out);

/* Constant bank globals for a bank (e.g. 4), C# ExtractConstantBankGlobals. */
int rtxdiasm_cubin_extract_constant_bank_globals(const unsigned char *cubin, size_t size,
                                                 const char *entry, int bank,
                                                 rtxdiasm_global_image_map_t *out);

/* ---- Surface refs (.surfref, C# SassToPtx) ---- */
/* Surfrefs are synthesized during SASS lift from SULD/SUST/SURED/SUQ as
 * __surf_{bank}_{index}; this formats the canonical name. */
void rtxdiasm_format_surfref_name(char *buf, size_t buf_size, int bank, int index);

/* ---- .nv.info / ABI metadata helpers ---- */
typedef struct rtxdiasm_info_section {
    char *name;          /* e.g. ".nv.info", ".nv.info._Z3foov" (malloc'd) */
    unsigned char *data; /* raw bytes (malloc'd) */
    size_t size;
} rtxdiasm_info_section_t;

typedef struct rtxdiasm_info_sections {
    rtxdiasm_info_section_t *items;
    size_t count;
} rtxdiasm_info_sections_t;

typedef struct rtxdiasm_regcount_entry {
    uint32_t symbol_index;
    uint32_t regcount;
} rtxdiasm_regcount_entry_t;

typedef struct rtxdiasm_regcounts {
    rtxdiasm_regcount_entry_t *entries;
    size_t count;
} rtxdiasm_regcounts_t;

typedef struct rtxdiasm_shared_entry {
    char *name;   /* section name, e.g. ".nv.shared._Z3foov" (malloc'd) */
    uint64_t size;
} rtxdiasm_shared_entry_t;

typedef struct rtxdiasm_shared_sizes {
    rtxdiasm_shared_entry_t *entries;
    size_t count;
} rtxdiasm_shared_sizes_t;

void rtxdiasm_info_sections_free(rtxdiasm_info_sections_t *s);
void rtxdiasm_regcounts_free(rtxdiasm_regcounts_t *r);
void rtxdiasm_shared_sizes_free(rtxdiasm_shared_sizes_t *s);

/* Collect all .nv.info* section payloads from a cubin ELF. */
int rtxdiasm_cubin_collect_info_sections(const unsigned char *cubin, size_t size,
                                         rtxdiasm_info_sections_t *out);
/* Parse EIATTR_REGCOUNT (0x2f, format 4) from .nv.info* sections (C# ReadRegisterCounts). */
int rtxdiasm_cubin_extract_regcounts(const unsigned char *cubin, size_t size,
                                     rtxdiasm_regcounts_t *out);
/* Collect .nv.shared* section sizes (SHT_NOBITS or PROGBITS with size). */
int rtxdiasm_cubin_collect_shared_sizes(const unsigned char *cubin, size_t size,
                                        rtxdiasm_shared_sizes_t *out);

/* ---- Fatbin/cubin helpers ---- */
/* 1 if data begins with ELF magic. */
int rtxdiasm_is_elf_cubin(const unsigned char *data, size_t size);
/* 1 if data looks like a fatbin (wrapper 0x466243B1 or data blob 0xBA55ED50). */
int rtxdiasm_is_fatbin(const unsigned char *data, size_t size);

#ifdef __cplusplus
}
#endif

#endif /* RTXDIASM_CUBIN_H */
