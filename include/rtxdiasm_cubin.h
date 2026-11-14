#ifndef RTXDIASM_CUBIN_H
#define RTXDIASM_CUBIN_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Texture ref map extracted from cubin .nv.constant0 relocations (C#-style). */
typedef struct rtxdiasm_texref_entry {
    int descriptor_index; /* relocation offset / 4 (SASS TLD/TLDS immediate) */
    char *name;           /* texture symbol name, malloc'd */
} rtxdiasm_texref_entry_t;

typedef struct rtxdiasm_texref_map {
    rtxdiasm_texref_entry_t *entries;
    size_t count;
} rtxdiasm_texref_map_t;

void rtxdiasm_texref_map_free(rtxdiasm_texref_map_t *map);

/*
 * Extract texref descriptor->symbol mapping from a cubin ELF image, mirroring
 * C# RtxDisamApi.ExtractTextureRefs:
 * - prefer .nv.constant0.<entry> when entry is provided/non-empty
 * - otherwise .nv.constant0, or the sole .nv.constant0.* section
 * - for each relocation with symbol name and offset%4==0: map[offset/4]=symbol
 *
 * Returns 0 on success (map may be empty). Returns -1 on parse error.
 */
int rtxdiasm_cubin_extract_texrefs(const unsigned char *cubin, size_t size,
                                   const char *entry,
                                   rtxdiasm_texref_map_t *out);

/*
 * Extract texrefs from a fatbin or cubin image (C# LoadCubinForEntry +
 * ExtractTextureRefs behavior for selection). If data is ELF cubin, parses it.
 * If data is a fatbin (wrapper/BA55ED50 blob), selects a cubin entry matching
 * entry (.text.<entry>) when possible, else first cubin.
 * Returns 0 on success, -1 if no suitable cubin/texrefs context.
 */
int rtxdiasm_image_extract_texrefs(const unsigned char *data, size_t size,
                                   const char *entry,
                                   rtxdiasm_texref_map_t *out);

/*
 * Surface refs (.surfref) are synthesized during SASS->PTX lift from surface
 * instructions (C# SassToPtx: SULD/SUST/SURED/SUQ), not stored as named
 * cubin symbols. C# naming: "__surf_{bank}_{index}" where (bank,index) are the
 * descriptor immediates of the instruction.
 */
void rtxdiasm_format_surfref_name(char *buf, size_t buf_size, int bank, int index);

#ifdef __cplusplus
}
#endif

#endif /* RTXDIASM_CUBIN_H */
