#include "rtxdiasm_cubin.h"
#include "rtxdiasm_fatbin.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    uint32_t name_off;
    uint32_t type;
    uint64_t flags;
    uint64_t addr;
    uint64_t offset;
    uint64_t size;
    uint32_t link;
    uint32_t info;
    uint64_t addralign;
    uint64_t entsize;
} shdr_t;

typedef struct {
    uint32_t name;
    uint8_t  type;
    uint8_t  other;
    uint16_t shndx;
    uint64_t value;
    uint64_t size;
} sym_t;

static uint16_t rd16(const unsigned char *p){ return (uint16_t)p[0] | ((uint16_t)p[1]<<8); }
static uint32_t rd32(const unsigned char *p){ return (uint32_t)p[0] | ((uint32_t)p[1]<<8) | ((uint32_t)p[2]<<16) | ((uint32_t)p[3]<<24); }
static uint64_t rd64(const unsigned char *p){ uint64_t lo=rd32(p), hi=rd32(p+4); return lo | (hi<<32); }

void rtxdiasm_texref_map_free(rtxdiasm_texref_map_t *map) {
    if (!map) return;
    for (size_t i = 0; i < map->count; i++) free(map->entries[i].name);
    free(map->entries);
    map->entries = NULL;
    map->count = 0;
}

void rtxdiasm_format_surfref_name(char *buf, size_t buf_size, int bank, int index) {
    if (!buf || buf_size == 0) return;
    snprintf(buf, buf_size, "__surf_%d_%d", bank, index);
}

static int is_elf(const unsigned char *d, size_t n) {
    return n >= 16 && d[0]==0x7f && d[1]=='E' && d[2]=='L' && d[3]=='F';
}

static const char *sec_name(const unsigned char *shstr, size_t shstrsz, uint32_t off) {
    if (!shstr || off >= shstrsz) return "";
    size_t max = shstrsz - off;
    size_t len = strnlen((const char*)shstr + off, max);
    if (len == max) return "";
    return (const char*)shstr + off;
}

static int parse_sections(const unsigned char *d, size_t n, int is64,
                          shdr_t **out_sh, size_t *out_n, const unsigned char **out_shstr, size_t *out_shstrsz) {
    *out_sh = NULL; *out_n = 0; *out_shstr = NULL; *out_shstrsz = 0;
    if (n < (is64 ? 64u : 52u)) return -1;
    uint64_t shoff = is64 ? rd64(d+0x28) : rd32(d+0x20);
    uint16_t shentsz = rd16(d + (is64 ? 0x3A : 0x2E));
    uint16_t shnum = rd16(d + (is64 ? 0x3C : 0x30));
    uint16_t shstrndx = rd16(d + (is64 ? 0x3E : 0x32));
    size_t minentsz = is64 ? 64u : 40u;
    if (shentsz < minentsz || shnum == 0) return -1;
    if (shoff > n || shentsz > n || (uint64_t)shnum > (n - shoff) / shentsz) return -1;
    if (shstrndx >= shnum) return -1;
    shdr_t *sh = (shdr_t*)calloc(shnum, sizeof(shdr_t));
    if (!sh) return -1;
    for (uint16_t i=0;i<shnum;i++){
        const unsigned char *p = d + (size_t)shoff + (size_t)i*shentsz;
        if (is64){
            sh[i].name_off=p?rd32(p):0; sh[i].type=rd32(p+4); sh[i].flags=rd64(p+8);
            sh[i].addr=rd64(p+16); sh[i].offset=rd64(p+24); sh[i].size=rd64(p+32);
            sh[i].link=rd32(p+40); sh[i].info=rd32(p+44); sh[i].addralign=rd64(p+48); sh[i].entsize=rd64(p+56);
        } else {
            sh[i].name_off=rd32(p); sh[i].type=rd32(p+4); sh[i].flags=rd32(p+8);
            sh[i].addr=rd32(p+12); sh[i].offset=rd32(p+16); sh[i].size=rd32(p+20);
            sh[i].link=rd32(p+24); sh[i].info=rd32(p+28); sh[i].addralign=rd32(p+32); sh[i].entsize=rd32(p+36);
        }
    }
    if (sh[shstrndx].offset > n || sh[shstrndx].size > n - sh[shstrndx].offset) { free(sh); return -1; }
    *out_sh = sh; *out_n = shnum;
    *out_shstr = d + (size_t)sh[shstrndx].offset; *out_shstrsz = (size_t)sh[shstrndx].size;
    return 0;
}

static int read_symbols(const unsigned char *d, size_t n, int is64,
                        const shdr_t *sh, size_t shn,
                        const unsigned char *shstr, size_t shstrsz,
                        sym_t **out_syms, size_t *out_nsyms, char ***out_symnames) {
    *out_syms=NULL; *out_nsyms=0; *out_symnames=NULL;
    size_t si = (size_t)-1;
    for (size_t i=0;i<shn;i++){
        const char *nm = sec_name(shstr, shstrsz, sh[i].name_off);
        if (sh[i].type == 2 /*SHT_SYMTAB*/ || (sh[i].type == 11 && strcmp(nm, ".symtab")==0)) { si=i; break; }
    }
    if (si==(size_t)-1){
        for (size_t i=0;i<shn;i++) if (sh[i].type==2){ si=i; break; }
    }
    if (si==(size_t)-1) return 0; /* no symbols */
    size_t entsz = (size_t)sh[si].entsize;
    if (entsz == 0) entsz = is64 ? 24u : 16u;
    if (sh[si].offset > n || sh[si].size > n - sh[si].offset) return -1;
    size_t count = (size_t)(sh[si].size / entsz);
    if (sh[si].link >= shn) return -1;
    const unsigned char *strsec = d + (size_t)sh[sh[si].link].offset;
    size_t strsz = (size_t)sh[sh[si].link].size;
    if (sh[sh[si].link].offset > n || strsz > n - sh[sh[si].link].offset) return -1;
    sym_t *syms = (sym_t*)calloc(count ? count : 1, sizeof(sym_t));
    char **names = (char**)calloc(count ? count : 1, sizeof(char*));
    if (!syms || !names){ free(syms); free(names); return -1; }
    for (size_t i=0;i<count;i++){
        const unsigned char *p = d + (size_t)sh[si].offset + i*entsz;
        uint32_t name_off;
        if (is64){
            name_off = rd32(p); syms[i].type = p[4] & 0xf; syms[i].other = p[5]; syms[i].shndx = rd16(p+6);
            syms[i].value = rd64(p+8); syms[i].size = rd64(p+16);
        } else {
            name_off = rd32(p); syms[i].value = rd32(p+4); syms[i].size = rd32(p+8);
            syms[i].type = p[12] & 0xf; syms[i].other = p[13]; syms[i].shndx = rd16(p+14);
        }
        if (name_off < strsz){
            size_t max = strsz - name_off;
            size_t len = strnlen((const char*)strsec + name_off, max);
            if (len < max){
                names[i] = (char*)malloc(len+1);
                if (names[i]) memcpy(names[i], (const char*)strsec + name_off, len+1);
            }
        }
        if (!names[i]) { names[i] = (char*)calloc(1,1); if(!names[i]){ /*oom*/ }
        }
    }
    *out_syms=syms; *out_nsyms=count; *out_symnames=names; return 0;
}

static int add_texref(rtxdiasm_texref_map_t *map, int idx, const char *name){
    if (!name || !*name) return 0;
    rtxdiasm_texref_entry_t *ne = (rtxdiasm_texref_entry_t*)realloc(map->entries, (map->count+1)*sizeof(*ne));
    if (!ne) return -1;
    map->entries = ne;
    ne[map->count].descriptor_index = idx;
    ne[map->count].name = (char*)malloc(strlen(name)+1);
    if (!ne[map->count].name) return -1;
    strcpy(ne[map->count].name, name);
    map->count++;
    return 0;
}

int rtxdiasm_cubin_extract_texrefs(const unsigned char *cubin, size_t size,
                                   const char *entry,
                                   rtxdiasm_texref_map_t *out) {
    if (!out) return -1;
    out->entries = NULL; out->count = 0;
    if (!is_elf(cubin, size)) return -1;
    int is64 = cubin[4] == 2;
    if (cubin[5] != 1) return -1; /* little endian only */
    shdr_t *sh=NULL; size_t shn=0; const unsigned char *shstr=NULL; size_t shstrsz=0;
    if (parse_sections(cubin,size,is64,&sh,&shn,&shstr,&shstrsz)!=0) return -1;

    sym_t *syms=NULL; size_t nsyms=0; char **symnames=NULL;
    int have_syms = (read_symbols(cubin,size,is64,sh,shn,shstr,shstrsz,&syms,&nsyms,&symnames)==0);

    /* choose target .nv.constant0 section index */
    size_t target = (size_t)-1;
    char want[256]; want[0]=0;
    if (entry && *entry) snprintf(want,sizeof(want), ".nv.constant0.%s", entry);
    if (want[0]){
        for (size_t i=0;i<shn;i++) if (strcmp(sec_name(shstr,shstrsz,sh[i].name_off), want)==0){ target=i; break; }
    }
    if (target==(size_t)-1){
        for (size_t i=0;i<shn;i++) if (strcmp(sec_name(shstr,shstrsz,sh[i].name_off), ".nv.constant0")==0){ target=i; break; }
    }
    if (target==(size_t)-1){
        size_t found = (size_t)-1; int count=0;
        for (size_t i=0;i<shn;i++){
            const char *nm = sec_name(shstr,shstrsz,sh[i].name_off);
            if (strncmp(nm, ".nv.constant0.", 14)==0){ found=i; count++; }
        }
        if (count==1) target=found;
    }

    if (target!=(size_t)-1 && have_syms){
        /* find relocation sections whose info points to target */
        for (size_t i=0;i<shn;i++){
            int is_rela = (sh[i].type==4);
            int is_rel = (sh[i].type==9);
            if ((!is_rela && !is_rel) || sh[i].size==0) continue;
            if ((size_t)sh[i].info != target) continue;
            if (sh[i].offset > size || sh[i].size > size - sh[i].offset) continue;
            size_t minsz = is64 ? (is_rela?24u:16u) : (is_rela?12u:8u);
            size_t entsz = (size_t)sh[i].entsize; if (entsz==0) entsz=minsz; if (entsz < minsz) continue;
            size_t rcount = (size_t)(sh[i].size / entsz);
            for (size_t r=0;r<rcount;r++){
                const unsigned char *p = cubin + (size_t)sh[i].offset + r*entsz;
                uint64_t roff; uint64_t rinfo; uint32_t symidx;
                if (is64){ roff=rd64(p); rinfo=rd64(p+8); symidx=(uint32_t)(rinfo>>32); }
                else { roff=rd32(p); rinfo=rd32(p+4); symidx=(uint32_t)(rinfo>>8); }
                if (roff % 4 != 0) continue;
                if (symidx >= nsyms) continue;
                const char *sname = symnames[symidx] ? symnames[symidx] : "";
                if (!*sname) continue;
                /* C#: include if symbol name present and offset%4==0 (texture refs in constant0) */
                if (add_texref(out, (int)(roff/4), sname) != 0) {
                    /* oom -> cleanup and fail */
                    for (size_t k=0;k<nsyms;k++) free(symnames[k]);
                    free(symnames); free(syms); free(sh);
                    rtxdiasm_texref_map_free(out);
                    return -1;
                }
            }
        }
    }

    if (have_syms){
        for (size_t k=0;k<nsyms;k++) free(symnames[k]);
        free(symnames); free(syms);
    }
    free(sh);
    return 0;
}

static int is_fatbin_wrapper(const unsigned char *d, size_t n){ return n>=8 && rd32(d)==0x466243B1u; }

int rtxdiasm_image_extract_texrefs(const unsigned char *data, size_t size,
                                   const char *entry,
                                   rtxdiasm_texref_map_t *out) {
    if (!out) return -1;
    out->entries=NULL; out->count=0;
    if (!data || size < 16) return -1;
    if (is_elf(data,size)) return rtxdiasm_cubin_extract_texrefs(data,size,entry,out);

    /* Fatbin data blob (BA55ED50): try to find cubin (kind==2) entries */
    if (rd32(data)==0xBA55ED50u && rd16(data+4)==1) {
        uint64_t files_size = rd64(data+8);
        if (files_size <= (uint64_t)512<<20){
            size_t pos=16, end = pos + (size_t)files_size;
            if (end <= size){
                /* TODO: full scan/select by entry; for now try cubins in order */
                while (pos + 64 <= end){
                    const unsigned char *e = data+pos;
                    uint16_t kind = rd16(e);
                    uint32_t header_size = rd32(e+4);
                    uint32_t payload_size = rd32(e+8);
                    uint32_t compressed_size = rd32(e+16);
                    if (header_size < 64 || header_size > 4096) break;
                    size_t pay = pos + header_size;
                    size_t disk = payload_size > compressed_size ? payload_size : compressed_size;
                    if (pay > end || disk > end-pay) break;
                    if (kind == 2 /*ELF cubin*/ && disk>0){
                        /* only uncompressed cubins handled here for texrefs; compressed would need decompress */
                        uint64_t flags = rd64(e+40);
                        if (!(flags & (0x2000ull|0x8000ull))){
                            if (rtxdiasm_cubin_extract_texrefs(data+pay, disk, entry, out)==0 && out->count>0) return 0;
                            rtxdiasm_texref_map_free(out);
                        }
                    }
                    size_t step = header_size + disk; if (!step) break; pos += step;
                }
            }
        }
        return -1;
    }

    /* Wrapper 0x466243B1: ver1 points to data blob */
    if (is_fatbin_wrapper(data,size)){
        uint32_t ver = rd32(data+4);
        if (ver==1 && size >= 16){
            const unsigned char *blob = NULL;
            memcpy(&blob, data+8, sizeof(blob));
            if (blob){
                /* cannot know blob size safely from pointer alone; best-effort if it looks like BA55ED50 header nearby */
                if (rd32(blob)==0xBA55ED50u){
                    uint64_t files_size = rd64(blob+8);
                    if (files_size <= (uint64_t)512<<20)
                        return rtxdiasm_image_extract_texrefs(blob, 16 + (size_t)files_size, entry, out);
                }
            }
        }
        /* ver2 array of subwrappers not fully handled */
    }
    return -1;
}
