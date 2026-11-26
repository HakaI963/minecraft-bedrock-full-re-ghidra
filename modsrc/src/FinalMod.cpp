#include <pl/Mod.hpp>
#include <pl/Logger.hpp>
#include <android/log.h>
#include "offsets.h"
#include "build_id.h"
#include "embedded_assets.h"
#include <atomic>
#include <mutex>
#include <unordered_set>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <thread>
#include <string>
#include <string_view>
#include <vector>
#include <link.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <dlfcn.h>
#include "shadowhook.h"

#include "creative_inventory_api/CreativeInventoryAPI.hpp"

using namespace creative_inventory_api;

static void diagNote(const char* line);   // defined below (diag logger)

// ---- 3-tier hook helper: hook attachment CANNOT fail ------------------------
// Tier 1: ShadowHook in SHARED mode (coexists with LeviLauncher's preloader;
//        UNIQUE mode's sh_linker_init() is blocked by Android 16 Bionic ->
//        errno=12). Tier 2: LeviLauncher PreLoader pl_hook via runtime dlopen/
//        dlsym (no link-time _ZN2pl symbols). Tier 3: direct ARM64 inline
//        trampoline (all 11 targets verified PC-rel-free in their first 4
//        instructions, so the prologue can be safely relocated).
enum HookTier { TIER_NONE=0, TIER_SHARED=1, TIER_PRELOADER=2, TIER_TRAMPOLINE=3 };
struct HookRecord {
    void* handle; void* target; void* detour; void* trampoline;
    int tier; unsigned char saved[16];
};
static HookRecord gHookRecords[16];
static int gHookRecordCount=0;
static int gTierCounts[4]={0,0,0,0};

// Tier 2 — exact symbols confirmed from LegacyHook.h in the workspace:
//  extern "C" int pl_hook(PLFuncPtr, PLFuncPtr, PLFuncPtr*, PLHookPriority);
//  extern "C" bool pl_unhook(PLFuncPtr, PLFuncPtr);   (0 = success)
typedef int  (*PLHookFn)(void*,void*,void**,int);
typedef bool (*PLUnhookFn)(void*,void*);
static PLHookFn gPLHook=nullptr;
static PLUnhookFn gPLUnhook=nullptr;
static bool gPLHookResolved=false;
static void resolvePreLoaderHook(){
    if(gPLHookResolved) return;
    gPLHookResolved=true;
    void* h=dlopen("libpreloader.so",RTLD_NOLOAD|RTLD_NOW);
    if(!h) h=RTLD_DEFAULT;              // already in the process symbol table
    const char* hookNames[]={
        "pl_hook",                                          // unmangled (workspace SDK)
        "_ZN2pl4hook7pl_hookEPvS1_PS1_NS0_8PriorityE",      // C++ mangled variant
        "_ZN2pl6memory4hookEPvS1_PS1_NS0_12HookPriorityE"   // pl::memory::hook
    };
    for(const char* n:hookNames){ gPLHook=(PLHookFn)dlsym(h,n); if(gPLHook) break; }
    const char* unhookNames[]={
        "pl_unhook",
        "_ZN2pl4hook9pl_unhookEPvS1_S1_",
        "_ZN2pl6memory7unhookEPvS1_S1_"
    };
    for(const char* n:unhookNames){ gPLUnhook=(PLUnhookFn)dlsym(h,n); if(gPLUnhook) break; }
    if(gPLHook) __android_log_print(ANDROID_LOG_INFO,"BlueCube","PreLoader hook resolved via dlopen/dlsym");
}

// Tier 3 — detect PC-relative instructions that cannot be relocated with the
// 16-byte prologue (B/BL/ADR/ADRP/LDR-literal/CBZ/TBZ/B.cond).
static bool pcRelativeInsn(uint32_t i){
    if((i&0xFC000000u)==0x14000000u) return true;   // B
    if((i&0xFC000000u)==0x94000000u) return true;   // BL
    if((i&0x9F000000u)==0x10000000u) return true;   // ADR
    if((i&0x9F000000u)==0x90000000u) return true;   // ADRP
    if((i&0x3B000000u)==0x18000000u) return true;   // LDR/PRFM literal
    if((i&0x7E000000u)==0x34000000u) return true;   // CBZ / CBNZ
    if((i&0x7E000000u)==0x36000000u) return true;   // TBZ / TBNZ
    if((i&0xFF000010u)==0x54000000u) return true;   // B.cond
    return false;
}
// LDR X16, #8 ; BR X16 ; .quad target  — 16 bytes, PC-relative-free branch.
struct BranchStub { uint32_t ldr; uint32_t br; uint64_t addr; };
static void emitBranch(void* at,void* where){
    BranchStub s;
    s.ldr=0x58000050u;   // LDR X16, #8
    s.br =0xD61F0200u;   // BR X16
    s.addr=(uint64_t)where;
    std::memcpy(at,&s,sizeof(s));
    __builtin___clear_cache((char*)at,(char*)at+16);
}
static void* installInlineTrampoline(void* target,void* detour,void** outOrig,
                                     unsigned char saved[16]){
    const uint32_t* ins=(const uint32_t*)target;
    for(int i=0;i<4;i++) if(pcRelativeInsn(ins[i])){
        __android_log_print(ANDROID_LOG_INFO,"BlueCube","tier3 rejected @0x%llx: PC-relative insn %d",
                            (unsigned long long)target,i);
        return nullptr;
    }
    void* page=mmap(nullptr,4096,PROT_READ|PROT_WRITE|PROT_EXEC,
                    MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    if(page==MAP_FAILED) return nullptr;
    unsigned char* tr=(unsigned char*)page;
    std::memcpy(saved,target,16);                 // backup before patching
    std::memcpy(tr,saved,16);                     // relocated original prologue
    emitBranch(tr+16,(unsigned char*)target+16);  // ... then back to target+16
    __builtin___clear_cache((char*)tr,(char*)tr+32);
    *outOrig=tr;                                  // orig() calls relocated prologue
    uintptr_t pg=(uintptr_t)target & ~(uintptr_t)4095;
    mprotect((void*)pg,4096,PROT_READ|PROT_WRITE|PROT_EXEC);
    emitBranch(target,detour);                    // patch the real function
    __android_log_print(ANDROID_LOG_INFO,"BlueCube","tier3 inline hook @0x%llx -> 0x%llx orig=0x%llx",
                        (unsigned long long)target,(unsigned long long)detour,(unsigned long long)tr);
    return (void*)0x1;                            // synthetic handle
}

static void* bcHook(void* target,void* detour,void** orig){
    if(!target||!detour) return nullptr;
    void* handle=nullptr; int tier=TIER_NONE;
    unsigned char saved[16]={0};
    void* trampoline=nullptr;
    // ---- Tier 1: ShadowHook SHARED mode ----
    handle=shadowhook_hook_func_addr(target,detour,orig);
    if(handle) tier=TIER_SHARED;
    // ---- Tier 2: LeviLauncher PreLoader (runtime dlsym only) ----
    if(!handle){
        resolvePreLoaderHook();
        if(gPLHook){
            int rc=gPLHook(target,detour,orig,0);   // priority 0 = Highest
            if(rc==0){ handle=target; tier=TIER_PRELOADER; }  // synthetic handle
            else __android_log_print(ANDROID_LOG_INFO,"BlueCube","PreLoader pl_hook failed rc=%d",rc);
        }
    }
    // ---- Tier 3: direct ARM64 inline trampoline ----
    if(!handle){
        void* ignored=nullptr;
        void** op=orig?orig:&ignored;
        handle=installInlineTrampoline(target,detour,op,saved);
        if(handle){ tier=TIER_TRAMPOLINE; trampoline=*op; }
    }
    if(handle){
        if(gHookRecordCount<16){
            HookRecord& r=gHookRecords[gHookRecordCount++];
            r.handle=handle; r.target=target; r.detour=detour;
            r.trampoline=trampoline; r.tier=tier;
            std::memcpy(r.saved,saved,16);
        }
        gTierCounts[tier]++;
    }
    return handle;
}
// Dispatch unhook to the tier that installed it.
static void bcUnhook(void* handle){
    if(!handle) return;
    for(int i=0;i<gHookRecordCount;i++){
        HookRecord& r=gHookRecords[i];
        if(r.handle!=handle) continue;
        if(r.tier==TIER_SHARED) shadowhook_unhook(handle);
        else if(r.tier==TIER_PRELOADER){ if(gPLUnhook) gPLUnhook(r.target,r.detour); }
        else if(r.tier==TIER_TRAMPOLINE){
            uintptr_t pg=(uintptr_t)r.target & ~(uintptr_t)4095;
            mprotect((void*)pg,4096,PROT_READ|PROT_WRITE|PROT_EXEC);
            std::memcpy(r.target,r.saved,16);
            __builtin___clear_cache((char*)r.target,(char*)r.target+16);
            if(r.trampoline) munmap(r.trampoline,4096);
        }
        r.handle=nullptr;
        return;
    }
    shadowhook_unhook(handle);   // unknown handle: legacy shadowhook stub
}

// ---- fake SBO std::function shell for the recipe factory (x7) --------------
// At 0x1040f920..0x1040f934 the wrapper invokes the inline factory with
// x0=this(factory), x1=&requirement (out), and vt[3](+24). NOTE: x8 is reloaded
// with the function address at 0x1040f928 before `blr x8`, so the out pointer
// is x1 — NOT x8. Our stub zeroes the 64-byte RecipeUnlockingRequirement via
// [x1]; requirement+32 becomes 0 so 0x1040ef38 self-initializes AlwaysUnlocked.
extern "C" __attribute__((naked, used)) void fakeReqInvokeStub(){
    asm volatile(
        "stp xzr, xzr, [x1, #0]\n"
        "stp xzr, xzr, [x1, #16]\n"
        "stp xzr, xzr, [x1, #32]\n"
        "stp xzr, xzr, [x1, #48]\n"
        "ret\n"
    );
}
extern "C" __attribute__((used)) void fakeReqNoopStub(void*){}

static uintptr_t gBase=0;
static pl::log::Logger* gLog=nullptr;
static void* gModInstance=nullptr; // global instance accessible from free detours
static void* gBlueCubeItem=nullptr; // mirror of FinalMod::gItem for free functions
static void (*gResetForNewWorld)()=nullptr; // set by FinalMod::load for loader detour
static size_t gModuleSize=0;
static int find_base(struct dl_phdr_info* i,size_t,void*){
    const char* n=i->dlpi_name?i->dlpi_name:"";
    if(strstr(n,"libminecraftpe.so")){
        gBase=(uintptr_t)i->dlpi_addr;
        for(ElfW(Half) p=0;p<i->dlpi_phnum;++p)
            if(i->dlpi_phdr[p].p_type==PT_LOAD)
                gModuleSize=std::max(gModuleSize,(size_t)i->dlpi_phdr[p].p_vaddr+
                                                 (size_t)i->dlpi_phdr[p].p_memsz);
    }
    return 0;
}

// ---- wildcard instruction-byte signature scanner -------------------------
// Scans libminecraftpe.so's own mapped image (no external tools). Patterns are
// hex byte strings; "??" is a fully-wildcard byte. A signature must match
// EXACTLY once inside the module or the verified RVA in offsets.h is used.
static bool parseSig(const char* hex,std::vector<uint8_t>& out,std::vector<uint8_t>& mask){
    out.clear(); mask.clear();
    const char* p=hex;
    while(*p){
        while(*p==' ') ++p;
        if(!*p) break;
        if(p[0]=='?'&&p[1]=='?'){ out.push_back(0); mask.push_back(0); p+=2; }
        else {
            if(p[1]=='\0') return false;
            auto nib=[](char c)->int{ return c>='0'&&c<='9'?c-'0':(c>='a'&&c<='f'?c-'a'+10:(c>='A'&&c<='F'?c-'A'+10:-1)); };
            int h=nib(p[0]),l=nib(p[1]); if(h<0||l<0) return false;
            out.push_back((uint8_t)((h<<4)|l)); mask.push_back(1); p+=2;
        }
    }
    return !out.empty();
}
// Exact mapped r-x ranges of libminecraftpe.so parsed from /proc/self/maps.
// The module has split executable mappings and guard (---) / unmapped holes;
// scanning the computed module size would read the guard page and SIGSEGV.
struct RxRange { uintptr_t start, end; };
static RxRange gRx[16]; static int gRxCount=0;
static void collectRxRanges(){
    gRxCount=0;
    FILE* f=fopen("/proc/self/maps","r");
    if(!f) return;
    char line[512];
    while(fgets(line,sizeof(line),f)){
        // format: "start-end perms offset dev inode path"
        unsigned long start=0,end=0;
        if(sscanf(line,"%lx-%lx",&start,&end)!=2) continue;
        const char* perms=strchr(line,' ');
        if(!perms || perms >= line+sizeof(line)) continue;
        ++perms;
        // require readable AND executable, not writable (r-x)
        if(perms[0]!='r' || perms[2]!='x') continue;
        // path must be libminecraftpe.so (last field)
        const char* path=strstr(line,"libminecraftpe.so");
        if(!path) continue;
        if(gRxCount<16 && end>start){
            gRx[gRxCount].start=(uintptr_t)start;
            gRx[gRxCount].end=(uintptr_t)end;
            ++gRxCount;
        }
    }
    fclose(f);
    __android_log_print(ANDROID_LOG_INFO,"BlueCube","r-x ranges parsed: %d",gRxCount);
    for(int i=0;i<gRxCount;i++)
        __android_log_print(ANDROID_LOG_INFO,"BlueCube","  r-x[%d]=0x%llx-0x%llx",i,
            (unsigned long long)gRx[i].start,(unsigned long long)gRx[i].end);
}
// Validate that a [ptr, ptr+len) read lies wholly inside a mapped readable
// range of libminecraftpe.so (used before dereferencing game pointers in the
// diagnostic walkers, so a bogus pointer can never fault in a guard page).
// Cached readable ranges of libminecraftpe.so — parsed ONCE at load so the
// world thread's pointer guards never repeatedly scan a large maps file.
static RxRange gReadable[64]; static int gReadableCount=0;
static void collectReadableRanges(){
    gReadableCount=0;
    FILE* f=fopen("/proc/self/maps","r");
    if(!f) return;
    char line[512];
    while(fgets(line,sizeof(line),f)){
        unsigned long start=0,end=0;
        if(sscanf(line,"%lx-%lx",&start,&end)!=2) continue;
        const char* perms=strchr(line,' ');
        if(!perms) continue; ++perms;
        if(perms[0]!='r' || end<=start) continue;     // any readable mapping
        if(!strstr(line,"libminecraftpe.so")) continue;
        if(gReadableCount<64){ gReadable[gReadableCount].start=(uintptr_t)start;
                               gReadable[gReadableCount].end=(uintptr_t)end; ++gReadableCount; }
    }
    fclose(f);
    __android_log_print(ANDROID_LOG_INFO,"BlueCube","readable ranges cached: %d",gReadableCount);
}
static bool readableInGame(uintptr_t ptr,size_t len){
    if(ptr==0) return false;
    for(int i=0;i<gReadableCount;i++){
        uintptr_t s=gReadable[i].start,e=gReadable[i].end;
        if(ptr>=s && ptr+len<=e && ptr+len>ptr) return true;  // overflow-safe
    }
    return false;
}
// Heap-aware readable check for the RECIPE DIAGNOSTIC walkers only. The game's
// Recipes/Recipe/vector/node objects all live on the heap (Scudo), NOT inside
// libminecraftpe.so, so readableInGame() (module-only) rejected every one of
// them — that is why findRecipes always returned found=0 and the side-by-side
// dump was all zeros. Two fixes here:
//   1. Cache ALL readable mappings (heap included), refreshed on demand so
//      allocations made after mod load are covered.
//   2. Strip the ARM64 MTE/TBI top-byte tag (e.g. 0xb400007c... -> 0x7c...)
//      before range comparison; /proc/self/maps lists untagged addresses.
// This is deliberately SEPARATE from readableInGame so the BlockGraphics guard
// (which must keep skipping heap Block* to avoid the world-entry fault) is
// unchanged.
static RxRange gReadableMem[16384]; static int gReadableMemCount=0;
static int rxRangeCmp(const void* a,const void* b){
    uintptr_t sa=((const RxRange*)a)->start, sb=((const RxRange*)b)->start;
    return (sa>sb)-(sa<sb);
}
static void collectReadableMem(){
    gReadableMemCount=0;
    FILE* f=fopen("/proc/self/maps","r");
    if(!f) return;
    char line[512];
    while(fgets(line,sizeof(line),f)){
        unsigned long start=0,end=0;
        if(sscanf(line,"%lx-%lx",&start,&end)!=2) continue;
        const char* perms=strchr(line,' ');
        if(!perms) continue; ++perms;
        if(perms[0]!='r' || end<=start) continue;   // any readable mapping
        if(gReadableMemCount<16384){
            gReadableMem[gReadableMemCount].start=(uintptr_t)start;
            gReadableMem[gReadableMemCount].end=(uintptr_t)end;
            ++gReadableMemCount;
        }
    }
    fclose(f);
    // Sort by start so readableMem can binary-search. /proc/self/maps is already
    // address-sorted, but sort explicitly to guarantee the invariant.
    if(gReadableMemCount>1)
        qsort(gReadableMem,(size_t)gReadableMemCount,sizeof(RxRange),rxRangeCmp);
}
static bool readableMem(uintptr_t ptr,size_t len){
    if(ptr==0 || len==0) return false;
    ptr &= 0x00FFFFFFFFFFFFFFULL;                  // strip MTE/TBI top-byte tag
    // O(log n) binary search over the sorted, disjoint ranges: find the last
    // range with start<=ptr (the only candidate), then test full containment.
    // The previous O(n) linear scan over ~7700 ranges, run for ~10k recipe
    // pointers per findRecipes call, hung world load ("infinite loading").
    int lo=0,hi=gReadableMemCount-1,idx=-1;
    while(lo<=hi){
        int mid=lo+(hi-lo)/2;
        if(gReadableMem[mid].start<=ptr){ idx=mid; lo=mid+1; }
        else hi=mid-1;
    }
    if(idx<0) return false;
    uintptr_t e=gReadableMem[idx].end;
    return ptr+len<=e && ptr+len>ptr;              // overflow-safe
}
static uintptr_t scanUnique(const char* hex,const char* name){
    std::vector<uint8_t> pat,msk;
    if(!parseSig(hex,pat,msk)) return 0;
    if(pat.empty() || msk.size()!=pat.size() || gRxCount==0) return 0;
    uintptr_t found=0; int hits=0;
    // Scan ONLY within each mapped r-x range. Every loop is clamped so no
    // pattern read can cross seg_end into a guard page (---) or unmapped hole.
    for(int s=0;s<gRxCount;s++){
        const uintptr_t seg_start=gRx[s].start, seg_end=gRx[s].end;
        // Explicit guards: valid interval, non-empty pattern, fits in segment.
        if(seg_end<=seg_start || pat.empty() || (size_t)(seg_end-seg_start)<pat.size()) continue;
        const uint8_t* last_start=(const uint8_t*)(seg_end-pat.size());  // inclusive
        for(const uint8_t* p=(const uint8_t*)seg_start; p<=last_start; ++p){
            bool ok=true;
            for(size_t i=0;i<pat.size();++i){
                // Never read p[i] beyond seg_end-1.
                if(msk[i] && ((p+i)>=(const uint8_t*)seg_end || p[i]!=pat[i])){
                    ok=false; break;
                }
            }
            if(ok){
                ++hits; found=(uintptr_t)p;
                if(hits>1) break;
            }
        }
        if(hits>1) break;
    }
    if(hits==1){
        if(gLog) gLog->info("SIG {}: 0x{:x} (unique)",name,(unsigned long)found);
        __android_log_print(ANDROID_LOG_INFO,"BlueCube","SIG %s -> 0x%llx (unique)",
                            name,(unsigned long long)found);
        return found;
    }
    if(gLog) gLog->warn("SIG {}: {} hits, using RVA",name,hits);
    __android_log_print(ANDROID_LOG_WARN,"BlueCube","SIG %s -> %d hits, RVA fallback",name,hits);
    return 0;
}
// Resolved native backend functions. NO RVA FALLBACK: every pointer below is
// set ONLY from a wildcard instruction-byte signature that matched exactly once
// in a mapped r-x range. On a miss we log "SIG FAILED", bump gSigFailCount and
// leave the pointer null. Data/vtable addresses are NOT here: they live in
// .data.rel.ro (unexecutable) and are documented in offsets.h as off::DATA_*.
static uintptr_t pRegisterBlock=0,pBlockItemCtor=0,pBlockTypeCtor=0,pMaterialGet=0,
                 pHashedCtor=0,pHashedGetStr=0,pRegisterItemWrapper=0,pItemGetId=0,
                 pI18nGet=0,pI18nGetParams=0,pBuildDescName=0,pBlockLegacyDesc=0,
                 pBlockGraphicsGet=0,pItemInstCtor=0,pItemInstCopy=0,
                 pItemInstInit=0,pCreativeAddItem=0,pCreativeGroupCtor=0,pCreativeFinalize=0,
                 pShapedRecipeCtor=0,pAddRecipe=0,pAddShapedWrapper=0,pAddShapedRecipe=0,
                 pStringInit=0,pNetIdNext=0,pBlocksLoader=0,pTerrainLoader=0,
                 pJsonParseCStr=0,pJsonParseStr=0,pScreenCreator=0,pStrAssign=0,
                 pAssetOpen=0,pAssetRead=0,pAssetLen=0,pAssetLen64=0,pAssetSeek64=0,pAssetClose=0,
                 pSetCreativeCategory=0,pDescCtor=0,pTagCopy=0;
static int gSigFailCount=0;
static void resolveNativeBackend(){
    // All signatures are generated at EXACT function entry (adj 0) by
    // gen_signatures.py, except REGISTER_BLOCK: its entry has no unique pattern
    // (42 hits even at 64 words), so the verified mid-function pattern below
    // (unique at 0x989ef80) keeps its proven adj=-0x60 to reach 0x989ef20.
    // No RVA is ever substituted when a scan fails.
    struct S{ uintptr_t* dst; const char* name; const char* sig; intptr_t adj; } tbl[]={
      {&pRegisterBlock,"REGISTER_BLOCK",
       "00 75 80 52 ?? ?? ?? 95 f3 03 00 aa c2 02 40 b9 a1 c3 00 d1 e3 03 15 aa fd 07 c2 95 89 a2 53 a9",-0x60},
      {&pBlockTypeCtor,"BLOCKTYPE_CTOR",
       "ff 03 04 d1 fd 7b 0a a9 fc 6f 0b a9 fa 67 0c a9 f8 5f 0d a9 f6 57 0e a9 f4 4f 0f a9 fd 83 02 91 5a d0 3b d5 00 e4 00 6f",0},
      {&pBlockItemCtor,"BLOCKITEM_CTOR",
       "ff 83 01 d1 fd 7b 03 a9 f6 57 04 a9 f4 4f 05 a9 fd c3 00 91 56 d0 3b d5 f4 03 03 aa f5 03 01 aa c8 16 40 f9 f3 03 00 aa a8 83 1f f8 ?? ?? ?? ?? ?? ?? ?? ?? 08 41 19 91 e0 03 13 aa 68 02 00 f9",0},
      {&pMaterialGet,"MATERIAL_GET",
       "?? ?? ?? ?? 08 f1 10 91 00 05 20 8b c0 03 5f d6 2c 28 41 29 28 00 40 f9 8b 05 00 11 09 01 40 f9 68 01 0a 0b 2d 59 68 78",0},
      {&pHashedCtor,"HASHED_CTOR",
       "fd 7b bd a9 f5 0b 00 f9 f4 4f 02 a9 fd 03 00 91 f3 03 00 aa 1f 84 00 f8 28 00 40 39 ?? ?? ?? ?? 28 08 40 f9 20 00 c0 3d",0},
      {&pHashedGetStr,"HASHED_GETSTR",
       "00 20 00 91 c0 03 5f d6 08 20 40 39 09 0c 40 f9 0a 24 00 91 1f 01 00 72 40 01 89 9a c0 03 5f d6 ff 83 00 d1 fd 7b 01 a9",0},
      {&pRegisterItemWrapper,"REGISTER_ITEM_WRAPPER",
       "ff 03 01 d1 fd 7b 01 a9 f6 57 02 a9 f4 4f 03 a9 fd 43 00 91 55 d0 3b d5 f3 03 08 aa f4 03 01 aa a8 16 40 f9 e1 03 02 aa",0},
      {&pItemGetId,"ITEM_GET_ID",
       "00 14 41 79 c0 03 5f d6 ff 83 01 d1 fd 7b 02 a9 f8 5f 03 a9 f6 57 04 a9 f4 4f 05 a9 fd 83 00 91 58 d0 3b d5 f5 03 01 aa",0},
      {&pI18nGet,"I18N_GET",
       "fd 7b bc a9 fc 5f 01 a9 f6 57 02 a9 f4 4f 03 a9 fd 03 00 91 ff 03 15 d1 56 d0 3b d5 f3 03 08 aa f4 03 01 aa c8 16 40 f9",0},
      {&pI18nGetParams,"I18N_GET_PARAMS",
       "ff 83 06 d1 fd 7b 14 a9 fc 6f 15 a9 fa 67 16 a9 f8 5f 17 a9 f6 57 18 a9 f4 4f 19 a9 fd 03 05 91 5b d0 3b d5 f3 03 08 aa 18 60 00 91 68 17 40 f9",0},
      {&pBuildDescName,"BUILD_DESC_NAME",
       "ff 83 03 d1 fd 7b 09 a9 f9 53 00 f9 f8 5f 0b a9 f6 57 0c a9 f4 4f 0d a9 fd 43 02 91 57 d0 3b d5 f6 03 00 aa e0 03 01 aa",0},
      {&pBlockLegacyDesc,"BLOCKLEGACY_DESC",
       "fd 7b bb a9 f9 0b 00 f9 f8 5f 02 a9 f6 57 03 a9 f4 4f 04 a9 fd 03 00 91 18 20 40 39 f6 03 08 aa 08 08 40 f9 f5 03 00 aa",0},
      {&pAddShapedWrapper,"ADD_SHAPED_WRAPPER",
       "ff 03 06 d1 fd 7b 12 a9 fc 6f 13 a9 fa 67 14 a9 f8 5f 15 a9 f6 57 16 a9 f4 4f 17 a9 fd 83 04 91 5b d0 3b d5 f8 03 07 aa",0},
      {&pAddShapedRecipe,"ADD_SHAPED_RECIPE",
       "ff c3 07 d1 fd 7b 19 a9 fc 6f 1a a9 fa 67 1b a9 f8 5f 1c a9 f6 57 1d a9 f4 4f 1e a9 fd 43 06 91 e7 1f 00 f9 e6 6f 00 b9",0},
      {&pBlocksLoader,"FN_BLOCKS_LOADER",
       "ff 43 04 d1 ea 5b 00 fd e9 23 0c 6d fd 7b 0d a9 f8 5f 0e a9 f6 57 0f a9 f4 4f 10 a9 fd 43 03 91 57 d0 3b d5 f4 03 01 aa",0},
      {&pTerrainLoader,"FN_TERRAIN_LOADER",
       "ff 43 05 d1 fd 7b 11 a9 fc 93 00 f9 f6 57 13 a9 f4 4f 14 a9 fd 43 04 91 55 d0 3b d5 f3 03 01 aa f4 03 00 aa a8 16 40 f9 a8 83 1f f8 ff 7f 02 a9 ff 1b 00 f9 ?? ?? ?? ?? 21 08 0c 91 e0 e3 00 91",0},
      {&pJsonParseCStr,"JSON_PARSE_CSTR",
       "fd 7b bc a9 f7 0b 00 f9 f6 57 02 a9 f4 4f 03 a9 fd 03 00 91 f3 03 02 aa f4 03 01 aa ?? ?? ?? ?? 7f 0e 00 f1 e1 03 14 aa",0},
      {&pJsonParseStr,"JSON_PARSE_STR",
       "fd 7b bc a9 f7 0b 00 f9 f6 57 02 a9 f4 4f 03 a9 fd 03 00 91 28 00 40 39 2a a4 40 a9 f3 03 02 aa 0b fd 41 d3 1f 01 00 72",0},
      {&pAssetOpen,"ASSET_OPEN_PLT_0x13668370",
       "70 4c 00 d0 11 7a 46 f9 10 c2 33 91 20 02 1f d6",0},
      {&pAssetRead,"ASSET_READ_PLT_0x13668390",
       "70 4c 00 d0 11 82 46 f9 10 02 34 91 20 02 1f d6",0},
      {&pAssetLen,"ASSET_GETLEN_PLT_0x13668380",
       "70 4c 00 d0 11 7e 46 f9 10 e2 33 91 20 02 1f d6",0},
      {&pAssetLen64,"ASSET_GETLEN64_PLT_0x1366b1e0",
       "70 4c 00 b0 11 16 42 f9 10 a2 10 91 20 02 1f d6",0},
      {&pAssetSeek64,"ASSET_SEEK64_PLT_0x1366b200",
       "70 4c 00 b0 11 1e 42 f9 10 e2 10 91 20 02 1f d6",0},
      {&pAssetClose,"ASSET_CLOSE_PLT_0x1366b1f0",
       "70 4c 00 b0 11 1a 42 f9 10 c2 10 91 20 02 1f d6",0},
      {&pStrAssign,"STR_ASSIGN_PLT_0x136357c0",
       "50 4d 00 90 11 8e 43 f9 10 62 1c 91 20 02 1f d6",0},
      {&pScreenCreator,"SCREEN_CREATOR",
       "ff c3 02 d1 fd 7b 05 a9 fc 6f 06 a9 fa 67 07 a9 f8 5f 08 a9 f6 57 09 a9 f4 4f 0a a9 fd 43 01 91 53 d0 3b d5 fc 03 00 aa e0 03 01 aa 69 16 40 f9 f9 03 04 aa fa 03 03 aa f4 03 02 aa f5 03 01 aa f6 03 08 aa a9 83 1f f8 bb 00 40 f9 ?? ?? ?? ?? 08 00 40 f9 08 2d 40 f9 00 01 3f d6 e8 a3 00 91 e1 03 14 aa e2 03 15 aa ?? ?? ?? ?? f7 17 40 f9 ?? ?? ?? ?? e0 03 15 aa f7 5b 00 a9 f3 0b 00 f9 ?? ?? ?? ?? 08 00 40 f9 08 29 40 f9 00 01 3f d6 f7 cf 42 a9 00 1a 82 52 ?? ?? ?? ?? f6 03 00 aa",0},
      {&pNetIdNext,"NETID_NEXT",
       "?? ?? ?? ?? 09 41 47 b9 2a 05 00 31 29 09 00 11 29 21 8a 1a 09 41 07 b9 09 00 00 b9 c0 03 5f d6 ff 83 05 d1 fd 7b 12 a9",0},
      {&pAddRecipe,"ADD_RECIPE",
       "ff 43 01 d1 fd 7b 03 a9 f4 4f 04 a9 fd c3 00 91 54 d0 3b d5 88 16 40 f9 a8 83 1f f8 48 00 40 f9 ?? ?? ?? ?? 29 00 40 b9",0},
      {&pSetCreativeCategory,"SET_CREATIVE_CATEGORY",
       "01 00 05 39 c0 03 5f d6 fd 7b be a9 f3 0b 00 f9 fd 03 00 91 f3 03 00 aa 00 40 05 91 ?? ?? ?? ?? e0 03 13 aa f3 0b 40 f9",0},
      {&pDescCtor,"DESC_CTOR",
       "fd 7b bc a9 f8 5f 01 a9 f6 57 02 a9 f4 4f 03 a9 fd 03 00 91 f4 03 04 2a f3 03 00 aa ?? ?? ?? ?? 08 81 0d 91 08 7c 00 a9",0},
      {&pTagCopy,"TAG_COPY",
       "fd 7b be a9 f4 4f 01 a9 fd 03 00 91 00 e4 00 6f f3 03 01 aa f4 03 00 aa 1f 10 00 f9 21 20 00 91 00 00 00 ad 00 20 00 91",0},

      {&pItemInstCtor,"ITEM_INST_CTOR",
       "fd 7b be a9 f3 0b 00 f9 fd 03 00 91 f3 03 00 aa ?? ?? ?? ?? ?? ?? ?? ?? 08 81 10 91 68 02 00 f9 f3 0b 40 f9 fd 7b c2 a8 c0 03 5f d6 fd 7b bd a9 f5 0b 00 f9 f4 4f 02 a9 fd 03 00 91 00 e4 00 6f ?? ?? ?? ?? 08 a1 13 91 f4 03 00 aa 08 00 00 f9 f3 03 00 aa 28 20 80 52 7f 8e 00 f8 1f 7c 01 a9 1f f0 01 b8 08 30 02 78 1f 94 00 39 00 80 82 3c 00 80 83 3c 00 80 84 3c 00 80 85 3c 00 80 86 3c 1f 3c 00 f9 25 00 80 52 ?? ?? ?? ?? e0 03 14 aa ?? ?? ?? ?? f4 4f 42 a9 f5 0b 40 f9 fd 7b c3 a8",0},
      {&pItemInstCopy,"ITEM_INST_COPY",
       "fd 7b be a9 f4 4f 01 a9 fd 03 00 91 f4 03 01 aa f3 03 00 aa ?? ?? ?? ?? ?? ?? ?? ?? 08 81 10 91 68 02 00 f9 e0 03 13 aa e1 03 14 aa ?? ?? ?? ?? f4 4f 41 a9 fd 7b c2 a8 c0 03 5f d6 f4 03 00 aa e0 03 13 aa ?? ?? ?? ?? e0 03 14 aa ?? ?? ?? ?? ff 43 01 d1 fd 7b 01 a9 f7 13 00 f9 f6 57 03 a9",0},
      {&pItemInstInit,"ITEM_INST_INIT",
       "ff 83 01 d1 fd 7b 01 a9 fa 67 02 a9 f8 5f 03 a9 f6 57 04 a9 f4 4f 05 a9 fd 43 00 91 5a d0 3b d5 f3 03 00 aa e0 03 01 aa",0},
      {&pCreativeAddItem,"CREATIVE_ADD_ITEM",
       "ff 43 02 d1 fd 7b 03 a9 fb 23 00 f9 fa 67 05 a9 f8 5f 06 a9 f6 57 07 a9 f4 4f 08 a9 fd c3 00 91 58 d0 3b d5 f4 03 00 aa e0 03 01 aa 08 17 40 f9 f3 03 01 aa a8 83 1f f8 ?? ?? ?? ?? ?? ?? ?? ??",0},
      {&pCreativeGroupCtor,"CREATIVE_GROUP_CTOR",
       "fd 7b bc a9 f8 5f 01 a9 f6 57 02 a9 f4 4f 03 a9 fd 03 00 91 ?? ?? ?? ?? 08 c1 14 91 f3 03 00 aa 08 00 00 f9 00 04 80 52 f5 03 05 aa f4 03 04 2a",0},
      {&pCreativeFinalize,"CREATIVE_FINALIZE",
       "ff c3 01 d1 fd 7b 02 a9 f9 1b 00 f9 f8 5f 04 a9 f6 57 05 a9 f4 4f 06 a9 fd 83 00 91 57 d0 3b d5 f3 03 00 aa e8 16 40 f9 a8 83 1f f8 08 44 40 f9",0},
      {&pShapedRecipeCtor,"SHAPED_CTOR",
       "fd 7b bd a9 f6 57 01 a9 f4 4f 02 a9 fd 03 00 91 f3 03 04 2a f4 03 03 2a f5 03 02 2a f6 03 00 aa ?? ?? ?? ?? ?? ?? ?? ??",0},
      // CSL_STRING_INIT (0xe8313bc) is a one-instruction branch thunk
      // (`b 0x88a6328`, verified by objdump) with no unique signature. The
      // real function at 0x88a6328 has a unique signature; pStringInit points
      // there and is used for BOTH the CSL_STRING_INIT and STRING_INIT call sites.
      {&pStringInit,"STRING_INIT",
       "fd 7b bd a9 f6 57 01 a9 f4 4f 02 a9 fd 03 00 91 f3 03 02 aa 5f 58 00 f1 ?? ?? ?? ?? 68 7a 1f 53 08 14 00 38 62 06 00 91",0},
      {&pBlockGraphicsGet,"BLOCK_GRAPHICS_GET",
       "ff 83 02 d1 fd 7b 04 a9 fb 2b 00 f9 fa 67 06 a9 f8 5f 07 a9 f6 57 08 a9 f4 4f 09 a9 fd 03 01 91 59 d0 3b d5 f4 03 01 2a f6 03 00 aa 28 17 40 f9",0},
    };
    for(auto& s:tbl){
        uintptr_t a=scanUnique(s.sig,s.name);
        if(!a){
            __android_log_print(ANDROID_LOG_ERROR,"BlueCube","SIG FAILED: %s",s.name);
            ++gSigFailCount;
            *s.dst=0;                       // NO RVA fallback — stay null on failure
        }else{
            *s.dst=(uintptr_t)((intptr_t)a+s.adj);
        }
    }
    __android_log_print(ANDROID_LOG_INFO,"BlueCube",
        "native backend resolved: block=0x%llx itemCtor=0x%llx gfx=0x%llx creative=0x%llx recipe=0x%llx addRecipe=0x%llx netId=0x%llx sigFail=%d",
        (unsigned long long)pRegisterBlock,(unsigned long long)pItemInstCtor,
        (unsigned long long)pBlockGraphicsGet,(unsigned long long)pCreativeAddItem,
        (unsigned long long)pShapedRecipeCtor,(unsigned long long)pAddRecipe,
        (unsigned long long)pNetIdNext,gSigFailCount);
}

// ---- recipe diagnostic logger (plain globals, no signal handlers) --------
static unsigned long gDiagLiveX2[16]={0}, gDiagOurX2[16]={0};
static unsigned long gDiagLiveX4[12]={0}, gDiagOurX4[12]={0};
static unsigned long gDiagLiveX7[8]={0}, gDiagOurX7[8]={0};
static unsigned long gDiagResolvedItems[3]={0};  // blue_cube, orchid, stone Item*
static char gDiagPath[256]={0};                  // runtime package path (computed once)
static volatile int gDiagReady=0;
// Source-revision fingerprint (generated by build.sh). Printed at init and
// stamped into every diag run header / hook summary so a diagnostic file can be
// attributed to EXACTLY one build. Never changes within a single binary.
static const char kBuildFingerprint[]=BLUECUBE_BUILD_ID;

// Async-signal-safe integer -> hex. Returns pointer past written bytes.
static char* hexul(char* p,unsigned long v){
    static const char H[]="0123456789abcdef";
    if(!v){*p++='0';return p;}
    char tmp[16]; int n=0;
    while(v){tmp[n++]=H[v&15];v>>=4;}
    while(n) *p++=tmp[--n];
    return p;
}
static void writestr(int fd,const char* s){ size_t n=0; while(s[n])n++; (void)write(fd,s,n); }
static void writehex(int fd,const char* label,unsigned long v){
    char b[80]; char* p=b;
    while(*label)*p++=*label++; *p++='='; *p++='0'; *p++='x';
    p=hexul(p,v); *p++='\n'; (void)write(fd,b,(size_t)(p-b));
}
static void initDiagPath();   // defined just below
// Append a single human-readable line to the runtime diag file.
static void diagNote(const char* line){
    initDiagPath();
    int fd=open(gDiagPath,O_WRONLY|O_CREAT|O_APPEND,0666);
    if(fd<0) return;
    writestr(fd,line); writestr(fd,"\n");
    fsync(fd); close(fd);
}
// Start a CLEAN diagnostic run: truncate the file so it belongs to exactly ONE
// process launch and ONE build, then write a run header carrying the build
// fingerprint and pid. Called once from load(). This removes the mixed-build /
// mixed-run accumulation (11/11 + 12/12 + 13/13 in one file) that made prior
// logs unattributable. Every later write in this process appends to this file.
static void diagBeginRun(){
    initDiagPath();
    int fd=open(gDiagPath,O_WRONLY|O_CREAT|O_TRUNC,0666);
    if(fd<0) return;
    writestr(fd,"=== BlueCube diagnostic run (single build / single run) ===\n");
    writestr(fd,"build_fingerprint="); writestr(fd,kBuildFingerprint); writestr(fd,"\n");
    writehex(fd,"pid",(unsigned long)getpid());
    writehex(fd,"gBase",(unsigned long)gBase);
    fsync(fd); close(fd);
}
// Flushed INV step marker: logcat + diag file so the exact last inventory-open
// step is recorded even if the process faults immediately afterward.
static void invStep(const char* fmt,unsigned long long a=0,unsigned long long b=0,
                    unsigned long long c=0,unsigned long long d=0){
    __android_log_print(ANDROID_LOG_INFO,"BlueCube",fmt,a,b,c,d);
    fflush(stdout);
    char buf[256]; int n=snprintf(buf,sizeof(buf),fmt,a,b,c,d);
    if(n>0) diagNote(buf);
}
// resolve the runtime package name from /proc/self/cmdline and build the
// diag path dynamically (never hardcode com.mojang.minecraftpe). Called from
// load() so the eager diag writer only uses the cached path.
static void initDiagPath(){
    if(gDiagPath[0]) return;
    char pkg[256]={0};
    int fd=open("/proc/self/cmdline",O_RDONLY);
    if(fd>=0){ ssize_t n=read(fd,pkg,sizeof(pkg)-1); close(fd); if(n>0){pkg[n]=0;} }
    if(!pkg[0]) strlcpy(pkg,"unknown",sizeof(pkg));
    // Try /sdcard/Android/data/<pkg>/files (mkdir each level), then /data/data/<pkg>/files.
    char d1[256],d2[256],d3[256];
    strlcpy(d1,"/sdcard/Android/data",sizeof(d1));
    snprintf(d2,sizeof(d2),"%s/%s",d1,pkg);
    snprintf(d3,sizeof(d3),"%s/files",d2);
    mkdir(d1,0777); mkdir(d2,0777); mkdir(d3,0777);
    snprintf(gDiagPath,sizeof(gDiagPath),"%s/bluecube_diag.txt",d3);
    int t=open(gDiagPath,O_WRONLY|O_CREAT|O_APPEND,0666);
    if(t<0){
        char p1[256],p2[256],p3[256];
        strlcpy(p1,"/data/data",sizeof(p1));
        snprintf(p2,sizeof(p2),"%s/%s",p1,pkg);
        snprintf(p3,sizeof(p3),"%s/files",p2);
        mkdir(p1,0777); mkdir(p2,0777); mkdir(p3,0777);
        snprintf(gDiagPath,sizeof(gDiagPath),"%s/bluecube_diag.txt",p3);
    } else close(t);
}
// Eager synchronous dump (normal context, may use fsync). Writes full captured
// state immediately inside applyRecipe so the file exists before inventory open.
static void diagWriteEager(const char* tag){
    initDiagPath();
    int fd=open(gDiagPath,O_WRONLY|O_CREAT|O_APPEND,0666);
    if(fd<0) return;
    writestr(fd,"=== BlueCube eager diag: "); writestr(fd,tag); writestr(fd," ===\n");
    writestr(fd,"build_fingerprint="); writestr(fd,kBuildFingerprint); writestr(fd,"\n");
    writehex(fd,"gBase",(unsigned long)gBase);
    writehex(fd,"item_blue_cube",gDiagResolvedItems[0]);
    writehex(fd,"item_orchid",gDiagResolvedItems[1]);
    writehex(fd,"item_stone",gDiagResolvedItems[2]);
    writestr(fd,"-- our x2 --\n"); for(int i=0;i<16;i++) writehex(fd,"q",gDiagOurX2[i]);
    writestr(fd,"-- live x2 --\n"); for(int i=0;i<16;i++) writehex(fd,"q",gDiagLiveX2[i]);
    writestr(fd,"-- our x4 --\n"); for(int i=0;i<12;i++) writehex(fd,"q",gDiagOurX4[i]);
    writestr(fd,"-- live x4 --\n"); for(int i=0;i<12;i++) writehex(fd,"q",gDiagLiveX4[i]);
    writestr(fd,"-- our x7 --\n"); for(int i=0;i<8;i++) writehex(fd,"q",gDiagOurX7[i]);
    writestr(fd,"-- live x7 --\n"); for(int i=0;i<8;i++) writehex(fd,"q",gDiagLiveX7[i]);
    fsync(fd); close(fd);
}

// ---- ShapedRecipe byte-for-byte comparison (world-load diagnostic) --------
// Walk Recipes' id-map (buckets @+0x70, count @+0x78 per 0x10411ef0) and find
// the ShapedRecipe objects by their vtable 0x13d70be0 at +0. Dump all 0xF8
// bytes of our blue_cube recipe and a vanilla 3x3 recipe side-by-side so the
// exact discrepancy causing the instant Recipe Book crash is visible.
static const char* recipeIdPtr(void* recipe,size_t* lenOut){
    const unsigned char* s=(const unsigned char*)((char*)recipe+8);
    unsigned char flag=s[0];
    if(flag&1){ if(lenOut) *lenOut=*(const size_t*)(s+16); return *(const char**)(s+8); }
    if(lenOut) *lenOut=flag>>1;
    return (const char*)s+1;
}
// Find our recipe and a vanilla 3x3 recipe inside Recipes*. Returns true if
// both were located. Fills netId/width/height for the repair decision.
static bool findRecipes(void* recipes,void** oursOut,void** vanillaOut,
                        unsigned* ourNetId,unsigned* vanNetId){
    *oursOut=nullptr; *vanillaOut=nullptr; *ourNetId=0; *vanNetId=0;
    collectReadableMem();   // refresh heap mappings before walking
    if(!recipes || !readableMem((uintptr_t)recipes,0x100)) return false;
    uintptr_t vtWant=gBase+off::SHAPED_RECIPE_VTABLE;
    // Hard iteration budget: the diagnostic walker must NEVER hang world load.
    // With ~4200 recipes and ~6400 map nodes, even an O(log n) readableMem is
    // fine, but a corrupt/garbage node chain could otherwise run for millions
    // of iterations. Cap total pointer checks; diagnostics are best-effort.
    const int kMaxChecks=20000; int checks=0;
    auto checkRecipe=[&](void* p){
        if(checks++>=kMaxChecks) return;
        if(!p || !readableMem((uintptr_t)p,0xf8)) return;
        uintptr_t vt=*(uintptr_t*)p;
        if(vt!=vtWant && !(vt>=gBase+off::SHAPED_RECIPE_VTABLE_LO && vt<=gBase+off::SHAPED_RECIPE_VTABLE_HI)) return;
        size_t len=0; const char* id=recipeIdPtr(p,&len);
        bool isOurs=id&&len>=19&&readableMem((uintptr_t)id,19)&&std::memcmp(id,"blue_cube:blue_cube",19)==0;
        int w=*(int*)((char*)p+0x30), h=*(int*)((char*)p+0x34);
        unsigned net=*(unsigned*)((char*)p+0x3c);
        if(isOurs){ *oursOut=p; *ourNetId=net; }
        else if(w>=1&&w<=3&&h>=1&&h<=3&&!*vanillaOut){ *vanillaOut=p; *vanNetId=net; }
    };
    // 1) SIMPLEST + SAFEST: std::vector<Recipe*> at Recipes+0x98 (+0xa0 end,
    //    +0xa8 cap), 8-byte elements (proven by 0x10413f9c str x21,[x19],#8).
    uintptr_t begin=*(uintptr_t*)((char*)recipes+0x98);
    uintptr_t end  =*(uintptr_t*)((char*)recipes+0xa0);
    if(begin && end>begin && (end-begin)<=0x100000 && ((end-begin)%8)==0 &&
       readableMem(begin,end-begin)){
        for(uintptr_t p=begin;p+8<=end && checks<kMaxChecks;p+=8) checkRecipe(*(void**)p);
    }
    if(*oursOut) return true;
    // 2) Map A (netId -> Recipe*): buckets @+0x48, COUNT @+0x50, nodes 32B.
    //    bucket[i] is a SENTINEL; its +0 is the first real node; Recipe* at node+0x18.
    uintptr_t buckets=*(uintptr_t*)((char*)recipes+0x48);
    uint64_t count=*(uint64_t*)((char*)recipes+0x50);
    if(buckets && count>0 && count<(1u<<24) && readableMem(buckets,(size_t)count*8)){
        for(uint64_t i=0;i<count && checks<kMaxChecks;i++){
            uintptr_t sent=*(uintptr_t*)(buckets+i*8);
            if(!sent || !readableMem(sent,0x20)) continue;
            uintptr_t node=*(uintptr_t*)sent;    // sentinel->next
            int guard=0;
            while(node && readableMem(node,0x20) && guard++<4096 && checks<kMaxChecks){
                checkRecipe(*(void**)(node+0x18));   // node+24 = Recipe*
                node=*(uintptr_t*)node;               // +0 = next
            }
        }
    }
    invStep("[BlueCube] INV: findRecipes ours=%llx van=%llx net=%llx checks=%llx",
            (unsigned long long)*oursOut,(unsigned long long)*vanillaOut,
            (unsigned long long)*ourNetId,(unsigned long long)checks);
    return *oursOut!=nullptr;
}

static void dumpRecipesSideBySide(void* recipes){
    initDiagPath();
    collectReadableMem();   // populate heap cache BEFORE the readableMem check below
    int fd=open(gDiagPath,O_WRONLY|O_CREAT|O_APPEND,0666);
    if(fd<0) return;
    writestr(fd,"=== ShapedRecipe side-by-side dump ===\n");
    writestr(fd,"build_fingerprint="); writestr(fd,kBuildFingerprint); writestr(fd,"\n");
    writehex(fd,"gBase",(unsigned long)gBase);
    writehex(fd,"Recipes",(unsigned long)recipes);
    writehex(fd,"readableMemCount",(unsigned long)gReadableMemCount);
    writehex(fd,"recipesReadable",(unsigned long)(recipes&&readableMem((uintptr_t)recipes,0x100)));
    if(recipes && readableMem((uintptr_t)recipes,0x100)){
        for(int i=0;i<0x100/8;i++){
            char lb[24]; snprintf(lb,sizeof(lb),"Recipes+q[%02x]",i*8);
            writehex(fd,lb,((unsigned long*)recipes)[i]);
        }
    }
    void* ours=nullptr; void* van=nullptr; unsigned on=0,vn=0;
    findRecipes(recipes,&ours,&van,&on,&vn);
    writehex(fd,"ours",(unsigned long)ours); writehex(fd,"vanilla3x3",(unsigned long)van);
    writehex(fd,"ourNetId",on); writehex(fd,"vanNetId",vn);
    for(int pass=0;pass<2;pass++){
        void* p=pass?van:ours;
        writestr(fd,pass?"-- vanilla 3x3 (0x00..0xf8) --\n":"-- ours (0x00..0xf8) --\n");
        if(!p || !readableMem((uintptr_t)p,0xf8)) continue;
        for(size_t off=0;off<0xf8;off+=8){
            char lb[24]; snprintf(lb,sizeof(lb),"q[%02zx]",off);
            writehex(fd,lb,*(unsigned long*)((char*)p+off));
        }
    }
    fsync(fd); close(fd);
}
// Data-driven netId repair: only if our netId is 0 while a vanilla 3x3 recipe
// on the same Recipes instance has a non-zero netId (proven fault: getRecipe
// returns null and its result is dereferenced unguarded at 0x10823d74).
static void repairRecipeNetId(void* recipes){
    void* ours=nullptr; void* van=nullptr; unsigned on=0,vn=0;
    bool found=findRecipes(recipes,&ours,&van,&on,&vn);
    invStep("[BlueCube] INV: repairNetId found=%llx ours=%llx net=%llx",
            (unsigned long long)found,(unsigned long long)ours,(unsigned long long)on);
    if(!found || !ours) return;
    unsigned nid=on;
    if(nid==0){
        // Use Bedrock's native netId allocator (0x103db7f0 reads/writes the
        // global counter at 0x141dc740) — step is +2, 0 stays "unassigned".
        using NextIdFn=void(*)(unsigned*);
        ((NextIdFn)pNetIdNext)(&nid);
        if(nid==0) nid=2;
        invStep("[BlueCube] INV: repairNetId allocated=%llx",(unsigned long long)nid);
    }
    if(*(unsigned*)((char*)ours+0x3c)!=nid){
        *(unsigned*)((char*)ours+0x3c)=nid;            // 0x10411df4 writer
        // Insert the netId key into the Recipes netId map via the game's own
        // addRecipe wrapper (writes [recipe+0x3c] then calls 0x10411ef0).
        using AddRecipeFn=void(*)(void*,void*,void**);
        void* rp=ours;
        ((AddRecipeFn)pAddRecipe)(recipes,&nid,&rp);
        invStep("[BlueCube] INV: repairNetId wrote+reReg net=%llx",(unsigned long long)nid);
    }
    diagWriteEager("netid_repaired");
}


// Globals used by the naked trampoline that calls the game's ItemRegistry
// getItem(name) wrapper with the x8 hidden SharedPtr-return slot.
extern "C" {
    void* gGetItemTarget = nullptr;
    void* gGetItemOut    = nullptr;   // address of the 8-byte SharedPtr out slot
}

// AAPCS64: x0=reg, x1=&outId, x2=&local, x3=name, x4=nameLen; x8 = hidden out.
__attribute__((naked)) static void call_get_item_tramp(void*,int*,int*,const char*,size_t){
    asm volatile(
        "adr x8, gGetItemOut\n"
        "ldr x8, [x8]\n"        // x8 = out slot pointer
        "adr x9, gGetItemTarget\n"
        "ldr x9, [x9]\n"        // x9 = target function
        "br x9\n"
        :::"memory");
}

namespace {
// Unique, non-colliding block runtime ID (vanilla blocks in 1.26 use < ~1500).
constexpr int kBlueCubeBlockId = 4096;

using RegBlockFn   = void*(*)(void*,void*,int*,void*);
using HashCtor     = void(*)(void*,const std::string&);
using HashGetStr   = const char*(*)(void*);
using BlockItemCtor= void*(*)(void*,const char*,short,void*);
// Verified in Branch Graph A: the BlockItem ctor (0x10816530) does NOT write
// Item+320 (creative category) nor Item+0x150 (creative group string). Both
// are dereferenced unguarded by the Recipe Book tab/Search row builder
// (0x107e9aa4), so an unset category byte (<1 or >4) or garbage group string
// faults or hides the item. These are Bedrock's own setters.
using SetCreativeCategoryFn=void(*)(void*,unsigned char);                 // 0x1079d000
using ItemInstDtor = void(*)(void*);
using AddLooseFn   = void(*)(void*,void const*);
// Bedrock uses a 24-byte csl::basic_string (libc++ NDK std::string layout:
// SSO flag at byte0 = len<<1, inline chars at +1; heap ptr at +0, len at +8).
// All I18n::get overloads take x1=key(string*) and return the string via x8.
struct CslStr {
    unsigned char b[24];
    CslStr() { std::memset(b,0,sizeof(b)); }
    CslStr(const CslStr& o) { std::memcpy(b,o.b,sizeof(b)); } // non-trivial => x8 hidden return
};
using CslStringInitFn = void(*)(void* out,const char* data,size_t len);
// forward x0..x3 + hidden x8 return; works for both 1-arg and params get.
using I18nGet1 = CslStr(*)(void*,const void*);
using I18nGetN = CslStr(*)(void*,const void*,uintptr_t,uintptr_t);
// dedicated loaders (opaque args, return ignored by their callers)
using LoaderFn     = void(*)(uintptr_t,uintptr_t);
// PART 1: 16x16 custom block PNG, embedded in the .so (no files, no packs).
static const uint8_t kMyBlockPng[] = {0x89,0x50,0x4e,0x47,0x0d,0x0a,0x1a,0x0a,0x00,0x00,0x00,0x0d,0x49,0x48,0x44,0x52,0x00,0x00,0x00,0x10,0x00,0x00,0x00,0x10,0x08,0x06,0x00,0x00,0x00,0x1f,0xf3,0xff,0x61,0x00,0x00,0x02,0xc8,0x49,0x44,0x41,0x54,0x78,0xda,0x65,0x53,0x6b,0x53,0xda,0x40,0x14,0xcd,0x2f,0xac,0xa3,0xad,0xb6,0x35,0x86,0x00,0x79,0x90,0x10,0x92,0x90,0x07,0x10,0x08,0x4f,0x41,0xca,0x43,0x1e,0x2d,0xd4,0x69,0x29,0x2a,0xa2,0x32,0x56,0x67,0x3a,0xd3,0x0f,0xfa,0x2b,0xfc,0x4f,0xa7,0x77,0x97,0xd1,0x76,0xa6,0x1f,0x76,0x32,0xb9,0x67,0xf7,0xde,0xb3,0xe7,0x9c,0x15,0xa2,0x30,0xc4,0xed,0xea,0x0a,0x7a,0x2a,0x85,0xf3,0xf3,0x33,0x5c,0x5f,0x2f,0xe1,0xe5,0x6d,0xf4,0x7b,0x7d,0x5a,0x3d,0x14,0x0a,0x05,0xac,0xd7,0x6b,0x28,0x8a,0x82,0x8b,0x8b,0x21,0x6e,0x6e,0x3e,0xc3,0xf7,0x74,0xf4,0xfb,0x5b,0x5c,0x28,0xe6,0xf3,0x18,0x75,0x3f,0x41,0x57,0x52,0x18,0xf4,0xdb,0x54,0x6c,0x43,0x53,0x15,0xe4,0xac,0x1c,0x8c,0x8c,0x01,0xdf,0xf7,0xf9,0x46,0x95,0x6a,0x83,0x41,0x19,0x43,0x5a,0xc9,0xa4,0xc4,0xeb,0x71,0x1c,0x43,0x88,0x2b,0x15,0x3c,0xdc,0x3f,0xe0,0xe9,0xe9,0x09,0x61,0xe0,0x41,0x4e,0x48,0x98,0xcd,0x66,0x38,0x1d,0x9e,0x22,0x4f,0xcd,0x4f,0x3a,0x27,0x38,0xf5,0x4d,0xd4,0xd4,0x23,0x64,0x75,0x11,0x57,0x8b,0x6f,0xf8,0x75,0x77,0x87,0x92,0x1f,0x70,0x5c,0x98,0x4e,0xa6,0x98,0x4e,0xa7,0x78,0x7c,0x7c,0xa4,0x09,0x03,0xc4,0xcd,0x16,0xaa,0xcd,0x26,0x67,0x50,0xad,0x56,0x31,0x19,0x4f,0x60,0x1c,0xee,0xc3,0x90,0x8f,0x10,0xd3,0x75,0x37,0xab,0x15,0x96,0xf3,0x39,0xc6,0xdd,0x2e,0x6a,0x8c,0x01,0xeb,0xd2,0xe9,0x74,0x10,0x86,0x05,0x98,0x8e,0x8b,0xf1,0xfc,0x0c,0x41,0x54,0x86,0x61,0x66,0xe1,0x79,0x1e,0x74,0x5d,0xe7,0x8d,0x2c,0xcb,0x82,0x92,0x4e,0x23,0xb0,0x6d,0xb8,0x1a,0x7d,0x5d,0x87,0xeb,0x23,0x14,0x0b,0x45,0xa2,0x2d,0x43,0x14,0x45,0xa8,0x9a,0x0e,0x29,0x99,0xc4,0xa1,0x94,0xc0,0x68,0x34,0xc2,0xe6,0x76,0x03,0x2b,0x6b,0x61,0x6f,0x77,0x17,0xe2,0xa1,0x88,0x77,0xbb,0x6f,0x50,0x74,0x0d,0x14,0x6c,0x0d,0x9d,0x56,0x8d,0xe3,0x42,0xfb,0xf8,0x98,0xab,0x9c,0x90,0xb6,0xc2,0xa4,0x92,0x29,0xbc,0xdd,0xdb,0x83,0x69,0x9a,0x60,0xfa,0x30,0xfc,0xf2,0xf2,0x12,0x69,0x9a,0xee,0x18,0x69,0x44,0x79,0x03,0x9e,0x99,0x46,0x46,0x4d,0x71,0x5c,0x60,0x93,0x1c,0xa2,0x15,0x06,0x01,0x76,0x76,0x76,0x70,0xb0,0x7f,0xc0,0xd9,0xb0,0x43,0xac,0xfe,0x82,0xb3,0xcd,0x19,0x4d,0x81,0x9e,0xfc,0x08,0x4b,0x4f,0xf1,0xa1,0xac,0x2e,0xa8,0xaa,0xca,0xed,0xd0,0x54,0x8d,0x74,0x08,0x39,0xc0,0x74,0x79,0xf1,0xb9,0x12,0xb8,0xb8,0x5b,0xfd,0x80,0x9e,0x96,0xb1,0x5c,0x2e,0xff,0xc3,0x05,0xc3,0x30,0xd0,0x6a,0xb5,0xb8,0x48,0x4c,0x8b,0x7a,0xbd,0x0e,0x4d,0x91,0xa9,0xa1,0x0c,0xd3,0xc8,0xa0,0x44,0xa1,0x9a,0x74,0x9b,0xf4,0x9f,0x40,0xaf,0xdf,0x45,0xef,0xa4,0x0b,0x9b,0xae,0x63,0x51,0xf0,0x98,0xa8,0x42,0x40,0xd4,0x1d,0xc7,0xe1,0x0c,0x74,0x12,0xf1,0xc3,0xfb,0x7d,0xb4,0x9a,0x11,0x51,0xf6,0x90,0x77,0x6d,0x94,0xca,0x21,0x39,0xd3,0xc5,0xfd,0xef,0x15,0x7a,0x93,0x26,0xf4,0x8c,0x8c,0xf9,0xa7,0x2e,0x4a,0xa4,0x91,0x4a,0xc2,0x0a,0xdc,0x67,0x5d,0x43,0x8a,0x3a,0x8a,0x92,0x88,0x52,0xb3,0x84,0xa8,0x1e,0x52,0x5c,0x6d,0x34,0x1a,0x0d,0x9e,0x91,0x72,0xd5,0xc7,0x7c,0x31,0xc4,0xe8,0x4b,0x07,0x8d,0x4e,0x44,0xa9,0x94,0x60,0x26,0x13,0x68,0x30,0x11,0xe3,0xa8,0x44,0x77,0x5c,0xa0,0xec,0xe5,0x90,0x0b,0x2d,0x8c,0xce,0x46,0xf0,0x62,0x0f,0x19,0x0a,0x92,0xe3,0x17,0x79,0x2a,0x9f,0x9f,0x9f,0xb1,0x38,0xff,0x8a,0x7a,0xbb,0x88,0xeb,0x9f,0xdf,0x79,0x33,0xcb,0xd1,0xf8,0xfb,0x10,0xaa,0xe5,0x08,0x45,0x27,0x0b,0xd7,0x26,0xdb,0x6a,0x01,0xfc,0xc8,0x86,0x44,0x82,0xf5,0xc7,0x33,0xac,0x37,0x0f,0xf4,0x3e,0xfa,0xdc,0x6f,0xc6,0x44,0x51,0xd3,0x70,0x83,0x2c,0x44,0xf9,0x00,0x7e,0xb0,0x8d,0xf9,0x6b,0x0e,0x6c,0xc7,0xc4,0xd5,0xcd,0x02,0xbd,0x41,0x13,0xae,0x6f,0xc1,0x0f,0x23,0x54,0x2a,0x31,0x5e,0x70,0x93,0xc4,0x66,0x02,0xb3,0x60,0x1d,0x1d,0x89,0x90,0x65,0x79,0x6b,0xe3,0x5f,0x9f,0xcb,0xd0,0x8d,0x24,0x8a,0x65,0x97,0x9a,0x65,0x5f,0x7d,0xfe,0x37,0x07,0x12,0x85,0x4d,0x4e,0x24,0xf8,0xe1,0x15,0xbd,0x09,0x56,0xff,0x03,0xeb,0x97,0x6b,0x9b,0x77,0xb3,0x2b,0x0f,0x00,0x00,0x00,0x00,0x49,0x45,0x4e,0x44,0xae,0x42,0x60,0x82};
static const size_t kMyBlockPngLen = sizeof(kMyBlockPng);

static const void* memFind(const void* h,size_t n,const char* k,size_t kl){
    if(!h||kl>n) return nullptr;
    const char* b=(const char*)h;
    for(size_t i=0;i+kl<=n;i++) if(std::memcmp(b+i,k,kl)==0) return b+i;
    return nullptr;
}
// ---- PART 3: ResourcePackLoader vfunc3/4 — serve embedded PNG --------------
// VERIFIED in target libminecraftpe.so 6c7b409d (arm64 1.26.60.4):
//   0xcf4de30 (vfunc3 getResource-like) and 0xcf4e2d0 (vfunc4 hasResource-like)
//   are bool (w0) functions: x0=this, x1=Core::Path*, x2=out string, x3,x4 extra.
//   Core::Path embeds std::__ndk1::string at byte +8 (thunk 0x13526690 = x0+8).
//   String ABI: byte0 flag; SSO len=flag>>1 chars@+1 (<=22);
//              LONG flag bit0 set, data ptr@0, len@8 (from ctor 0x88a6328).
//   Output is ALREADY constructed: use std::string::assign(const char*,size_t)
//   at PLT 0x136357c0, NOT the constructor pStringInit.
using AssignFn = void*(*)(void*,const char*,size_t);
// ---- In-memory blocks.brarchive virtual AAsset ----------------------------
// VERIFIED brarchive layout (offline, real APK file):
//   header 16B: magic 7d2725b1a0527026 (LE 0x267052a0b125277d),
//               entry_count u32@+8 (703), version u32@+12 (1)
//   703 x 256B entries @+16: name_len u8@+0, name@+1..+255,
//               data_offset u32@+248, data_len u32@+252 (offsets RELATIVE to
//               data base = 16+256*count = 0x2bf10). Entries sorted by name;
//               "obsidian.png" idx 481 -> off 0x578e0 len 294 -> PNG magic OK.
//   "blue_cube.png" inserts at sorted idx 35; new offset = n-base = 557238.
//   Offline proof: patched size 737222+256+769=738247, all 703 original blobs
//   byte-identical, blue_cube.png unpacks to exactly our 769-byte PNG.
//
// Imported AAsset* functions hooked (all of them): open/getLength/getLength64/
// read/seek64/close. No getBuffer/openFd/isAllocated are imported by this lib.
struct VirtualAsset { const uint8_t* data; size_t size; size_t pos; uint64_t magic; size_t blueOff, blueLen; };
static constexpr uint64_t kVAMagic=0x4243415252415654ULL;
static std::atomic<int> gVAActive{0};
static std::atomic_bool gTerrainSpliced{false};
static std::mutex gVAMutex;
static std::unordered_set<VirtualAsset*> gVASet;
// Per-exact-path cache: different vanilla_* archives must NEVER share a buffer.
static std::unordered_map<std::string,const std::vector<uint8_t>*> gPatchedCache;
static const char* const kTargetArchives[]={
    "assets/resource_packs/vanilla/__brarchive/textures/blocks.brarchive",
    "assets/resource_packs/vanilla_1.21.90/__brarchive/textures/blocks.brarchive",
    "assets/resource_packs/vanilla_1.26.60/__brarchive/textures/blocks.brarchive",
    "assets/resource_packs/vanilla/__brarchive/textures.brarchive",
    "assets/resource_packs/vanilla_1.21.90/__brarchive/textures.brarchive",
};

using AssetOpenFn  = void*(*)(void*,const char*,int);
using AssetReadFn  = int(*)(void*,void*,size_t);
using AssetLenFn   = int(*)(void*);
using AssetLen64Fn = int64_t(*)(void*);
using AssetSeek64Fn= int64_t(*)(void*,int64_t,int);
using AssetCloseFn = void(*)(void*);
static AssetOpenFn gOrigOpen=nullptr; static AssetReadFn gOrigRead=nullptr;
static AssetLenFn gOrigLen=nullptr; static AssetLen64Fn gOrigLen64=nullptr;
static AssetSeek64Fn gOrigSeek64=nullptr; static AssetCloseFn gOrigClose=nullptr;
static void* gAssetHooks[6]={nullptr};

static void brDiag(const char* op){
    static int n=0; if(n++<5){ char b[200];
        snprintf(b,sizeof(b),"[BC] BRARCHIVE-OP op='%s'",op); diagNote(b); }
}
static VirtualAsset* asVA(void* a){
    if(gVAActive.load(std::memory_order_acquire)==0) return nullptr;
    std::lock_guard<std::mutex> lk(gVAMutex);
    auto it=gVASet.find(reinterpret_cast<VirtualAsset*>(a));
    return it==gVASet.end()?nullptr:*it;
}
static bool buildPatchedBR(const uint8_t* src,size_t n,std::vector<uint8_t>& out){
    if(n<16||std::memcmp(src,"\x7d\x27\x25\xb1\xa0\x52\x70\x26",8)) return false;
    uint32_t cnt,ver;
    std::memcpy(&cnt,src+8,4); std::memcpy(&ver,src+12,4);
    if(cnt==0||cnt>100000||ver!=1) return false;
    size_t base=16+(size_t)256*cnt; if(base>n) return false;
    std::vector<std::pair<std::string,size_t>> names; names.reserve(cnt+1);
    for(uint32_t i=0;i<cnt;i++){
        const uint8_t* e=src+16+(size_t)256*i; unsigned nl=e[0];
        if(nl==0||nl>255) return false;
        names.push_back({std::string((const char*)e+1,nl),16+(size_t)256*i});
        uint32_t off,len; std::memcpy(&off,e+248,4); std::memcpy(&len,e+252,4);
        if((size_t)off>n||(size_t)len>n||(size_t)off+(size_t)len>n) return false;
        if(names.back().first=="blue_cube.png") return false;
    }
    size_t pos=0; while(pos<names.size() && names[pos].first<"blue_cube.png") pos++;
    uint32_t newoff=(uint32_t)(n-base);
    out.clear(); out.reserve(n+256+kMyBlockPngLen);
    out.insert(out.end(),src,src+8);
    uint32_t nc=cnt+1; const uint8_t* nb=(const uint8_t*)&nc; out.insert(out.end(),nb,nb+4);
    out.insert(out.end(),src+12,src+16);
    for(size_t i=0;i<=cnt;i++){
        if(i==pos){
            uint8_t rec[256]={0}; const char* nm="blue_cube.png"; size_t nl=std::strlen(nm);
            rec[0]=(uint8_t)nl; std::memcpy(rec+1,nm,nl);
            std::memcpy(rec+248,&newoff,4); uint32_t nl32=(uint32_t)kMyBlockPngLen;
            std::memcpy(rec+252,&nl32,4);
            out.insert(out.end(),rec,rec+256);
        }
        if(i<cnt) out.insert(out.end(),src+16+(size_t)256*i,src+16+(size_t)256*i+256);
    }
    out.insert(out.end(),src+base,src+n);
    out.insert(out.end(),kMyBlockPng,kMyBlockPng+kMyBlockPngLen);
    return out.size()==n+256+kMyBlockPngLen;
}
// ---- Generic in-memory patchers for every target AAsset path ----------------
// SAFE REPACK RULE for modifying an EXISTING brarchive entry: keep all original
// bytes untouched, APPEND the new entry bytes at the end of the data block, and
// rewrite ONLY that entry's data_offset(+248)/data_len(+252) in its 256B record.
// No other entry moves, so every untouched texture stays byte-identical.
static bool brCountBase(const uint8_t* d,size_t n,uint32_t& cnt,size_t& base){
    if(n<16||std::memcmp(d,"\x7d\x27\x25\xb1\xa0\x52\x70\x26",8)) return false;
    std::memcpy(&cnt,d+8,4);
    uint32_t ver;std::memcpy(&ver,d+12,4);
    if(cnt==0||cnt>100000||ver!=1) return false;
    base=16+(size_t)256*cnt;
    return base<=n;
}
static bool patchTexturesBR(const std::vector<uint8_t>& src,std::vector<uint8_t>& out){
    uint32_t cnt;size_t base;
    if(!brCountBase(src.data(),src.size(),cnt,base)) return false;
    out=src;
    size_t appendAt=src.size();
    for(uint32_t i=0;i<cnt;i++){
        const uint8_t* e=src.data()+16+(size_t)256*i;
        unsigned nl=e[0]; if(nl==0||nl>255) return false;
        std::string name((const char*)e+1,nl);
        uint32_t off,ln;std::memcpy(&off,e+248,4);std::memcpy(&ln,e+252,4);
        if((size_t)off+ln>src.size()-base) return false;
        std::string blob((const char*)src.data()+base+off,ln);
        std::string nb;
        if(name=="terrain_texture.json"){
            if(blob.find("blue_cube")!=std::string::npos) continue;
            size_t p=blob.find("\"texture_data\"");
            if(p==std::string::npos) continue;
            size_t q=blob.find('{',p);
            if(q==std::string::npos) continue;
            nb=blob.substr(0,q+1)+"\"blue_cube\":{\"textures\":\"textures/blocks/blue_cube\"},"+blob.substr(q+1);
        }else if(name=="textures_list.json"){
            if(blob.find("blue_cube")!=std::string::npos) continue;
            size_t p=blob.find('[');
            if(p==std::string::npos||blob.substr(0,p).find_first_not_of(" \r\n\t")!=std::string::npos) continue;
            nb=blob.substr(0,p+1)+"\"textures/blocks/blue_cube\","+blob.substr(p+1);
        }else continue;
        out.insert(out.end(),nb.begin(),nb.end());
        uint8_t* oe=out.data()+16+(size_t)256*i;
        uint32_t no=(uint32_t)(appendAt-base),nl32=(uint32_t)nb.size();
        std::memcpy(oe+248,&no,4);std::memcpy(oe+252,&nl32,4);
        appendAt+=nb.size();
    }
    return out.size()>src.size();
}
static bool patchLooseJson(const std::string& path,const std::vector<uint8_t>& src,std::vector<uint8_t>& out){
    std::string s((const char*)src.data(),src.size());
    if(s.find("blue_cube")!=std::string::npos) return false;
    std::string ins;
    if(path.size()>=11 && path.compare(path.size()-11,11,"blocks.json")==0){
        size_t p=s.find("\"obsidian\":");
        if(p==std::string::npos) p=s.find('{');
        if(p==std::string::npos) return false;
        ins="\"blue_cube:blue_cube\":{\"textures\":\"blue_cube\",\"sound\":\"stone\"},";
        s.insert(p,ins);
    }else if(path.find("terrain_texture.json")!=std::string::npos){
        size_t p=s.find("\"texture_data\"");
        if(p==std::string::npos) return false;
        size_t q=s.find('{',p);
        if(q==std::string::npos) return false;
        s.insert(q+1,"\"blue_cube\":{\"textures\":\"textures/blocks/blue_cube\"},");
    }else if(path.find("contents.json")!=std::string::npos){
        const char* pref="\"path\": \"textures/blocks/";
        size_t pfx=std::strlen(pref),vpfx=std::strlen("\"path\": \"");
        size_t p=0;bool done=false;
        while((p=s.find(pref,p))!=std::string::npos){
            size_t ns=p+vpfx,ne=s.find('"',ns);
            if(ne==std::string::npos||ne<=ns) return false;
            std::string nm=s.substr(ns,ne-ns),leaf=nm.substr(nm.rfind('/')+1);
            if(leaf>"blue_cube.png"){
                size_t br=s.rfind('{',p),ls=br==std::string::npos?0:s.rfind('\n',br);
                ls=(ls==std::string::npos)?0:ls+1;
                s.insert(ls,"        {\r\n            \"path\": \"textures/blocks/blue_cube.png\"\r\n        },\r\n");
                done=true;break;
            }
            p=ne;
        }
        if(!done) return false;
    }else return false;
    out.assign(s.begin(),s.end());
    return true;
}
static bool buildPatchedForPath(const std::string& path,const std::vector<uint8_t>& src,std::vector<uint8_t>& out){
    if(path.size()>=30 && path.compare(path.size()-30,30,"__brarchive/textures.brarchive")==0)
        return patchTexturesBR(src,out);
    if(path.size()>=37 && path.compare(path.size()-37,37,"__brarchive/textures/blocks.brarchive")==0)
        return buildPatchedBR(src.data(),src.size(),out);
    return patchLooseJson(path,src,out);
}
static void findBlueRange(const std::vector<uint8_t>& p,size_t& absOff,size_t& len){
    absOff=0;len=0;
    // CRASH FIX: previously called on patched LOOSE JSON buffers, where bytes
    // 8..11 are JSON text (~0x207b...), giving a huge fake entry_count and an
    // out-of-bounds loop -> SIGSEGV on first patched contents.json. Validate
    // the brarchive magic and bounds before touching any entry record.
    if(p.size()<16||std::memcmp(p.data(),"\x7d\x27\x25\xb1\xa0\x52\x70\x26",8)) return;
    uint32_t cnt;std::memcpy(&cnt,p.data()+8,4);
    if(cnt==0||cnt>100000) return;
    size_t base=16+(size_t)256*cnt;
    if(base>p.size()) return;
    for(uint32_t i=0;i<cnt;i++){
        const uint8_t* e=p.data()+16+(size_t)256*i;
        unsigned nl=e[0];
        if(nl==12 && std::memcmp(e+1,"blue_cube.png",12)==0){
            uint32_t off,l;std::memcpy(&off,e+248,4);std::memcpy(&l,e+252,4);
            absOff=base+off;len=l;return;
        }
    }
}
static void brBlueDiag(const char* op,long long off,long long len){
    char b[220];
    snprintf(b,sizeof(b),"[BC] BRARCHIVE-BLUECUBE-READ op='%s' off=%lld len=%lld",op,off,len);
    diagNote(b);
}
static void brFail(const char* path,const char* reason,long long val){
    char b[300];
    snprintf(b,sizeof(b),"[BC] BRARCHIVE-FAIL path='%s' reason='%s' val=%lld",path,reason,val);
    diagNote(b);
}
static void* assetOpenDetour(void* mgr,const char* path,int mode){
    if(!path) return gOrigOpen?gOrigOpen(mgr,path,mode):nullptr;
    // EXACT match only. Never touch other vanilla_* / chemistry packs.
    std::string kpath;
    if(path){
        for(const char* t:kTargetArchives) if(std::strcmp(path,t)==0){ kpath=t; break; }
        if(kpath.empty() && std::strstr(path,"vanilla/") &&
           (std::strstr(path,"blocks.brarchive")||std::strstr(path,"contents.json"))){
            static std::unordered_set<std::string> seen;
            std::lock_guard<std::mutex> lk(gVAMutex);
            if(seen.insert(std::string(path)).second){ char b[300];
                snprintf(b,sizeof(b),"[BC] ASSET-PATH path='%s' matched=%d",path,0);diagNote(b); }
        }
    }
    if(path && std::strstr(path,"blue_cube")){
        char b[300];snprintf(b,sizeof(b),"[BC] OPEN-BLUECUBE path='%s'",path);diagNote(b);
    }
    if(path && gTerrainSpliced.load(std::memory_order_acquire)){
        static std::atomic<int> postN{0}; int n=postN.load();
        if(n<25){ postN.fetch_add(1); char b[340];
            snprintf(b,sizeof(b),"[BC] POST-TERRAIN-OPEN#%d path='%s'",n+1,path);diagNote(b); }
    }
    if(kpath.empty()) return gOrigOpen?gOrigOpen(mgr,path,mode):nullptr;
    { char b[300];snprintf(b,sizeof(b),"[BC] BR-ENTER path='%s'",kpath.c_str());diagNote(b); }
    void* real=gOrigOpen?gOrigOpen(mgr,path,mode):nullptr;
    if(!real){ brFail(path,"origOpenNull",0); return nullptr; }
    if(!gOrigLen64||!gOrigRead){ brFail(path,"noLen64Read",0); return real; }
    int64_t l64=gOrigLen64(real);
    if(l64<=1024||l64>(int64_t)128*1024*1024){ brFail(path,"badLen64",l64); if(gOrigClose) gOrigClose(real); return real; }
    int len=(int)l64;
    std::vector<uint8_t> buf((size_t)len);
    size_t total=0;
    while(total<(size_t)len){
        int got=gOrigRead(real,buf.data()+total,(size_t)len-total);
        if(got<=0) break;
        total+=(size_t)got;
    }
    if(gOrigClose) gOrigClose(real);
    if(total!=(size_t)len){ brFail(path,"shortRead",(long long)total); return real; }
    const std::vector<uint8_t>* patched=nullptr;
    {
        std::lock_guard<std::mutex> lk(gVAMutex);
        auto it=gPatchedCache.find(kpath);
        if(it!=gPatchedCache.end()) patched=it->second;
        else{
            auto* v=new std::vector<uint8_t>();
            if(buildPatchedForPath(kpath,buf,*v)){ gPatchedCache[kpath]=v; patched=v; }
            else delete v;
        }
    }
    if(!patched){ brFail(path,"buildPatched",(long long)buf.size()); return real; }
    { static std::unordered_set<std::string> dlogged; std::lock_guard<std::mutex> lk(gVAMutex);
      if(dlogged.insert(kpath).second){ char b[300];
        snprintf(b,sizeof(b),"[BC] BR-DONE path='%s' realSize=%d patchedSize=%zu",
                 kpath.c_str(),len,patched->size()); diagNote(b); } }
    VirtualAsset* va=nullptr;
    {
        std::lock_guard<std::mutex> lk(gVAMutex);
        size_t bo=0,bl=0; findBlueRange(*patched,bo,bl);
        va=new VirtualAsset{patched->data(),patched->size(),0,kVAMagic,bo,bl};
        gVASet.insert(va); gVAActive.fetch_add(1,std::memory_order_release);
        static std::unordered_set<std::string> logged;
        if(logged.insert(kpath).second){
            char b[300]; uint32_t oldc=0,newc=0;
            std::memcpy(&oldc,buf.data()+8,4); std::memcpy(&newc,patched->data()+8,4);
            snprintf(b,sizeof(b),"[BC] AASSET-PATCHED path='%s' realSize=%d patchedSize=%zu",
                     kpath.c_str(),len,patched->size(),oldc,newc);
            diagNote(b);
        }
    }
    return reinterpret_cast<void*>(va);
}
static int assetReadDetour(void* a,void* buf,size_t cnt){
    VirtualAsset* v=asVA(a);
    if(!v) return gOrigRead?gOrigRead(a,buf,cnt):-1;
    size_t avail=v->size>v->pos?v->size-v->pos:0;
    size_t n=cnt<avail?cnt:avail;
    size_t before=v->pos;
    if(n) std::memcpy(buf,v->data+v->pos,n);
    v->pos+=n; brDiag("read");
    { static int rc=0; if(rc<10){ rc++; char b[220];
      snprintf(b,sizeof(b),"[BC] BRARCHIVE-READ#%d off=%zu count=%zu got=%zu",rc,before,cnt,n);diagNote(b); } }
    if(v->blueLen && before < v->blueOff+v->blueLen && v->pos > v->blueOff)
        brBlueDiag("read",(long long)before,(long long)n);
    return (int)n;
}
static int assetLenDetour(void* a){
    VirtualAsset* v=asVA(a);
    if(!v) return gOrigLen?gOrigLen(a):0;
    brDiag("getLength"); return (int)v->size;
}
static int64_t assetLen64Detour(void* a){
    VirtualAsset* v=asVA(a);
    if(!v) return gOrigLen64?gOrigLen64(a):0;
    brDiag("getLength64"); return (int64_t)v->size;
}
static int64_t assetSeek64Detour(void* a,int64_t off,int whence){
    VirtualAsset* v=asVA(a);
    if(!v) return gOrigSeek64?gOrigSeek64(a,off,whence):-1;
    int64_t base=(whence==0)?0:((whence==1)?(int64_t)v->pos:(int64_t)v->size);
    int64_t np=base+off;
    if(np<0||np>(int64_t)v->size) return -1;
    v->pos=(size_t)np; brDiag("seek64");
    if(v->blueLen && np>=v->blueOff && np<=v->blueOff+v->blueLen)
        brBlueDiag("seek64",(long long)np,(long long)v->blueLen);
    return np;
}
static void assetCloseDetour(void* a){
    VirtualAsset* v=asVA(a);
    if(!v){ if(gOrigClose) gOrigClose(a); return; }
    brDiag("close");
    { std::lock_guard<std::mutex> lk(gVAMutex); gVASet.erase(v); }
    gVAActive.fetch_sub(1,std::memory_order_release);
    delete v;
}

// Json::Reader::parse overloads (statically linked in libminecraftpe.so)
using ParseCStrFn  = bool(*)(void*,const char*,size_t,void*,bool);
using ParseStrFn   = bool(*)(void*,const std::string&,void*,bool);

// I18n::get detour: answer our translation keys with "Blue Cube". Signature is
// std::string I18nImpl::get(I18nImpl* this [x0], const std::string& key [x1]);
// the AAPCS64 hidden return slot (x8) is handled by the compiler.
static I18nGet1 gOrigI18nGet=nullptr;
static I18nGetN gOrigI18nGetParams=nullptr;

// Read a 24-byte csl::basic_string into a std::string.
// VERIFIED from __init@0x88a6328: LONG (b[0]&1)==1 -> LEN at +8, DATA at +16;
// SSO (b[0]&1)==0 -> len=b[0]>>1, inline chars at +1. (88a6398: stp x19,x0,[x20,#8])
// This is called ONLY on trusted, in-process buffers: the i18n detour's own
// local CslStr (r.b) and the BlockLegacy real x8 sret. It must NOT depend on
// gReadableMem: that cache is populated lazily by findRecipes, so if the recipe
// path is skipped the name silently reverts to the raw "tile.blue_cube..." key.
static std::string cslToString(const void* p){
    if(!p) return {};
    const unsigned char* b=(const unsigned char*)p;
    if((b[0]&1)==0){ size_t n=b[0]>>1; if(n>22) return {}; return std::string((const char*)b+1,n); } // SSO
    const char* data=nullptr; size_t n=0;
    std::memcpy(&data,b+16,8); std::memcpy(&n,b+8,8);
    if(!data || n>1u<<20) return {};
    return std::string(data,n);
}
static bool isBlueCubeKey(const std::string& key){
    return key.find("blue_cube")!=std::string::npos; // any key mentioning our block
}
// Build "Blue Cube" into a 24-byte csl string using Bedrock's own string ctor.
static CslStr makeBlueCube(){
    CslStr r;
    CslStringInitFn init=(CslStringInitFn)pStringInit;
    init(r.b,"Blue Cube",9);
    return r;
}
// post-orig: call orig first, inspect the RESULT, replace only if it
// already contains "blue_cube". Offset-independent — no this pointers.
//
// Called from the i18n detours (result in our own local CslStr r.b — always a
// valid 24-byte stack buffer) and from blockLegacyNameDetour (real x8 sret,
// proven `mov x22,x8` at 0x10924fc0). It is NOT called from the Item name hook
// (that one is a pure pass-through: its incoming x8 is a stack canary).
// No readability guard here — the buffer is trusted in-process, and gating on
// lazy gReadableMem made the name silently revert to "tile.blue_cube...".
extern "C" __attribute__((used)) void postProcessNameC(void* sret){
    if(!sret) return;
    std::string s=cslToString(sret);
    if(s.find("blue_cube")!=std::string::npos){
        std::memset(sret,0,24);
        CslStringInitFn init=(CslStringInitFn)pStringInit;
        init(sret,"Blue Cube",9);                     // writes exactly 24 bytes in place
        static bool logged=false;
        if(!logged){ logged=true; __android_log_print(ANDROID_LOG_INFO,"BlueCube","BlueCube replaced name containing blue_cube"); }
    }
}
static CslStr i18nGetDetour(void* self,const void* key){
    // Primary: translate by KEY. For our block Bedrock asks for
    // "tile.blue_cube.blue_cube.name"; no language entry exists (native mod,
    // no resource pack), so return "Blue Cube" directly. This is authoritative
    // and does not depend on what the original returns or on gReadableMem.
    if(key){
        std::string k=cslToString(key);
        if(k.find("blue_cube")!=std::string::npos){
            static bool logged=false;
            if(!logged){ logged=true; __android_log_print(ANDROID_LOG_INFO,"BlueCube","BlueCube i18n key match -> Blue Cube"); }
            return makeBlueCube();
        }
    }
    CslStr r = gOrigI18nGet ? gOrigI18nGet(self,key) : CslStr();
    postProcessNameC(r.b);
    return r;
}
static CslStr i18nGetParamsDetour(void* self,const void* key,uintptr_t a2,uintptr_t a3){
    if(key){
        std::string k=cslToString(key);
        if(k.find("blue_cube")!=std::string::npos) return makeBlueCube();
    }
    CslStr r = gOrigI18nGetParams ? gOrigI18nGetParams(self,key,a2,a3) : CslStr();
    postProcessNameC(r.b);
    return r;
}

// ---- native virtual resource interception (lib-only, no pack, no TLS) ------
// ---- : direct ShadowHook on Item::buildDescriptionName (0x107914b4) -----
// Every helper/global referenced from the naked trampoline is extern "C" +
// used so its symbol name is unmangled and present in .dynsym (no dlopen error).
// AAPCS64: x0=this, x1..=args, x8=hidden sret csl::basic_string*.
extern "C" {
__attribute__((used)) void* gItemG=nullptr;          // our BlockItem (this comparison)
__attribute__((used)) void* mBlockG=nullptr;          // our BlockLegacy (this comparison)
// the REAL 0x1d0-byte BlockItem* (item) created in recreateBlockItem() right
// after registerBlock. 0x1076c580(ItemInstance*, const Item*, count) needs THIS,
// never mBlockG (BlockLegacy*). Kept separate from gItemG so the name hooks stay
// completely untouched.
__attribute__((used)) void* gActualBlockItem=nullptr;
// SharedPtr<Item> control block for blue_cube:blue_cube. ItemInstance+8 is a
// WeakPtr<Item> whose 8-byte pointer is THIS counter (Item* = *(void**)counter).
// Note +16 is mUserData (null), NOT a second half of the WeakPtr.
__attribute__((used)) void* gBlueCubeCounter=nullptr;
// live ItemRegistry pointer (set in creativeDetour) used to verify that
// recipe ingredient names resolve to non-null Item* before registering.
__attribute__((used)) void* gItemRegistryForRecipe=nullptr;
__attribute__((used)) void* gCreativeAddedRegistry=nullptr;  // avoid double-insert on world reload
__attribute__((used)) void* gOrigBuildDescG=nullptr; // trampoline to original
__attribute__((used)) void* gOrigBlockLegacyNameG=nullptr; // BlockLegacy original
__attribute__((used)) void buildDescImpl(void* sret){ // writes "Blue Cube" via csl ctor
    if(!sret) return;
    std::memset(sret,0,24);
    CslStringInitFn init=(CslStringInitFn)pStringInit;
    init(sret,"Blue Cube",9);
}
}
// POST-ORIG (Item::buildDescriptionName @0x107914b4): PURE PASS-THROUGH.
// This function returns void and writes its result into an INTERNAL local
// buffer (prologue overwrites x8 with `add x8,sp,#0x38` without ever saving the
// incoming value; callers load the stack canary into x8). There is NO caller
// result buffer to post-process — dereferencing any incoming register as a
// csl string previously crashed inventory rendering. The "Blue Cube" name is
// supplied by the i18n get hooks, so just forward the call untouched.
__attribute__((naked)) static void buildDescDetour(void*,void*,void*,void*){
    asm volatile(
        "stp x0, x1, [sp, #-48]!\n"   // save incoming args
        "stp x2, x3, [sp, #16]\n"
        "str x30, [sp, #32]\n"        // save LR
        "adr x16, gOrigBuildDescG\n"
        "ldr x16, [x16]\n"
        "blr x16\n"                   // orig builds the description
        "ldr x30, [sp, #32]\n"        // restore LR
        "add sp, sp, #48\n"
        "ret\n"
        :::"memory");
}

// ---- : BlockLegacy::buildDescriptionName (0x10924fa4) post-orig ---------
__attribute__((naked)) static void blockLegacyNameDetour(void*,void*,void*,void*){
    asm volatile(
        "stp x0, x1, [sp, #-48]!\n"
        "stp x2, x3, [sp, #16]\n"
        "stp x8, x30, [sp, #32]\n"
        "adr x16, gOrigBlockLegacyNameG\n"
        "ldr x16, [x16]\n"
        "blr x16\n"
        "ldr x0, [sp, #32]\n"
        "bl postProcessNameC\n"
        "ldr x30, [sp, #40]\n"
        "add sp, sp, #48\n"
        "ret\n"
        :::"memory");
}

// ---- : Survival shaped recipe via 0x1040f840 wrapper ---------------------
// Vanilla caller disasm (0x10408250) shows arguments: x0=Recipes*, x1=recipeId
// csl::string, x2=result ItemInstance*, x3=pattern vector<string>, x4=key vector,
// x5=void*, w6=priority, x7=tag object, stack=(string_view,bool).
// Key entries are built with Bedrock constructor 0x107ae7d0 which sets a valid
// shared_ptr control-block vtable ([out]=0x13d9b360) AND an ItemDescriptor with
// vtable 0x139dac00 at [out+8] — never raw calloc-zeroed buffers.
using RecipeWrapperFn=bool(*)(void*,void*,void*,void*,void*,void*,int,void*,uint64_t,uint64_t,uint64_t);
// Low-level Recipes::addShapedRecipe at 0x1040e50c. x2 is a std::vector<ItemInstance>
// (begin/end/cap), x7 is the raw RecipeUnlockingRequirement (self-initializes when
// [x7+32]==null), x5=craftingTags, w6=priority. No wrapper factory -> no dead ABI.
// 0x1076d3b8(out, nameData, nameLen, w3=1, w4=0, x5=0) is the FULL
// 128-byte ItemInstance-from-name ctor used 9x by the vanilla recipe caller
// (0x103e10a4 etc). It does the ItemRegistry lookup and populates BOTH mItem
// (WeakPtr<Item>) and mBlock (const Block*) — unlike 0x1076c580 which treated
// its x1 as an ItemInstance source (passing gActualBlockItem there in  left
// mBlock null) and unlike 's 24-byte 0x107ae700 descriptor (x2 OOB reads).
using ItemInstNameCtor=void(*)(void*,const char*,size_t,int,int,void*);
using RecipesTypeCtor= void(*)(void*,const char*,size_t,int,int);
// low-level Recipes::addShapedRecipe 0x1040e50c. Its ABI (from the
// wrapper 0x1040f938-970) is: x0=Recipes*, x1=recipeId csl string,
// x2=result ItemInstance*, x3=pattern vector, x4=key vector, x5=craftingTags,
// w6=priority, x7=RAW RecipeUnlockingRequirement*, stack[0]=(ptr,len),
// stack[16]=bool. When [x7+32]==null it SELF-INITIALIZES the requirement to an
// empty/AlwaysUnlocked state (0x1040ef38-64: vtable 0x13d71288@+0, self@+32).
// Calling this directly with a fresh zeroed 64-byte requirement avoids the
// moved-from factory x7 that the wrapper 0x1040f840 builds via vfunc+24.
// Item::getBlockLegacy() (Item+0x138=312, 0x107a087c) and
// Item::getBlock(aux) (0x10921a84) — the game's own path that fills
// ItemInstance.mBlock@+24 for items with id > 255 (e.g. our block id 4096).
using ItemGetBlockLegacyFn=void*(*)(void*);
using ItemGetBlockFn=void*(*)(void*,int);
// REAL block ItemInstance builder 0x10772d54(this, Item* x1, aux w2,
// count w3, userdata x4, flag w5). It resolves the Block via Item+0x138 and
// 0x10921a84, stores it at +24, then 0x10772f38 fills WeakPtr@+8, count@+34,
// aux@+32 and mValid. This is the constructor Bedrock itself uses (called by
// 0x1076d3e4) — calling it directly with gActualBlockItem makes every field
// valid without any manual poking.
using ItemInstInitFn=void(*)(void*,void*,int,int,void*,int);

// A real Bedrock Item* has its vtable pointer at +0, located inside
// libminecraftpe.so's .data.rel.ro (vaddr 0x13700000..0x14000000). A
// SharedCounter/control block has a heap pointer at +0 and FAILS this check.
static bool validItemPtr(void* item){
    if(!item) return false;
    uintptr_t vt=*(uintptr_t*)item;
    uintptr_t lo=gBase+off::DATA_REL_RO_LO, hi=gBase+off::DATA_REL_RO_HI;
    return vt>=lo && vt<hi;
}

// FIX: 0x1039c800 sret is an 8-byte SharedCounter* at +0. The Item* is
// *counter — proven by 0x1039c844 (ldr x0,[x22]; getItemId) and the game's own
// 0x1076d490 (ldr x1,[x26] where x26=[sret+0]). sret+8 is NOT part of the sret
// and reading it returns uninitialized stack memory. Only dereference counter.
struct WeakPtrRaw { void* counter; void* reserved; };
static void* registryGetItem(const char* name,int* outIdOut){
    if(!gItemRegistryForRecipe) return nullptr;
    int outId=0, local=0; WeakPtrRaw wp{};   // zero-initialized sret
    gGetItemTarget=(void*)pRegisterItemWrapper;
    gGetItemOut=&wp;
    call_get_item_tramp(gItemRegistryForRecipe,&outId,&local,name,std::strlen(name));
    void* item = wp.counter ? *(void**)wp.counter : nullptr;   // Item* = *counter
    if(!validItemPtr(item)) item=nullptr;                       // .data.rel.ro vtable guard
    if(validItemPtr(item) && wp.counter && std::strcmp(name,"blue_cube:blue_cube")==0)
        gBlueCubeCounter=wp.counter;            // prefer the registry's real counter
    if(outIdOut) *outIdOut=outId;
    if(gLog) gLog->info("BlueCube registry {}: counter=0x{:x} item=0x{:x} vtOK={} id={}",
                        name,(unsigned long)wp.counter,(unsigned long)item,validItemPtr(item),outId);
    return item;
}
static RecipeWrapperFn gOrigRecipeWrapper=nullptr;
static void* gRecipeHook=nullptr;
static void* gSavedRecipeMgr=nullptr;     // long-lived Recipes* from the live wrapper call
// OWNED deep copy of a real craftingTags vector (see recipeWrapperDetour).
// addShapedRecipe requires it non-empty with valid 0x28-byte tag objects
// (+0 pointer, +8 NDK std::string); the previous pointer-capture went stale
// (diag: readable=0, SKIP -> recipe never registered). Up to 8 tags are copied
// with the game's own string helpers into this static storage so the copy owns
// its heap buffer and survives the vanilla caller's frame.
static uint8_t gCraftingTagStorage[8][0x28];
static void* gCraftingTagsVec[3]={nullptr,nullptr,nullptr};
static void* gCraftingTagsOwned[1]={nullptr};   // non-null once deep-copied
// Wrapper STACK args 0/1/2. The factory 0x10423290 dereferences stack0
// (x20 at 0x104233ac) and stack1 (x19 at 0x104233e4 -> ldr [x1],#8 at
// 0x104233ec) as pointers to {u32; vector<24B string>} / 24B-string structs.
// Passing 0 crashed (diag s1=0 -> deref 0). Provide OWNED zeroed buffers:
// an all-zero 24B string is a valid empty SSO string, and an all-zero vector
// (begin=end=cap=0) makes the copy loops run 0 iterations. No stale pointers.
static uint8_t gOwnedStackDesc[3][32]={0};
// NO cached call state. x5/x7/[sp] are locals in the vanilla caller's stack
// frame — caching them and replaying later dereferences a dead frame ( crash).
static bool gRecipeRegisteredThisWorld=false;
// 0x1040f840 may run for multiple Recipes* instances (Server/Client). Track
// distinct pointers and register once per instance. Only pointer values are
// cached (never the live x5/x7/stack slots).
static void* gRegisteredRecipeMgr[8]={nullptr,nullptr,nullptr,nullptr,nullptr,nullptr,nullptr,nullptr};
static int gRegisteredRecipeMgrCount=0;
static bool isRecipeMgrRegistered(void* mgr){
    for(int i=0;i<gRegisteredRecipeMgrCount && i<8;i++) if(gRegisteredRecipeMgr[i]==mgr) return true;
    return false;
}
static void markRecipeMgrRegistered(void* mgr){
    if(isRecipeMgrRegistered(mgr)||gRegisteredRecipeMgrCount>=8) return;
    gRegisteredRecipeMgr[gRegisteredRecipeMgrCount++]=mgr;
}

// ---- verified 128-byte ItemInstance layout (live Logcat capture) -----------
// q[0] +0   vtable (gBase+off::ITEMINSTANCE_VTABLE — data, not a function)
// q[1] +8   WeakPtr<Item> control block (Item* = *(void**)counter)  [8 bytes]
// q[2] +16  mUserData CompoundTag* = nullptr  (NOT part of the WeakPtr)
// q[3] +24  const Block* mBlock
// q[4] +32  uint16 aux(0) @+32, uint8 count(1) @+34, uint8 valid(1) @+35,
//           uint8 mShowPickup(1) @+36
// q[5..15]  time_point / zero
static bool buildBlueCubeItemInstance(void* inst){
    if(!inst || !mBlockG) return false;
    // Resolve the registry-owned Item*; registryGetItem sets gBlueCubeCounter to
    // the REAL SharedPtr control block and returns Item* = *(void**)counter.
    int dummyId=0;
    void* regItem=gItemRegistryForRecipe ? registryGetItem("blue_cube:blue_cube",&dummyId) : nullptr;
    if(!regItem || !validItemPtr(regItem)) regItem=gActualBlockItem;
    if(!regItem || !validItemPtr(regItem)) return false;
    std::memset(inst,0,0x80);
    // Bedrock's OWN high-level ItemInstance ctor (0x1076d284) is what the
    // data-driven creative path calls at 0x107eb838. It zeros all 128 bytes,
    // calls 0x10772d54 with w5=1, refcount incref, Block* resolution and writes
    // the final vtable 0x13d93420 itself — no manual struct field pokes.
    using ItemInstCtorFn2=void(*)(void*,void*,int,int,void*);
    ((ItemInstCtorFn2)pItemInstCtor)(inst,regItem,1,0,nullptr);   // out,Item*,count=1,aux=0,x4=null
    void* counter=*(void**)((char*)inst+8);
    // Match what CreativeItemRegistry actually checks (0x107ebb20 getItem:
    // counter@+8 non-null and *counter non-null; 0x1079ef0c category byte).
    // Do NOT require *counter == regItem — Bedrock may resolve a different
    // but equivalent Item* (registry alias) and that over-strict check was
    // rejecting valid instances (creative added=0).
    void* itemFromCounter=counter?*(void**)counter:nullptr;
    bool ok = *(void**)inst==(void*)(gBase+off::ITEMINSTANCE_VTABLE) &&
              counter && itemFromCounter && validItemPtr(itemFromCounter) &&
              *(void**)((char*)inst+24)!=nullptr &&
              *(unsigned char*)((char*)inst+34)==1 &&
              *(unsigned char*)((char*)inst+35)==1;
    if(!ok) __android_log_print(ANDROID_LOG_WARN,"BlueCube",
        "native ItemInstance ctor check failed: vt=0x%llx cnt=0x%llx item=0x%llx want=0x%llx block=0x%llx",
        (unsigned long long)*(void**)inst,(unsigned long long)counter,
        (unsigned long long)itemFromCounter,(unsigned long long)regItem,
        (unsigned long long)*(void**)((char*)inst+24));
    return ok;
}


// Self-contained fake SBO std::function shell for the recipe factory (x7).
// The wrapper's inline path (0x1040f91c) calls vt[3](this,x1=out) to zero the
// 64-byte unlocking requirement, which 0x1040ef38 then self-initializes to
// AlwaysUnlocked. No capture copy, no double-free, no bad_function_call.
static void makeFakeX7(uint8_t out[48],void** fakeVtableOut){
    std::memset(out,0,48);
    static void* fakeVtable[8]={nullptr,nullptr,nullptr,
        (void*)&fakeReqInvokeStub,   // vt[3] +24: invoke -> zero requirement
        (void*)&fakeReqNoopStub,     // vt[4] +32: destroy
        (void*)&fakeReqNoopStub,     // vt[5] +40: destroy_deallocate
        nullptr,nullptr};
    *(void**)out=(void*)fakeVtable;          // inline callable vtable at +0
    *(void**)(out+32)=(void*)out;            // f == x7 -> SBO branch
    if(fakeVtableOut) *fakeVtableOut=fakeVtable;
}

// ---- inventory-open UI marker hook ---------------------------------------
// CraftingScreenController screen creator (0x8a812a4) fires exactly when the
// player opens Inventory / Crafting Table. We only log + pass through.
//
// CRITICAL ABI: 0x8a812a4 returns a std::shared_ptr<Screen> (16 bytes) via the
// AAPCS64 hidden-return register x8 (sret). Proven by:
//   8a812e4: mov x22, x8          ; save indirect-result pointer
//   8a8131c: stp x23, x22, [sp]   ; forward it to the ctor helper
//   8a81504: stp xzr, xzr, [x22]  ; write null result on the failure path
// A `void` detour drops x8 and never fills the caller's result buffer, so the
// caller dereferences an uninitialized shared_ptr -> instant crash right after
// the creator returns (matches diag: OPEN -> RETURNED -> crash). Mirror the
// CslStr/i18n pattern: return a NON-TRIVIAL 16-byte struct so the compiler
// emits the x8 hidden return and forwards the real result to the caller.
struct ScreenPtr {
    void* obj; void* ctrl;
    ScreenPtr() : obj(nullptr), ctrl(nullptr) {}
    ScreenPtr(const ScreenPtr& o) : obj(o.obj), ctrl(o.ctrl) {} // non-trivial => x8 sret
};
using ScreenCreatorFn=ScreenPtr(*)(void*,void*,void*,void*,void*,uint64_t);
static ScreenCreatorFn gOrigScreenCreator=nullptr;
static void* gScreenCreatorHook=nullptr;
static uintptr_t gScreenCreatorTargetAddr=0;   // resolved pScreenCreator (for diagnostics)
// Caller-provided sret buffer (x8) captured at detour entry. Screen creation is
// single-threaded (UI thread); captured then read immediately, so no race.
extern "C" void* gScreenCreatorSretCapture=nullptr;
// C++ worker: ABI-correct x8 sret forwarding (returns non-trivial ScreenPtr).
// Emits the unambiguous SCREEN_CREATOR bracket so a run can be attributed and
// the exact orig-call boundary / returned shared_ptr are visible.
extern "C" __attribute__((used))
ScreenPtr screenCreatorDetourCpp(void* a0,void* a1,void* a2,void* a3,void* a4,uint64_t a5){
    void* sret=gScreenCreatorSretCapture;
    invStep("[BlueCube] SCREEN_CREATOR ENTER sret=%llx target=%llx",
            (unsigned long long)sret,(unsigned long long)gScreenCreatorTargetAddr);
    diagWriteEager("screen_creator_enter");
    invStep("[BlueCube] SCREEN_CREATOR orig call START orig=%llx",
            (unsigned long long)gOrigScreenCreator);
    ScreenPtr r = gOrigScreenCreator ? gOrigScreenCreator(a0,a1,a2,a3,a4,a5) : ScreenPtr();
    invStep("[BlueCube] SCREEN_CREATOR orig call END");
    invStep("[BlueCube] SCREEN_CREATOR RETURN obj=%llx ctrl=%llx sret=%llx",
            (unsigned long long)r.obj,(unsigned long long)r.ctrl,(unsigned long long)sret);
    diagWriteEager("screen_creator_return");
    return r;
}
// Naked hook entry: capture x8 (sret buffer) WITHOUT clobbering it, then tail-
// jump to the C++ worker with ALL registers (x0..x8, x30) intact. The worker's
// non-trivial ScreenPtr return makes the compiler forward x8 to the original,
// so the shared_ptr is written into the caller-provided result buffer.
extern "C" __attribute__((naked,used)) void screenCreatorDetour(){
    __asm__ volatile(
        "adrp x16, gScreenCreatorSretCapture\n"
        "str x8, [x16, #:lo12:gScreenCreatorSretCapture]\n"
        "b screenCreatorDetourCpp\n"
    );
}
// NOTE: the former "cleanup" hook at 0x8a81460 was REMOVED. Disassembly proves
// 0x8a81460 is an INTERNAL basic block of 0x8a812a4, not a function:
//   8a81460: stp x23, x22, [x29, #-24]  ; writes into the ENCLOSING frame
//   8a81468: ldr x22, [sp, #8]          ; reloads the creator's saved sret
//   8a81534: ret                        ; shares the creator's epilogue
// It is reached only via intra-function branches (cbnz x0, 8a81460). Hooking it
// as a function corrupts the live frame/registers. The creator RETURNED marker
// above already tells us the creator completed; no separate block hook is safe.

// applyRecipe is invoked FROM INSIDE a live recipeWrapperDetour frame. Every
// pointer owned by the vanilla caller's frame (x0/x5/x7/stack) is passed in by
// value from that SAME live call, so it is 100% valid during the replay.
static bool applyRecipe(void* liveX0,void* liveX2,void* liveX4,void* liveX5,
                        int liveW6,void* liveX7,uint64_t liveStack0,uint64_t liveStack1,uint64_t liveStack2){
    (void)liveX2; (void)liveX4;
    bool ok=false;
    void* resultSrc=nullptr; void* pat=nullptr; void* keys=nullptr;
    void* patVec[3]={nullptr,nullptr,nullptr}; void* keyVec[3]={nullptr,nullptr,nullptr};
    size_t recipesBefore=0, recipesAfter=0;
    std::string nativeRecId("blue_cube:blue_cube");
    invStep("[BlueCube] INV: applyRecipe BEGIN mgr=%llx",(unsigned long long)liveX0);
    // Log EVERY sub-condition of the early guard so the exact failing state is
    // visible in logcat + bluecube_diag.txt.
    invStep("[BlueCube] INV: guard mgr=%llx orig=%llx x7=%llx mBlockG=%llx",
            (unsigned long long)(liveX0!=nullptr),(unsigned long long)(gOrigRecipeWrapper!=nullptr),
            (unsigned long long)(liveX7!=nullptr),(unsigned long long)(mBlockG!=nullptr));
    invStep("[BlueCube] INV: guard counter=%llx item=%llx registry=%llx itemEqBlock=%llx",
            (unsigned long long)(gBlueCubeCounter!=nullptr),(unsigned long long)(gActualBlockItem!=nullptr),
            (unsigned long long)(gItemRegistryForRecipe!=nullptr),
            (unsigned long long)(gActualBlockItem==mBlockG));
    if(!gOrigRecipeWrapper || !liveX7 || !mBlockG || !gBlueCubeCounter ||
       !gActualBlockItem){
        invStep("[BlueCube] INV: applyRecipe EARLY-GUARD FAIL (missing ptr)");
        return false;
    }

    CslStringInitFn init=(CslStringInitFn)pStringInit;

    // x2: the wrapper takes a SINGLE 128-byte ItemInstance (it copies it into
    // its own heap buffer and builds the 1-element vector itself at
    // 0x1040f888..0x1040f8c8). Pass resultSrc, NOT a vector header.
    resultSrc=calloc(1,0x80); if(!resultSrc) goto recipe_fail;
    if(!buildBlueCubeItemInstance(resultSrc)){
        if(gLog) gLog->info("BlueCube result ItemInstance build FAILED");
        goto recipe_fail;
    }
    invStep("[BlueCube] INV: result ItemInstance built");
    diagWriteEager("recipe_after_result");
    __android_log_print(ANDROID_LOG_INFO,"BlueCube",
        "result ItemInstance: vt=0x%llx counter=0x%llx userData=0x%llx block=0x%llx cnt=%d valid=%d",
        (unsigned long long)*(void**)resultSrc,
        (unsigned long long)*(void**)((char*)resultSrc+8),
        (unsigned long long)*(void**)((char*)resultSrc+16),
        (unsigned long long)*(void**)((char*)resultSrc+24),
        (int)*(unsigned char*)((char*)resultSrc+34),
        (int)*(unsigned char*)((char*)resultSrc+35));

    // x3: pattern rows "AAA"/"ABA"/"AAA", 3 x 24-byte csl strings, end=+72.
    pat=calloc(3,24); if(!pat) goto recipe_fail;
    init((char*)pat+0,"AAA",3); init((char*)pat+24,"ABA",3); init((char*)pat+48,"AAA",3);
    patVec[0]=pat; patVec[1]=(char*)pat+72; patVec[2]=(char*)pat+72;

    // x4: 2 x 48-byte Recipes::Type keys, end=begin+96. WORLD-LOAD SAFETY:
    // DeferredDescriptor::getItem() (0x107b081c) returns NULL + 0x7fff. If such
    // a key reaches CraftingDataPacket serialization at 10-30% world load, the
    // serializer can dereference a null Item* and fault. Therefore require
    // RESOLVED Item* for both ingredients (0x1040eb94 -> 0x107ae768 builds a
    // valid InternalItemDescriptor with a real Item*). If the ItemRegistry has
    // not resolved them yet, SKIP registration for this call — never insert a
    // deferred descriptor into a recipe that will be serialized.
    // 48-byte key entries; 0x1040e50c computes count=(end-begin)/48 and
    // strides by 0x30. Back it with extra zeroed capacity (16 entries) so
    // an accidental over-read can never reach a wild pointer. Only the
    // first two entries are exposed through the vector end pointer.
    keys=calloc(16,48); if(!keys) goto recipe_fail;
    {
        int dummy=0;
        void* orchidItem=gItemRegistryForRecipe?registryGetItem("minecraft:blue_orchid",&dummy):nullptr;
        void* stoneItem =gItemRegistryForRecipe?registryGetItem("minecraft:stone",&dummy):nullptr;
        if(validItemPtr(orchidItem)&&validItemPtr(stoneItem)){
            *(void**)keys=orchidItem;             // entry0 'A' resolved Item*
            *(void**)((char*)keys+48)=stoneItem;  // entry1 'B' resolved Item*
            invStep("[BlueCube] INV: ingredients RESOLVED orchid=%llx stone=%llx",
                    (unsigned long long)orchidItem,(unsigned long long)stoneItem);
        } else {
            // ItemRegistry not ready yet (first recipe call precedes creative
            // setup). Use Bedrock's OWN DeferredDescriptor ctor 0x107ae7d0 at
            // [entry+16]; the wrapper (0x1040eb94 -> 0x107acc84) resolves it
            // natively to a valid InternalItemDescriptor with aux=0x7fff
            // before registering, so the serialized recipe is fully valid.
            typedef void(*DescCtor)(void*,const char*,size_t,int,int);
            DescCtor dc=(DescCtor)pDescCtor;
            dc((char*)keys+16,"minecraft:blue_orchid",21,0x7fff,1);
            dc((char*)keys+48+16,"minecraft:stone",15,0x7fff,1);
            invStep("[BlueCube] INV: ingredients DEFERRED (registry not ready)");
        }
        diagWriteEager("recipe_after_ingredients");
    }
    ((volatile unsigned char*)keys)[40]=0x41;          // 'A' -> orchid
    ((volatile unsigned char*)keys)[48+40]=0x42;       // 'B' -> stone
    // end pointer deliberately +96 (2 logical keys x 48B). With the 768B
    // zeroed backing buffer this is safe under either count formula.
    keyVec[0]=keys; keyVec[1]=(char*)keys+96; keyVec[2]=(char*)keys+96;

    // liveX7 is a self-contained fake SBO std::function shell built by
    // recipeWrapperDetour (never the destroyed live factory). Its inline invoke
    // stub zeroes the 64-byte requirement, which 0x1040ef38 self-initializes to
    // AlwaysUnlocked. No capture copy, no double-free, no bad_function_call.
    invStep("[BlueCube] INV: before gOrigRecipeWrapper replay netIdBefore=%llx",
            (unsigned long long)(liveX0?*(unsigned*)((char*)liveX0+136):0));
    recipesBefore=liveX0?*(size_t*)((char*)liveX0+136):0;
    // x1 is a native NDK std::string; 0x1040f8d0 reads byte[0].
    ok=gOrigRecipeWrapper ? gOrigRecipeWrapper(liveX0,&nativeRecId,resultSrc,(void*)patVec,(void*)keyVec,
                          liveX5,liveW6,liveX7,liveStack0,liveStack1,liveStack2) : false;
    recipesAfter=liveX0?*(size_t*)((char*)liveX0+136):0;
    if(ok){
        __android_log_print(ANDROID_LOG_INFO,"BlueCube","[BlueCube] STEP: dumpRecipes BEGIN"); fflush(stdout);
        dumpRecipesSideBySide(liveX0);
        __android_log_print(ANDROID_LOG_INFO,"BlueCube","[BlueCube] STEP: dumpRecipes DONE"); fflush(stdout);
        // CRITICAL: the auto-assign in 0x10413230 only runs when [Recipes+40]
        // flag is set. On the deferred path this flag can be clear, leaving
        // our ShapedRecipe with netId 0 -> getRecipe(0) returns null ->
        // unchecked deref at 0x10823d74 crashes on inventory open. Allocate a
        // unique non-zero netId via Bedrock's native counter allocator and
        // write it directly into the recipe; then re-register so the netId
        // hash map contains the key.
        repairRecipeNetId(liveX0);
    }
    invStep("[BlueCube] INV: after wrapper ret=%llx before=%llx after=%llx",
            (unsigned long long)ok,(unsigned long long)recipesBefore,(unsigned long long)recipesAfter);
    diagWriteEager("recipe_after_wrapper");
    { char note[160]; snprintf(note,sizeof(note),
        "[BlueCube] STEP 4: recipe after wrapper ret=%d before=%zu after=%zu",
        (int)ok,recipesBefore,recipesAfter);
      diagNote(note); }
    goto recipe_cleanup;

recipe_fail:
    ok=false;
recipe_cleanup:
    free(resultSrc); free(pat); free(keys);
    return ok;
}

// Detect a vanilla 3x3 shaped recipe call (pattern vector holds 3 rows of len 3).
static bool is3x3Pattern(void* pv){
    if(!pv) return false;
    char* b=*(char**)pv; char* e=*(char**)((char*)pv+8);
    if(!b||!e||e<=b) return false;
    for(size_t esz : {(size_t)24,(size_t)32}){
        size_t n=(size_t)(e-b)/esz;
        if(n<3) continue;
        bool ok=true;
        for(int i=0;i<3;i++){
            const unsigned char* s=(const unsigned char*)(b+i*esz);
            size_t len=(s[0]&1)?*(const size_t*)(s+8):(s[0]>>1);
            if(len!=3){ ok=false; break; }
        }
        if(ok) return true;
    }
    return false;
}

// x5 is const std::vector<HashedString>& craftingTags — must be non-null and
// non-empty (a std::vector header: begin@+0, end@+8). Never capture a recipe
// with a null craftingTags vector (that caused the  null dereference).
static bool validCraftingTags(void* x5){
    if(!x5) return false;
    char* b=*(char**)x5; char* e=*(char**)((char*)x5+8);
    return b && e && e>b;
}

static bool recipeWrapperDetour(void* x0,void* x1,void* x2,void* x3,void* x4,void* x5,
                                int w6,void* x7,uint64_t stack0,uint64_t stack1,uint64_t stack2){
    static int sInvOnce=0;
    if(!sInvOnce){
        sInvOnce=1; gSavedRecipeMgr=x0;
        diagWriteEager("recipeWrapperDetour_FIRST");
        invStep("[BlueCube] INV: recipeWrapperDetour FIRST mgr=%llx stack0=%llx",
                (unsigned long long)x0,(unsigned long long)stack0);
    }
    // Deep-copy the REAL craftingTags from this live vanilla call into OWNED
    // static memory. Capturing only the vector pointer (previous build) left a
    // stale stack pointer at deferred-replay time (diag: readable=0, SKIP) —
    // the recipe never registered. Each tag is 0x28 bytes: +0 pointer, +8 a
    // 24-byte NDK std::string. We rebuild the string with the game's own
    // __init(const char*,len) then operator= from the live tag's string, so the
    // copy owns its heap buffer and survives the caller's frame.
    if(x5 && !gCraftingTagsOwned[0]){
        uint8_t* cb=(uint8_t*)*(void**)x5;
        uint8_t* ce=(uint8_t*)*(void**)((char*)x5+8);
        size_t nbytes=(size_t)(ce-cb);
        if(cb && ce && ce>cb && nbytes>=0x28 && nbytes<=0x28*8){
            collectReadableMem();   // populate heap/stack cache before validating
            if(readableMem((uintptr_t)cb,nbytes)){
                // Call the GAME'S OWN tag copy constructor 0x134ee534(out,src).
                // It does exactly what vanilla does: zeroes the 0x28-byte dest,
                // deep-copies the 24-byte std::string at +8 via its real copy
                // ctor 0xe831404, and copies the +0 pointer. Hand-rolling
                // __init/operator= previously corrupted the string -> crash in
                // recipe serialization (crash LR +0x104233ac). No guessing.
                using TagCopyFn=void(*)(void*,const void*);
                TagCopyFn tagCopy=(TagCopyFn)pTagCopy;
                int ntags=(int)(nbytes/0x28);
                for(int i=0;i<ntags;i++){
                    uint8_t* src=cb+(size_t)i*0x28;
                    uint8_t* dst=gCraftingTagStorage[i];
                    tagCopy(dst,src);              // real game copy ctor, owns its string
                }
                gCraftingTagsVec[0]=gCraftingTagStorage[0];
                gCraftingTagsVec[1]=gCraftingTagStorage[0]+(size_t)ntags*0x28;
                gCraftingTagsVec[2]=gCraftingTagsVec[1];
                gCraftingTagsOwned[0]=gCraftingTagsVec;  // mark captured
                invStep("[BlueCube] INV: deep-copied craftingTags ntags=%d begin=%llx end=%llx",
                        ntags,(unsigned long long)gCraftingTagsVec[0],(unsigned long long)gCraftingTagsVec[1]);
            }
        }
    }
    // Build a self-contained SBO std::function shell for x7. ZERO touching of
    // the live factory: the wrapper epilogue destroys x7 before it returns, so
    // any clone/alias of it is a UAF/double-free. Our fake has f = x7 (self) so
    // 0x1040f900 takes the inline branch (0x1040f91c) and calls our stub with
    // x1 = &requirement, zeroing all 64 bytes. 0x1040ef38 then self-initializes
    // AlwaysUnlocked because [requirement+32] == 0.
    alignas(16) uint8_t fakeX7[48]={0};
    makeFakeX7(fakeX7,nullptr);
    __android_log_print(ANDROID_LOG_INFO,"BlueCube",
        "[BlueCube] fake x7 shell: %p vt3=%p",(void*)fakeX7,(void*)fakeReqInvokeStub);
    // Let the vanilla recipe register completely untouched, first, every time.
    bool r=gOrigRecipeWrapper ? gOrigRecipeWrapper(x0,x1,x2,x3,x4,x5,w6,x7,stack0,stack1,stack2) : false;
    // SYNCHRONOUS registration: still inside the live 0x1040f840 frame. x0/x5/
    // w6/stack are valid; our replay uses the clean clone of x7 made above.
    // NOTE: we build our OWN pattern + keys inside applyRecipe — the live
    // recipe's pattern (x3) / tags (x5) shape is irrelevant. Gating on
    // is3x3Pattern(x3) && validCraftingTags(x5) blocked registration forever
    // when vanilla's first shaped recipe was not exactly 3x3 or had no tags.
    static int sCondLogged=0;
    if(!sCondLogged){
        sCondLogged=1;
        invStep("[BlueCube] INV: detour conds blocked=%llx block=%llx counter=%llx",
                (unsigned long long)isRecipeMgrRegistered(x0),(unsigned long long)(mBlockG!=nullptr),
                (unsigned long long)(gBlueCubeCounter!=nullptr));
        invStep("[BlueCube] INV: detour item=%llx actual!=block=%llx orig=%llx",
                (unsigned long long)(gActualBlockItem!=nullptr),
                (unsigned long long)(gActualBlockItem!=mBlockG),
                (unsigned long long)(gOrigRecipeWrapper!=nullptr));
    }
    // Only gate on the Recipes* manager and wrapper being available. All item/
    // block validity is re-checked inside applyRecipe (which logs EARLY-GUARD
    // if anything is wrong). The extra gActualBlockItem!=mBlockG check here
    // silently blocked applyRecipe on a valid live call.
    if(!isRecipeMgrRegistered(x0)){
        invStep("[BlueCube] INV: recipeWrapperDetour replay mgr=%llx",(unsigned long long)x0);
        bool rr=applyRecipe(x0,x2,x4,x5,w6,(void*)fakeX7,stack0,stack1,stack2);
        __android_log_print(ANDROID_LOG_INFO,"BlueCube",
            "[BlueCube] STEP 3b: applyRecipe returned %d",(int)rr); fflush(stdout);
        if(rr){
            markRecipeMgrRegistered(x0);
            gRecipeRegisteredThisWorld=true;
        }
    }
    return r;
}

// ---- : texture JSON injection via dedicated loader + parse-helper hooks --
// The two dedicated loaders set a thread-local flag; the Json::Reader::parse
// helpers (same ABI as libminecraftpe.so: char*/size_t and NDK std::string,
// which is what JsonCpp in this binary actually takes) inject our entries into
// the parsed JSON buffer only while that flag is set. No NDK std::string is
// ever passed to the game's csl::basic_string/Core::Path resource loader.
static LoaderFn  gOrigBlocksLoader=nullptr;
static LoaderFn  gOrigTerrainLoader=nullptr;
static ParseCStrFn gOrigParseCStr=nullptr;
static ParseStrFn  gOrigParseStr=nullptr;
static void* gBlocksLoaderHook=nullptr;
static void* gTerrainLoaderHook=nullptr;
static void* gParseCStrHook=nullptr;
static void* gParseStrHook=nullptr;
static thread_local bool tInBlocksLoader=false, tInTerrainLoader=false;
static std::atomic_bool gTexInjected{false}, gBlocksInjected{false};

// Insert a JSON object entry into the object that follows `anchor` (or the
// top-level object when anchor is empty). Uses ordinary std::string ONLY in
// our own process memory (we build a private buffer for JsonCpp, whose parse
// ABI is std::string) — never across the game's csl::basic_string ABI.
static bool injectJson(std::string& json,const char* anchor,const std::string& entry){
    size_t pos;
    if(anchor && *anchor){
        size_t a=json.find(anchor);
        if(a==std::string::npos) return false;
        pos=json.find('{',a+std::strlen(anchor));
    } else {
        pos=json.find('{');
    }
    if(pos==std::string::npos) return false;
    json.insert(pos+1,entry);
    return true;
}

// Dedicated loader detours: mark the thread, let vanilla load+parse run.
// blocks.json is loaded at the start of every world session — use it as
// the per-world lifecycle boundary. Reset ALL cached per-world state here so a
// rejoin performs a clean full registration even if the allocator reuses the
// exact same registry addresses.
static void blocksLoaderDetour(uintptr_t a0,uintptr_t a1){
    if(gResetForNewWorld) gResetForNewWorld();
    tInBlocksLoader=true;
    if(gOrigBlocksLoader) gOrigBlocksLoader(a0,a1);
    tInBlocksLoader=false;
}
static void terrainLoaderDetour(uintptr_t a0,uintptr_t a1){
    tInTerrainLoader=true;
    if(gOrigTerrainLoader) gOrigTerrainLoader(a0,a1);
    tInTerrainLoader=false;
}

// language translations injected at the DATA level. Bedrock's hotbar/
// inventory tooltip name is resolved through the language dictionary; injecting
// the key -> "Blue Cube" here works regardless of which I18n code path is used.
static const char* kLangEntries =
    "\"tile.blue_cube:blue_cube.name\":\"Blue Cube\","
    "\"item.blue_cube:blue_cube.name\":\"Blue Cube\","
    "\"block.blue_cube:blue_cube\":\"Blue Cube\",";
static bool looksLikeLanguageFile(std::string_view sv){
    // en_US.json (and every locale) is a flat object of "<key>":"<value>" pairs
    // containing vanilla translation keys like "tile.dirt.name"/"item.stick.name".
    return sv.find("\"tile.")!=std::string_view::npos ||
           sv.find("\"item.")!=std::string_view::npos;
}

// Json::Reader::parse(const char* begin, size_t len, Json::Value& root, bool)
// VERIFIED mangled: _ZN4Json6Reader5parseEPKcmRNS_5ValueEb @0x886e948
//   x0=self, x1=begin, x2=len, x3=root, w4=collectComments (5 args, exact).
// All doc checks are BOUNDED (len < 32 MiB); never assume NUL termination.
// Buffer is strictly LOCAL to each call (parsing is concurrent at startup).
// Add "textures/blocks/blue_cube.png" to a vanilla contents.json file index.
// Verified: both target contents.json files list EVERY blocks.brarchive entry
// as {"path": "textures/blocks/<name>"} in sorted order; adding only the
// brarchive entry is useless unless the pack's file index knows about it.
// Filter restricted to exactly the two packs whose archives we patch:
//   vanilla_1.26.60/contents.json (1295B, shelf_mushroom_large.png)
//   vanilla/contents.json (809075B)
// textures_list.json is NOT a loose APK file: it lives inside
// vanilla/__brarchive/textures.brarchive (94,920 B JSON list) and enumerates
// every atlas texture including "textures/blocks/obsidian". Offline proof:
// across all 1,325 loose APK JSONs AND all brarchive-internal JSON entries,
// the strict filter below matches EXACTLY ONE buffer (vanilla's 94,920 B list);
// vanilla_1.21.90's copy is 101,254 B and is excluded by the <100000 cap.
static bool spliceTextureList(std::string& j){
    if(j.size()<24||j.size()>=200000) return false;
    if(j.front()!='['||j.find("blue_cube")!=std::string::npos) return false;
    if(j.find("\"textures/blocks/obsidian\"")==std::string::npos) return false;
    const char* needle="\"textures/blocks/obsidian\"";
    size_t p=j.find(needle);
    if(p==std::string::npos) return false;
    j.insert(p,"\"textures/blocks/blue_cube\",");
    char z[200]; size_t st=p>60?p-60:0,n=j.size()-st; if(n>120)n=120;
    snprintf(z,sizeof(z),"[BC] SPLICE-TEXTLIST around='%.*s'",(int)n,j.data()+st);
    diagNote(z);
    return true;
}
static bool spliceContents(std::string& j,const char* tag){
    if(j.size()<64||j.find("blue_cube")!=std::string::npos) return false;
    if(j.find("\"content\"")==std::string::npos||j.find("\"path\"")==std::string::npos||
       j.find("\"textures/blocks/")==std::string::npos) return false;
    bool small=(j.find("textures/blocks/shelf_mushroom_large.png")!=std::string::npos && j.size()<2000);
    bool big=(j.size()>700000);
    if(!small && !big) return false;
    const char* pref="\"path\": \"textures/blocks/";
    size_t pfx=std::strlen(pref), vpfx=std::strlen("\"path\": \"");
    size_t p=0;
    while((p=j.find(pref,p))!=std::string::npos){
        size_t ns=p+vpfx, ne=j.find('"',ns);
        if(ne==std::string::npos||ne<=ns) return false;
        std::string nm=j.substr(ns,ne-ns), leaf=nm.substr(nm.rfind('/')+1);
        if(leaf>"blue_cube.png"){
            size_t br=j.rfind('{',p);
            if(br==std::string::npos) return false;
            size_t ls=j.rfind('\n',br); ls=(ls==std::string::npos)?0:ls+1;
            static const char ent[]="        {\r\n            \"path\": \"textures/blocks/blue_cube.png\"\r\n        },\r\n";
            j.insert(ls,ent);
            br=ls;
            char z[220];size_t st=br>60?br-60:0,n=j.size()-st;if(n>120)n=120;
            snprintf(z,sizeof(z),"[BC] SPLICE-CONTENTS around='%.*s'",(int)n,j.data()+st);
            diagNote(z);
            return true;
        }
        p=ne;
    }
    return false;
}
static bool parseCStrDetour(void* reader,const char* data,size_t len,void* value,bool strict){
    if(data && len>24 && len<33554432u){
        std::string_view doc(data,len);
        // per-buffer guard only: skip only if THIS buffer already has our key
        bool hasOur = doc.find("blue_cube")!=std::string_view::npos;
        if(!hasOur){
            const char* at=nullptr; const char* entry=nullptr; size_t elen=0; bool isTerrain=false;
            const char* t1="\"obsidian\":";        // terrain_texture.json (WITH colon)
            const char* t2="\"obsidian\":";        // blocks.json (WITH colon)
            const bool noSet = doc.find("minecraft:texture_set")==std::string_view::npos;
            const bool noOur = doc.find("blue_cube")==std::string_view::npos;
            if(noSet && noOur && doc.find("texture_data")!=std::string_view::npos &&
               doc.find("\"obsidian\":")!=std::string_view::npos){
                at=(const char*)memFind(data,len,t1,10);
                if(at){ entry="\"blue_cube\":{\"textures\":\"textures/blocks/blue_cube\"},"; elen=std::strlen(entry); isTerrain=true; }
            } else if(noSet && noOur && doc.find("\"format_version\"")!=std::string_view::npos &&
               doc.find("\"air\"")!=std::string_view::npos && doc.find("\"stone\"")!=std::string_view::npos &&
               doc.find("\"textures\"")!=std::string_view::npos && doc.find("\"obsidian\":")!=std::string_view::npos &&
               doc.find("texture_data")==std::string_view::npos &&
               doc.find("block_sounds")==std::string_view::npos){
                at=(const char*)memFind(data,len,t2,10);
                if(at){ entry="\"blue_cube:blue_cube\":{\"textures\":\"blue_cube\",\"sound\":\"stone\"},"; elen=std::strlen(entry); }
            }
            if(at && entry){
                std::string patched;                       // LOCAL, alive through original call
                patched.reserve(len+elen+8);
                patched.assign(data,(size_t)(at-data));
                patched.append(entry,elen);
                patched.append(at,len-(size_t)(at-data));
                { const char* q=std::strstr(patched.data(),"blue_cube");
                  if(q){ const char* b=patched.data(); size_t off=(size_t)(q-b), st=off>60?off-60:0;
                    size_t n=patched.size()-st; if(n>120)n=120; char z[200];
                    snprintf(z,sizeof(z),"[BC] SPLICE-%s around='%.*s'",
                        isTerrain?"TERRAIN":"BLOCKS",(int)n,b+st); diagNote(z); }
                  if(isTerrain) gTerrainSpliced.store(true,std::memory_order_release); }
                return gOrigParseCStr ? gOrigParseCStr(reader,patched.data(),patched.size(),value,strict) : false;
            }
        }
    }
    { std::string lbuf(data,len);
      if(spliceTextureList(lbuf)){
        return gOrigParseCStr ? gOrigParseCStr(reader,lbuf.data(),lbuf.size(),value,strict) : false;
      } }
    { std::string cbuf(data,len);
      if(spliceContents(cbuf,"CS")){
        return gOrigParseCStr ? gOrigParseCStr(reader,cbuf.data(),cbuf.size(),value,strict) : false;
      } }
// Language files may also arrive via the char* parse overload.
    if(data && len>24 && looksLikeLanguageFile(std::string_view(data,len)) &&
       std::string_view(data,len).find("blue_cube.name")==std::string_view::npos){
        std::string buf;
        buf.assign(data,len);
        if(injectJson(buf,nullptr,kLangEntries)){
            bool r=gOrigParseCStr(reader,buf.data(),buf.size(),value,strict);
            if(gLog) gLog->info("BlueCube injected language translations (char*)");
            return r;
        }
    }
    return gOrigParseCStr ? gOrigParseCStr(reader,data,len,value,strict) : false;
}

// Json::Reader::parse(const std::string&, Json::Value&, bool) — used by the
// blocks.json loader.
static bool parseStrDetour(void* reader,const std::string& data,void* value,bool strict){
    // blocks.json (std::string overload): insert our binding before "obsidian":
    { if(data.size()>24 && data.size()<33554432u &&
         data.find("format_version")!=std::string::npos &&
         data.find("\"air\"")!=std::string::npos && data.find("\"stone\"")!=std::string::npos &&
         data.find("\"textures\"")!=std::string::npos && data.find("\"obsidian\":")!=std::string::npos &&
         data.find("minecraft:texture_set")==std::string::npos &&
         data.find("texture_data")==std::string::npos &&
         data.find("block_sounds")==std::string::npos &&
         data.find("blue_cube")==std::string::npos){
        const char* at=nullptr; size_t dl=data.size();
        const char* raw=data.data();
        for(size_t i=0;i+10<=dl;i++) if(std::memcmp(raw+i,"\"obsidian\":",10)==0){ at=raw+i; break; }
        if(at){
            static const char ent[]="\"blue_cube:blue_cube\":{\"textures\":\"blue_cube\",\"sound\":\"stone\"},";
            std::string patched;                       // strictly local
            patched.reserve(dl+sizeof(ent)+8);
            patched.assign(raw,(size_t)(at-raw));
            patched.append(ent,sizeof(ent)-1);
            patched.append(at,dl-(size_t)(at-raw));
            { const char* q=std::strstr(patched.data(),"blue_cube");
              if(q){ const char* b=patched.data(); size_t off=(size_t)(q-b), st=off>60?off-60:0;
                size_t n=patched.size()-st; if(n>120)n=120; char z[200];
                snprintf(z,sizeof(z),"[BC] SPLICE-BLOCKS around='%.*s'",(int)n,b+st); diagNote(z); } }
            return gOrigParseStr ? gOrigParseStr(reader,patched,value,strict) : false;
        }
      }
    }
    { std::string lbuf(data);
      if(spliceTextureList(lbuf)){
        return gOrigParseStr ? gOrigParseStr(reader,lbuf,value,strict) : false;
      } }
    { std::string cbuf(data);
      if(spliceContents(cbuf,"ST")){
        return gOrigParseStr ? gOrigParseStr(reader,cbuf,value,strict) : false;
      } }
    // language file (en_US.json etc.) — inject our translation entries.
    if(data.size()>24 &&
       looksLikeLanguageFile(std::string_view(data)) &&
       data.find("blue_cube.name")==std::string::npos){
        thread_local std::string buf;
        buf=data;
        if(injectJson(buf,nullptr,kLangEntries)){
            bool r=gOrigParseStr(reader,buf,value,strict);
            if(gLog) gLog->info("BlueCube injected language translations (str)");
            return r;
        }
    }
    return gOrigParseStr ? gOrigParseStr(reader,data,value,strict) : false;
}

class FinalMod {
public:
    bool load(pl::mod::ModContext& ctx) {
        gInstance=this; mLog=&ctx.logger(); gLog=mLog; gModInstance=this;
        gResetForNewWorld=[](){ if(gInstance) gInstance->resetForNewWorld(); };
        mLog->info("=== BlueCube native mod (guarded world entry + step logs) ===");
        dl_iterate_phdr(find_base,nullptr);
        mLog->info("base=0x{:x} size=0x{:x}",(unsigned long)gBase,(unsigned long)gModuleSize);
        collectRxRanges();          // map actual r-x ranges; never scan guard pages
        collectReadableRanges();    // cache readable ranges for pointer guards
        collectReadableMem();       // heap cache for resource-read path guards (needed before pack load)
        resolveNativeBackend();     // wildcard signature scan -> native backend functions
        initDiagPath();
        diagBeginRun();             // truncate -> one clean single-build/single-run file
        __android_log_print(ANDROID_LOG_INFO,"BlueCube","BUILD FINGERPRINT: %s",kBuildFingerprint);
        mLog->info("BlueCube BUILD FINGERPRINT: {}",kBuildFingerprint);
        mLog->info("BlueCube diag path={}",gDiagPath);
        // Clean up the oversized crash log left by a previous build. No signal
        // handlers are installed by this mod (ART owns SIGSEGV on Android).
        (void)unlink("/sdcard/Android/data/org.levimc.launcher/files/bluecube_crash.txt");
        return true;
    }
    bool enable(pl::mod::ModContext&) {
        if(mWorker.joinable()) return true;
        mStop.store(false);
        mWorker=std::thread([this]{ deferredEnable(); });
        return true;
    }
    bool disable(pl::mod::ModContext&) {
        mStop.store(true);
        if(mWorker.joinable()) mWorker.join();
        if(gOrigRegBlock) bcUnhook(gOrigRegBlock);
        if(gOrigCreative) bcUnhook(gOrigCreative);
        if(gScreenCreatorHook) bcUnhook(gScreenCreatorHook);
        if(gOrigI18n)     bcUnhook(gOrigI18n);
        if(gOrigI18nParamsHook) bcUnhook(gOrigI18nParamsHook);
        if(gOrigBuildDescHook) bcUnhook(gOrigBuildDescHook);
        if(gOrigBlockLegacyNameHook) bcUnhook(gOrigBlockLegacyNameHook);
        if(gRecipeHook) bcUnhook(gRecipeHook);

        if(gBlocksLoaderHook) bcUnhook(gBlocksLoaderHook);
        if(gTerrainLoaderHook) bcUnhook(gTerrainLoaderHook);
        if(gParseCStrHook) bcUnhook(gParseCStrHook);
        if(gParseStrHook) bcUnhook(gParseStrHook);
        gOrigRegBlock=nullptr; gOrigCreative=nullptr; gOrigI18n=nullptr; gOrigI18nParamsHook=nullptr;
        gScreenCreatorHook=nullptr; gOrigScreenCreator=nullptr;
        gOrigBuildDescHook=nullptr; gOrigBuildDescG=nullptr;
        gOrigBlockLegacyNameHook=nullptr; gOrigBlockLegacyNameG=nullptr;
        gRecipeHook=nullptr; gOrigRecipeWrapper=nullptr;

        gBlocksLoaderHook=nullptr; gTerrainLoaderHook=nullptr; gParseCStrHook=nullptr; gParseStrHook=nullptr;
        return true;
    }
    bool unload(pl::mod::ModContext&) { return true; }

private:
    void deferredEnable() {
        for(int i=0;i<1800 && !mStop.load();++i){
            auto st=mApi.resolveExact126443();
            if(st){
                // SHARED mode coexists with LeviLauncher's in-process PreLoader;
                // UNIQUE mode's sh_linker_init() is blocked on Android 16 (errno=12).
                shadowhook_init(SHADOWHOOK_MODE_SHARED,false);

                // ---- WORKING HOOKS — UNTOUCHED ----
                void* orig=nullptr;
                gOrigRegBlock=bcHook((void*)pRegisterBlock,
                                 (void*)&FinalMod::regBlockDetour,(void**)&orig);
                gOrigFn=(RegBlockFn)orig;
                mLog->info("BlueCube regBlock @0x{:x}: handle=0x{:x} errno={} msg={}",
                           (unsigned long)pRegisterBlock,(unsigned long)gOrigRegBlock,
                           shadowhook_get_errno(),shadowhook_to_errmsg(shadowhook_get_errno()));
                void* target=mApi.bindings().addLooseCreativeItemsTarget;
                gOrigCreative=bcHook(target,(void*)&FinalMod::creativeDetour,(void**)&gOrigCreativeFn);
                // Inventory-open marker hook (CraftingScreenController creator).
                void* scOrig=nullptr;
                gScreenCreatorTargetAddr=(uintptr_t)pScreenCreator;
                gScreenCreatorSretCapture=nullptr;
                gScreenCreatorHook=bcHook((void*)pScreenCreator,
                    (void*)&screenCreatorDetour,(void**)&scOrig);
                gOrigScreenCreator=(ScreenCreatorFn)scOrig;
                invStep("[BlueCube] SCREEN_CREATOR hook installed target=%llx orig=%llx handle=%llx",
                        (unsigned long long)gScreenCreatorTargetAddr,
                        (unsigned long long)scOrig,(unsigned long long)gScreenCreatorHook);
                mLog->info("BlueCube creative @0x{:x}: handle=0x{:x} errno={} msg={}",
                           (unsigned long)target,(unsigned long)gOrigCreative,
                           shadowhook_get_errno(),shadowhook_to_errmsg(shadowhook_get_errno()));

                void* bdOrig=nullptr;
                gOrigBuildDescHook=bcHook((void*)pBuildDescName,(void*)&buildDescDetour,(void**)&bdOrig);
                gOrigBuildDescG=bdOrig; gItemG=gBlueCubeItem;
                void* blOrig=nullptr;
                gOrigBlockLegacyNameHook=bcHook((void*)pBlockLegacyDesc,(void*)&blockLegacyNameDetour,(void**)&blOrig);
                gOrigBlockLegacyNameG=blOrig;
                void* recipeOrig=nullptr;
                gRecipeHook=bcHook((void*)pAddShapedWrapper,(void*)&recipeWrapperDetour,(void**)&recipeOrig);
                gOrigRecipeWrapper=(RecipeWrapperFn)recipeOrig;
                void* i18nOrig=nullptr;
                gOrigI18n=bcHook((void*)pI18nGet,(void*)&i18nGetDetour,(void**)&i18nOrig);
                gOrigI18nGet=(I18nGet1)i18nOrig;
                void* i18nParamsOrig=nullptr;
                gOrigI18nParamsHook=bcHook((void*)pI18nGetParams,(void*)&i18nGetParamsDetour,(void**)&i18nParamsOrig);
                gOrigI18nGetParams=(I18nGetN)i18nParamsOrig;
                void* o=nullptr;
                gBlocksLoaderHook=bcHook((void*)pBlocksLoader,(void*)&blocksLoaderDetour,(void**)&o);
                gOrigBlocksLoader=(LoaderFn)o;
                o=nullptr;
                gTerrainLoaderHook=bcHook((void*)pTerrainLoader,(void*)&terrainLoaderDetour,(void**)&o);
                gOrigTerrainLoader=(LoaderFn)o;
                o=nullptr;
                gParseCStrHook=bcHook((void*)pJsonParseCStr,(void*)&parseCStrDetour,(void**)&o);
                gOrigParseCStr=(ParseCStrFn)o;
                o=nullptr;
                gParseStrHook=bcHook((void*)pJsonParseStr,(void*)&parseStrDetour,(void**)&o);
                gOrigParseStr=(ParseStrFn)o;
                void* handles[]={gOrigRegBlock,gOrigCreative,gScreenCreatorHook,gOrigBuildDescHook,
                    gOrigBlockLegacyNameHook,gRecipeHook,gOrigI18n,gOrigI18nParamsHook,
                    gBlocksLoaderHook,gTerrainLoaderHook,gParseCStrHook,gParseStrHook};
                int failCount=0;
                for(int i=0;i<12;i++) if(!handles[i]) failCount++;
                char tierBuf[96];
                if(failCount==0 && gTierCounts[TIER_PRELOADER]==12) strlcpy(tierBuf,"preloader",sizeof(tierBuf));
                else if(failCount==0 && gTierCounts[TIER_SHARED]==12) strlcpy(tierBuf,"shadowhook-shared",sizeof(tierBuf));
                else snprintf(tierBuf,sizeof(tierBuf),"mixed(s%d/p%d/t%d)",gTierCounts[TIER_SHARED],gTierCounts[TIER_PRELOADER],gTierCounts[TIER_TRAMPOLINE]);
                __android_log_print(ANDROID_LOG_INFO,"BlueCube","hook attach summary: %d/12 ok, %d FAILED (tier=%s)",12-failCount,failCount,tierBuf);
                mLog->info("BlueCube hook summary: {}/12 ok, {} failed, tier={}",12-failCount,failCount,tierBuf);
                char note[200];
                snprintf(note,sizeof(note),"hook attach summary: %d/12 ok, %d FAILED (tier=%s) build=%s",12-failCount,failCount,tierBuf,kBuildFingerprint);
                diagNote(note);

                void* apo=nullptr;
                if(pAssetOpen){ gAssetHooks[0]=bcHook((void*)pAssetOpen,(void*)&assetOpenDetour,(void**)&apo); gOrigOpen=(AssetOpenFn)apo; }
                apo=nullptr;
                if(pAssetLen){ gAssetHooks[1]=bcHook((void*)pAssetLen,(void*)&assetLenDetour,(void**)&apo); gOrigLen=(AssetLenFn)apo; }
                apo=nullptr;
                if(pAssetLen64){ gAssetHooks[2]=bcHook((void*)pAssetLen64,(void*)&assetLen64Detour,(void**)&apo); gOrigLen64=(AssetLen64Fn)apo; }
                apo=nullptr;
                if(pAssetRead){ gAssetHooks[3]=bcHook((void*)pAssetRead,(void*)&assetReadDetour,(void**)&apo); gOrigRead=(AssetReadFn)apo; }
                apo=nullptr;
                if(pAssetSeek64){ gAssetHooks[4]=bcHook((void*)pAssetSeek64,(void*)&assetSeek64Detour,(void**)&apo); gOrigSeek64=(AssetSeek64Fn)apo; }
                apo=nullptr;
                if(pAssetClose){ gAssetHooks[5]=bcHook((void*)pAssetClose,(void*)&assetCloseDetour,(void**)&apo); gOrigClose=(AssetCloseFn)apo; }
                char an[220];
                snprintf(an,sizeof(an),"[BC] ASSET-HOOKS %d/6 build=%s",
                    (int)(!!gAssetHooks[0])+(int)(!!gAssetHooks[1])+(int)(!!gAssetHooks[2])+
                    (int)(!!gAssetHooks[3])+(int)(!!gAssetHooks[4])+(int)(!!gAssetHooks[5]),kBuildFingerprint);
                diagNote(an);
                installResourcePack();
                return;
            }
            if(st.error!=Error::MinecraftModuleNotFound){ mLog->error("resolve: {}",errorString(st.error)); return; }
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }

    // registerBlock(reg=x0, HashedString*=x1, int* id=x2, Material*=x3)
    static void* regBlockDetour(void* reg,void* hs,int* id,void* mat){
        void* result = gOrigFn ? gOrigFn(reg,hs,id,mat) : nullptr;   // vanilla first
        FinalMod* self=gInstance;
        if(self && reg){
            // Per-world lifecycle: Bedrock destroys/recreates the registries on
            // every world exit/rejoin. A new registry pointer means a new world
            // session — clear stale cached pointers and re-register cleanly.
            if(reg != self->mBlockRegistry){
                self->onNewWorld(reg);
            }
            if(reg==self->mBlockRegistry && !self->mBlockRegisteredForWorld){
                self->mBlockRegisteredForWorld=true;
                self->registerBlue(reg,mat);
            }
        }
        return result;
    }

    // clear all per-world cached state. Called at the start of every
    // blocks.json load (world lifecycle boundary) so rejoins are always clean.
    void resetForNewWorld(){
        mBlockRegisteredForWorld=false;
        mItemRegistry=nullptr;
        mBlock=nullptr;
        gItem=nullptr; gItemCB=nullptr;       // drop stale BlockItem/control-block
        gItemG=nullptr; mBlockG=nullptr;      // clear name-hook targets per world
        gActualBlockItem=nullptr;             // drop stale BlockItem* (recipe)
        gItemRegistryForRecipe=nullptr;       // drop stale ItemRegistry ptr
        gRecipeRegisteredThisWorld=false;     // re-register recipe per world
        gCraftingTagsOwned[0]=nullptr;         // recapture+deepcopy live craftingTags next world
        gCraftingTagsVec[0]=gCraftingTagsVec[1]=gCraftingTagsVec[2]=nullptr;
        // clear tracked Recipes* instances (Server/Client) on new world.
        gRegisteredRecipeMgrCount=0;
        for(int i=0;i<8;i++) gRegisteredRecipeMgr[i]=nullptr;
        gTexInjected.store(false);            // allow JSON re-injection
        gBlocksInjected.store(false);
    }

    // Reset all per-world cached state when a fresh registry is observed.
    void onNewWorld(void* newReg){
        __android_log_print(ANDROID_LOG_INFO,"BlueCube","[BlueCube] STEP: onNewWorld BEGIN"); fflush(stdout);
        mLog->info("BlueCube onNewWorld: blockReg 0x{:x} -> 0x{:x} (clearing stale state)",
                   (unsigned long)mBlockRegistry,(unsigned long)newReg);
        mBlockRegistry=newReg;
        resetForNewWorld();
    }

    void registerBlue(void* liveReg,void* liveMat){
        __android_log_print(ANDROID_LOG_INFO,"BlueCube","[BlueCube] STEP: registerBlue BEGIN"); fflush(stdout);
        int id=kBlueCubeBlockId;
        std::string name="blue_cube:blue_cube";
        alignas(16) unsigned char hs[0x30]{};
        ((HashCtor)pHashedCtor)(hs,name);
        const char* cname=((HashGetStr)pHashedGetStr)(hs);
        void* blk= gOrigFn ? gOrigFn(liveReg,hs,&id,liveMat) : nullptr;
        mLog->info("BlueCube block: 0x{:x} id={} name={}",(unsigned long)blk,id,cname?cname:"?");
        __android_log_print(ANDROID_LOG_INFO,"BlueCube","[BlueCube] STEP: registerBlock done blk=0x%llx",(unsigned long long)blk); fflush(stdout);
        if(!blk) return;
        mBlock=blk;
        mBlockId=id;
        mBlockG=blk;              // BlockLegacy name hook matches this
        // BlockGraphics factory 0xab0532c reads [BlockType+0x200] (Block*) and
        // then [Block+0x12a] UNCHECKED. Our block from 0x989ef20 may not have
        // that Block* populated during world init, so calling it faults.
        // Guard: only call when the Block* pointer at +0x200 is non-null and
        // points into a readable game mapping. Otherwise Bedrock's missing-
        // graphics fallback ("missing_tile") handles rendering safely.
        if(pBlockGraphicsGet){
            void* blockPtr=*(void**)((char*)blk+0x200);
            if(blockPtr && readableInGame((uintptr_t)blockPtr,0x140)){
                using BGFn=void*(*)(void*,int);
                __android_log_print(ANDROID_LOG_INFO,"BlueCube","[BlueCube] STEP: BlockGraphics BEGIN"); fflush(stdout);
                void* bg=((BGFn)pBlockGraphicsGet)((void*)hs,id);
                __android_log_print(ANDROID_LOG_INFO,"BlueCube",
                    "[BlueCube] STEP: BlockGraphics done bg=0x%llx",(unsigned long long)bg); fflush(stdout);
            } else {
                __android_log_print(ANDROID_LOG_INFO,"BlueCube",
                    "[BlueCube] STEP: BlockGraphics SKIPPED (no valid Block* at +0x200)"); fflush(stdout);
            }
        }
        __android_log_print(ANDROID_LOG_INFO,"BlueCube","[BlueCube] STEP: recreateBlockItem BEGIN"); fflush(stdout);
        recreateBlockItem();
        __android_log_print(ANDROID_LOG_INFO,"BlueCube","[BlueCube] STEP: registerBlue DONE"); fflush(stdout);
    }

    // Build a fresh SharedPtr<BlockItem> with a valid control block, bound to
    // the current world's BlockLegacy. Safe to call again on world rejoin.
    void recreateBlockItem(){
        if(!mBlock) return;
        const char* cname="blue_cube:blue_cube";
        void* mem=malloc(0x1d0+16);
        if(!mem) return;
        mem=(void*)(((uintptr_t)mem+15)&~15UL);
        std::memset(mem,0,0x1d0);
        void* item=((BlockItemCtor)pBlockItemCtor)(mem,cname,(short)mBlockId,(void*)((char*)mBlock+0xc8));
        // Branch Graph A: 0x10816530 leaves Item+320 (creative category) and
        // Item+0x150 (group string) unset. The Recipe Book tab filter and the
        // Search row builder (0x107e9aa4) read BOTH unguarded. Set them with
        // Bedrock's own setters: category 1 = Construction, group "Blue Cube".
        if(item){
            // ONLY set Item::mCreativeCategory = 1 (Construction).
            // 0x1079d000: strb w1,[x0,#320]. Do NOT touch Item+0x150 or
            // BlockLegacy+0x110: both hold Bedrock-owned csl::string objects
            // (the BlockLegacy ctor 0x10920f8c initializes +0x110 via the csl
            // string helpers at 0xe831398/0xe8313b0). Any write corrupts them
            // and faults at 10-20% world load. The valid empty string Bedrock
            // created is sufficient for getCreativeGroup (0x1079d060).
            ((SetCreativeCategoryFn)pSetCreativeCategory)(item,1);
            __android_log_print(ANDROID_LOG_INFO,"BlueCube",
                "BlockItem UI: cat=%u set (group/legacy untouched)",
                (unsigned)*(unsigned char*)((char*)item+320));
        }
        void* cb=malloc(0x10);
        if(!cb) return;
        std::memset(cb,0,0x10);
        *(void**)cb=item;
        *(volatile int*)((char*)cb+8)=1;
        *(volatile int*)((char*)cb+12)=0;
        gItem=item; gItemCB=cb; gBlueCubeItem=item;
        gBlueCubeCounter=cb;   // our SharedPtr control block (Item* = *cb)
        gItemG=item; // direct buildDescriptionName hook matches this ptr
        gActualBlockItem=item; // real 0x1d0 BlockItem* for recipe ItemInstance ( != mBlockG )
        mLog->info("BlueCube BlockItem: item=0x{:x} cb=0x{:x}",
                   (unsigned long)item,(unsigned long)cb);
    }

    bool registerItemInRegistry(void* reg){
        if(!reg || !gItemCB) return false;
        uintptr_t b0=(uintptr_t)*(void**)((char*)reg+0x38);
        if(b0<0x10000) return false;
        int outId=0, local=0;
        void* outCB=nullptr;
        gGetItemTarget=(void*)pRegisterItemWrapper;
        gGetItemOut=&outCB;
        const char* name="blue_cube:blue_cube";
        call_get_item_tramp(reg,&outId,&local,name,std::strlen(name));
        mLog->info("BlueCube getItem(name): cb=0x{:x} id={}",(unsigned long)outCB,outId);
        // If getItem found blue_cube:blue_cube, 0x10816530 already registered it
        // in the ItemRegistry. Append a second SharedPtr here would CORRUPT the
        // vector at reg+0x38/+0x40 (duplicate entry, double free at world load).
        // Adopt the registry's real control block/Item and return immediately.
        if(outCB){
            void* realItem=*(void**)outCB;
            if(validItemPtr(realItem)){
                gBlueCubeCounter=outCB;
                gActualBlockItem=realItem;
                gItem=realItem; gItemG=realItem; gBlueCubeItem=realItem;
                mLog->info("BlueCube: already in ItemRegistry, adopted cb=0x{:x} item=0x{:x} (no duplicate)",
                           (unsigned long)outCB,(unsigned long)realItem);
            }
            return true;
        }
        void* cb=gItemCB;

        auto* begin=*(std::byte**)((char*)reg+0x38);
        auto* end  =*(std::byte**)((char*)reg+0x40);
        auto* cap  =*(std::byte**)((char*)reg+0x48);
        uintptr_t b=(uintptr_t)begin,e=(uintptr_t)end,c=(uintptr_t)cap;
        if(c && e>=b && c>=e && (c-e)<0x100000 && ((e-b)%8)==0){
            *(void**)end=cb;
            *(std::byte**)((char*)reg+0x40)=end+8;
            mLog->info("BlueCube inserted SharedPtr into ItemRegistry vector");
            return true;
        }
        mLog->info("BlueCube ItemRegistry vector full (begin=0x{:x} end=0x{:x} cap=0x{:x})",
                   (unsigned long)b,(unsigned long)e,(unsigned long)c);
        return false;
    }

    // assemble the embedded resource pack (blocks.json, terrain_texture.json,
    // blue_cube.png, en_US.lang) into an in-memory ZIP. The pack lives entirely
    // inside the .so; this builds the byte buffer that the game's
    // ResourcePackManager can load. The raw asset tables are in embedded_assets.h.
    void installResourcePack(){
        // Sanity: confirm all four embedded assets are present and non-empty.
        bool ok=kBlocksJson_LEN>0 && kTerrainTextureJson_LEN>0 && kEnUSLang_LEN>0;
        mLog->info("BlueCube assets: blocks={} terrain={} lang={}",
                   kBlocksJson_LEN,kTerrainTextureJson_LEN,kEnUSLang_LEN);
        if(!ok){ mLog->error("embedded resource pack assets invalid"); return; }
        // Resource pack is fully embedded and validated inside the .levipack.
        // name is served by BOTH the I18n::get hooks and data-level language
        // Custom tile is bound via JSON splice; PNG served by native Pack hooks.
        mPackReady.store(true);
        mLog->info("BlueCube resource pack assembled in-memory (pack ready)");
    }

    static void creativeDetour(void* initializer,void const* worldVersion){
        diagWriteEager("creativeDetour_BEGIN");
        invStep("[BlueCube] INV: creativeDetour BEGIN mgr=%llx",(unsigned long long)initializer);
        if(gOrigCreativeFn) gOrigCreativeFn(initializer,worldVersion);
        invStep("[BlueCube] INV: orig creative done");
        FinalMod* self=gInstance;
        if(!self) return;
        auto attached=self->mApi.attachInitializer(initializer);
        if(!attached){ self->mLog->error("attachInitializer: {}",errorString(attached.error)); return; }
        invStep("[BlueCube] INV: before createGroup");
        auto group=self->mApi.createGroup("Blue Cube",{"minecraft:stone",0,1},1);
        if(!group){ invStep("[BlueCube] INV: createGroup FAILED"); self->mLog->error("createGroup: {}",errorString(group.error)); return; }
        invStep("[BlueCube] INV: createGroup ok");

        if(self->mApi.initializerNative()){
            auto regSH=self->mApi.bindings().lockItemRegistry(self->mApi.initializerNative());
            if(regSH){
                void* itemReg=regSH.get();
                // New ItemRegistry (world rejoin): clear stale item cache and
                // recreate the BlockItem bound to the current world's block.
                if(itemReg != self->mItemRegistry){
                    self->mLog->info("BlueCube new ItemRegistry 0x{:x} (was 0x{:x})",
                                     (unsigned long)itemReg,(unsigned long)self->mItemRegistry);
                    self->mItemRegistry=itemReg;
                    gItemRegistryForRecipe=itemReg;   // for ingredient lookup
                    // registerBlue() already created the single BlockItem for
                    // this world. Never build a second 0x1d0 BlockItem here (that
                    // yielded duplicate id -3841 and left globals pointing at a
                    // different instance than the one in ItemRegistry). Only
                    // recreate if resetForNewWorld() cleared it (genuine rejoin).
                    if(!gActualBlockItem){
                        gItem=nullptr; gItemCB=nullptr;
                        if(self->mBlock) self->recreateBlockItem();
                    }
                }
                invStep("[BlueCube] INV: before registerItemInRegistry reg=%llx",(unsigned long long)itemReg);
                self->registerItemInRegistry(itemReg);
                invStep("[BlueCube] INV: registerItemInRegistry done");
            }
        }
        // DEFERRED recipe registration: recipeWrapperDetour runs during
        // VanillaRecipes BEFORE registerBlock/creativeDetour set up our block
        // and ItemRegistry, so its early guard failed every time. Here all
        // pointers are ready and gSavedRecipeMgr holds the long-lived Recipes*.
        if(gSavedRecipeMgr && !isRecipeMgrRegistered(gSavedRecipeMgr) &&
           gOrigRecipeWrapper && mBlockG && gBlueCubeCounter && gActualBlockItem){
            invStep("[BlueCube] INV: deferred replay BEGIN mgr=%llx",(unsigned long long)gSavedRecipeMgr);
            alignas(16) uint8_t dX7[48]={0};
            makeFakeX7(dX7,nullptr);
            // CRITICAL: Recipes::addShapedRecipe (0x1040e50c) REQUIRES a non-empty
            // craftingTags vector at 0x1040ef78-80. An empty vector (begin==end)
            // branches to cleanup at 0x1040ee8c and SKIPS addRecipe at 0x1040f0c8
            // — that is why the recipe never registered (count stayed 10, and the
            // wrapper's ret=1 was a stale-register artifact). The tag OBJECTS are
            // dereferenced (0x134ee4d8 copies a std::string from tag+8), so we must
            // supply a non-empty vector with valid, OWNED tag objects. Those were
            // deep-copied from a real live vanilla call into gCraftingTagsVec by
            // recipeWrapperDetour (a raw pointer capture went stale -> SKIP).
            bool ctOk = gCraftingTagsOwned[0] &&
                gCraftingTagsVec[0] && gCraftingTagsVec[1] > gCraftingTagsVec[0];
            invStep("[BlueCube] INV: deferred craftingTags vec=%llx ok=%llx begin=%llx end=%llx",
                    (unsigned long long)gCraftingTagsVec,(unsigned long long)ctOk,
                    (unsigned long long)gCraftingTagsVec[0],(unsigned long long)gCraftingTagsVec[1]);
            if(!ctOk){
                invStep("[BlueCube] INV: deferred replay SKIP - no owned craftingTags");
            }
            // All wrapper stack args must be valid owned descriptors. The factory
            // 0x10423290 derefs stack0 (0x104233ac) and stack1 (0x104233e4/ec);
            // passing 0 crashed. Zeroed 24B string = valid empty SSO; zeroed
            // vector (begin=end=cap=0) = copy loops run 0 iterations.
            uint64_t dS0=(uint64_t)gOwnedStackDesc[0],dS1=(uint64_t)gOwnedStackDesc[1],
                     dS2=(uint64_t)gOwnedStackDesc[2];
            invStep("[BlueCube] INV: deferred stack args s0=%llx s1=%llx s2=%llx",
                    (unsigned long long)dS0,(unsigned long long)dS1,(unsigned long long)dS2);
            bool dr=ctOk ?
                applyRecipe(gSavedRecipeMgr,nullptr,nullptr,(void*)gCraftingTagsVec,0,(void*)dX7,
                            dS0,dS1,dS2) : false;
            invStep("[BlueCube] INV: deferred replay done ret=%llx",(unsigned long long)dr);
            if(dr){ markRecipeMgrRegistered(gSavedRecipeMgr); gRecipeRegisteredThisWorld=true; }
            diagWriteEager("deferred_recipe_done");
        }

        // Build the CreativeItemEntry ItemInstance with the SAME verified
        // 128-byte layout used for the recipe result: vtable@+0, counter@+8,
        // mUserData=null@+16, Block*@+24, count/valid@+34/+35. The old check
        // wrongly required +16 to be an Item*, rejecting every valid instance.
        invStep("[BlueCube] INV: before buildBlueCubeItemInstance");
        alignas(16) unsigned char inst[0x80]={};
        bool instOk=buildBlueCubeItemInstance(inst);
        invStep("[BlueCube] INV: buildBlueCubeItemInstance ok=%llx",(unsigned long long)instOk);
        diagWriteEager("creative_after_build");
        __android_log_print(ANDROID_LOG_INFO,"BlueCube",
            "creative ItemInstance: vt=0x%llx counter=0x%llx counterItem=0x%llx userData=0x%llx block=0x%llx cnt=%d valid=%d ok=%d",
            (unsigned long long)*(void**)inst,
            (unsigned long long)*(void**)((char*)inst+8),
            (unsigned long long)(*(void**)((char*)inst+8)?**(void***)((char*)inst+8):nullptr),
            (unsigned long long)*(void**)((char*)inst+16),
            (unsigned long long)*(void**)((char*)inst+24),
            (int)*(unsigned char*)((char*)inst+34),
            (int)*(unsigned char*)((char*)inst+35),(int)instOk);
        AddOptions opt; opt.skipIfAlreadyPresent=true; opt.requireCanonicalName=false;
        std::size_t added=0, skipped=0;
        void* creg=self->mApi.creativeRegistryNative();
        bool alreadyInserted=(creg && gCreativeAddedRegistry==creg);
        if(instOk && !alreadyInserted){
            invStep("[BlueCube] INV: STEP1 before addItemInstance");
            auto eb=self->mApi.addItemInstance(group.value,inst,opt);
            invStep("[BlueCube] INV: STEP1 after addItemInstance");
            if(eb){ ++added; gCreativeAddedRegistry=creg; }
            self->mLog->info("BlueCube addItemInstance: {}",eb?"ok":errorString(eb.error));
        } else if(alreadyInserted){
            self->mLog->info("BlueCube creative: already inserted for registry 0x{:x}, skip",(unsigned long)creg);
        } else {
            self->mLog->error("BlueCube creative ItemInstance invalid - entry not added");
        }
        self->mApi.bindings().itemInstanceDtor(inst);

        invStep("[BlueCube] INV: before finalize added=%llx",(unsigned long long)added);
        auto fin=self->mApi.finalize();
        invStep("[BlueCube] INV: after finalize");
        self->mLog->info("BlueCube creative: added={} skipped={} finalize={}",
                         added,skipped,fin?"ok":errorString(fin.error));
        invStep("[BlueCube] INV: creativeDetour DONE added=%llx",(unsigned long long)added);
        diagWriteEager("creative_done");
    }

    CreativeInventoryAPI mApi;
    pl::log::Logger* mLog{};
    std::atomic_bool mStop{false};
    std::atomic_bool mPackReady{false};
    // per-world lifecycle state (no process-wide once-flag)
    void* mBlockRegistry{};             // live BlockTypeRegistry pointer for this world
    void* mItemRegistry{};              // live ItemRegistry pointer for this world
    bool  mBlockRegisteredForWorld{false};
    int   mBlockId{kBlueCubeBlockId};
    void* mBlock{};
    std::thread mWorker;

    static FinalMod* gInstance;
    static void* gOrigRegBlock;
    static RegBlockFn gOrigFn;
    static void* gOrigCreative;
    static AddLooseFn gOrigCreativeFn;
    static void* gOrigI18n;
    static void* gOrigI18nParamsHook;
    static void* gOrigBuildDescHook;
    static void* gOrigBlockLegacyNameHook;
    static void* gRecipeHook;
    static void* gItem;
    static void* gItemCB;
};
FinalMod* FinalMod::gInstance=nullptr;
void* FinalMod::gOrigRegBlock=nullptr;
RegBlockFn FinalMod::gOrigFn=nullptr;
void* FinalMod::gOrigCreative=nullptr;
AddLooseFn FinalMod::gOrigCreativeFn=nullptr;
void* FinalMod::gOrigI18n=nullptr;
void* FinalMod::gOrigI18nParamsHook=nullptr;
void* FinalMod::gOrigBuildDescHook=nullptr;
void* FinalMod::gOrigBlockLegacyNameHook=nullptr;
void* FinalMod::gRecipeHook=nullptr;
void* FinalMod::gItem=nullptr;
void* FinalMod::gItemCB=nullptr;
} // namespace

extern "C" PL_EXPORT ::pl::mod::ModRegistration* PLGetModRegistration(){
    static FinalMod* p=new FinalMod();
    static auto reg=::pl::mod::detail::makeRegistration(*p);
    return &reg;
}


