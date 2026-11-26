#pragma once
#include <cstdint>
// libminecraftpe.so 1.26.60.4 arm64, SHA 6c7b409d...cb8c77f
namespace off {
constexpr uintptr_t JNI_ONLOAD      = 0x889c410;
constexpr uintptr_t REGISTER_BLOCK  = 0x989ef20; // void*(reg, HashedString*, int* id, Material*)
constexpr uintptr_t BLOCKTYPE_CTOR  = 0x10920f8c; // void(this, HashedString, int id, Material)
constexpr uintptr_t BLOCKITEM_CTOR  = 0x10816530; // void(this, string, short, HashedString)
constexpr uintptr_t MATERIAL_GET    = 0x111c9918; // void*(int materialType)
constexpr uintptr_t HASHED_CTOR     = 0x134ee764; // void(out, const std::string&)
constexpr uintptr_t HASHED_GETSTR   = 0x134eea5c; // const char*(HashedString*) -> embedded string
constexpr uintptr_t REGISTER_ITEM   = 0x1039c2e0; // SharedPtr<Item> getItem(reg, int* outId, const char* name, size_t len; x8 = out slot)
constexpr uintptr_t REGISTER_ITEM_WRAPPER = 0x1039c800; // (reg, int* outId, int* local, const char* name, size_t len; x8 = out slot)
constexpr uintptr_t ITEM_GET_ID     = 0x10797f54; // short(Item* item)
// v30: I18n / translation (I18nImpl vtable 0x13b3d330, vfunc index 3)
constexpr uintptr_t I18N_GET        = 0xcc9db5c; // std::string I18nImpl::get(const std::string& key); x0=this x1=key x8=ret
constexpr uintptr_t I18N_GET_PARAMS = 0xcc9e630; // I18nImpl vtable vfunc5 - parameterized get(key, params...); x0=this x1=key x8=ret; PC-rel-free
constexpr uintptr_t CSL_STRING_INIT = 0xe8313bc; // NDK/csl string __init(const char* data, size_t len): x0=out x1=data x2=len; 24-byte SSO
constexpr uintptr_t I18N_VTABLE     = 0x13b3d330;
// v36: BlockItem vtable (133 vfuncs). Slot 55 is buildDescriptionName;
// x0=this, x1=hidden csl::basic_string sret, x2/x3=args.
constexpr uintptr_t BLOCKITEM_VTABLE = 0x13da9640;
constexpr int BUILD_DESC_NAME_SLOT  = 55;
// v36: real ResourcePackManager::load (thunk 0x11ae5f10 -> this).
// x0=mgr x1=ResourceLocation(path csl::string) x2=out csl::string x3=mode -> bool
constexpr uintptr_t RPM_LOAD_REAL   = 0x11b42458;
// v36: shaped recipe wrapper + low-level addShapedRecipe.
constexpr uintptr_t BUILD_DESC_NAME    = 0x107914b4; // BlockItem/Item vtable slot55 buildDescriptionName
constexpr uintptr_t BLOCKLEGACY_DESC   = 0x10924fa4; // BlockLegacy::buildDescriptionName (PC-rel-free)
constexpr uintptr_t ADD_SHAPED_WRAPPER = 0x1040f840;
constexpr uintptr_t ADD_SHAPED_RECIPE  = 0x1040e50c;
// v53: The REAL caller of 0x104080d0 (which forwards key vector x5 -> x4 of
// 0x1040f840) builds each entry at 0x103e5d38-0x103e5d90:
//   0x103e5c40: adrp x8,13d9b000 ; 0x103e5c44: add x8,x8,#0x360 -> 0x13d9b360
//   0x103e5c48: str x8,[sp,#11200]          (vtable staged for the entry)
//   0x103e5d38: mov w0,#0x18 ; bl _Znwm     (24-byte entry)
//   0x103e5d5c: bl 0x107ac7d0               (descriptor copy ctor)
//   0x103e5d68: str x21,[x19]               (vtable at entry+0)
// 0x1394e2a0 (V52) is the RecipeIngredient vtable used by the 3x3 pattern
// builder at 0x103de600 — NOT the 48-byte Recipes::Type key entry vtable.
constexpr uintptr_t RECIPETYPE_VTABLE  = 0x13d9b360;
// v30: ResourcePackManager (vtable 0x13b532c8)
constexpr uintptr_t RPM_VTABLE      = 0x13b532c8;
constexpr uintptr_t RPM_LOAD        = 0xcf4de30; // ResourcePackManager::load(loc, exts) - big vfunc
constexpr uintptr_t RPM_LOAD2       = 0xcf4e2d0; // ResourcePackManager::load(pair, exts)
// v30: BlockGraphics (vtable 0x139d4920) - setTextureItem candidates
constexpr uintptr_t BG_VTABLE       = 0x139d4920;
constexpr uintptr_t BG_SETTEXTURE   = 0xab134d0; // BlockGraphics::setTextureItem (vfunc 6)
// v32: dedicated JSON loaders (verified PC-rel-free 24-byte prologues)
constexpr uintptr_t FN_BLOCKS_LOADER = 0xab092b0; // blocks.json loader (one caller 0x9da0d28)
constexpr uintptr_t FN_TERRAIN_LOADER= 0xcf37454; // terrain_texture.json loader (one caller 0xf49ac20)
// v32: inner Json::Reader::parse helpers these loaders call (statically linked,
// resolved from GOT relocations, prologues PC-rel-free):
constexpr uintptr_t JSON_PARSE_CSTR  = 0x886e948; // parse(const char* data, size_t len, Json::Value&, bool)
constexpr uintptr_t JSON_PARSE_STR   = 0x886e5c8; // parse(const std::string& data, Json::Value&, bool)
// v32: string xrefs (documentation of RE evidence)
constexpr uintptr_t STR_BLOCKS_JSON = 0x27797a0; // "blocks.json"
constexpr uintptr_t STR_TERRAIN_JSON= 0x2465302; // "textures/terrain_texture.json"

constexpr uintptr_t SET_VANILLA     = 0x10926448; // void(block, bool)
constexpr uintptr_t CREATIVE_ADD    = 0x103a6fa4; // CreativeItemRegistry::add(ItemInstance,...)
constexpr uintptr_t REGISTRY        = 0x14208218; // global registry object
constexpr uintptr_t LAST_BLOCK_ID   = 0x142081e8; // next id counter
constexpr uintptr_t STD_FUNC_OBJ    = 0x179e270;  // creative-callback std::function
constexpr uintptr_t STD_FUNC_INVOKE = 0xf4b941c;  // __invoke thunk
constexpr uintptr_t STD_FUNC_TYPEINFO = 0x13c7db68;
constexpr uintptr_t CB_TYPECHECK     = 0xf4b95ac;
constexpr uintptr_t CREATIVE_VTABLE  = 0x13d6ecd0; // CreativeItemRegistry vtable addr point
constexpr uintptr_t CREATIVE_INIT     = 0x103a32c0; // cold one-time CreativeItemRegistry init (stores to Level+0x2f8)
constexpr uintptr_t LEVEL_CREATIVE_OFF= 0x2f8;      // Level -> CreativeItemRegistry*
constexpr uintptr_t PACKET_WRITE      = 0xc782cc4;  // CreativeContentPacket::write (vtable slot 6)
constexpr uintptr_t CREATIVE_REAL_ADD = 0x103a7200; // real creative item insert (copies 0x1b0 entries)
// v16 verified from objdump this session
constexpr uintptr_t ITEMINSTANCE_CTOR = 0x1076c580; // ItemInstance(this, Item*, unsigned char count)
constexpr uintptr_t ITEM_ADD          = 0xa5f58a0;  // add ItemInstance to live registry (x0=registry, x1=item) -> tailcalls 0x101e4eb0
constexpr uintptr_t ITEM_ADD_TAIL     = 0x101e4eb0; // copies 0x1b0-byte ItemInstance to registry+0x7f8
constexpr uintptr_t BLOCKREG_FROM_DEF = 0x10cbb5f8; // BlockDefinitionGroup::registerBlockFromDefinition (real block pass; increments id@0x142081e8)
constexpr uintptr_t BLOCK_GET_ITEM_ID = 0x109268cc; // block->+0x14e id getter
// v17: Bedrock's OWN in-memory block-definition JSON loader
constexpr uintptr_t BLOCKDEF_PARSE      = 0x10cbd2d8; // parse(Puv::Input* x2, ctx x1/x3/x4/x5) -> optional<BlockDefinition> in x0; result BlockDefinition* at [x0+0x30]
constexpr uintptr_t CSLSTRING_CTOR      = 0xe8313bc;  // csl::basic_string<char>(out x0, const char* x1, size_t x2) -- builds Puv::Input
constexpr uintptr_t BLOCKDEF_LOADER     = 0x10ccde40; // reads JSON from stream, calls parser, registers result
constexpr uintptr_t BLOCKDEF_COPY       = 0xb711924;  // copy BlockDefinition into accumulator
constexpr uintptr_t BLOCKDEF_OUTER      = 0x10cc1ff0;  // BlockDefinitionGroup outer loader (refs "block_definitions", runs every world load; called from 0x10b18d40)
// REAL function entry (has stp x29,x30 prologue). v20 used 0x10cbb5f8 which is MID-FUNCTION
// (just 'sub sp,sp,#0x2b0') -> skipped prologue -> LR not saved -> crash on return.
constexpr uintptr_t BLOCKDEF_REGISTER   = 0x10cbb5dc;  // BlockDefinitionGroup::registerBlockFromDefinition(this, def): x19=def, def+0x50=id string, calls registerBlock@0x989ef20
constexpr uintptr_t BLOCK_LOAD_ONE      = 0x10ccde40;  // full "load one definition" fn: stream->csl input -> parse(x8 result) -> copy. ADR refs @0x10cc2d44
constexpr uintptr_t STD_FUNC_VTABLE     = 0x13a52a80;  // std::function vtable built @0x10cc2d34 (captures base,x19+8,x19+0x10,x19+0x28)
constexpr uintptr_t ITERATOR_CALL       = 0xb708470;  // unique caller @0x10cc2eac; hook to get live frame while std::function F is alive
constexpr uintptr_t F_STACK_OFF         = 0x930;      // F (std::function, target 0x10ccde40) at [bodySP+0x930] = [sp,#2352]
constexpr uintptr_t THUNK_ENTER         = 0xb7126f8;  // std::function vtable stub: add x0,#8; b 0xb712728 (invoke thunk)
constexpr uintptr_t THUNK_INVOKE        = 0xb712728;  // invoke thunk: unpacks OBJ captures, calls 0x10ccde40 with real x1-x5, x8=result
// v26: init-pass registration hooks (callers of registerBlock 0x989ef20 with full prologues)
constexpr uintptr_t VBLOCK_REG_HELPER1  = 0x989287c;  // vanilla block registration helper (sub sp,#0xe0; calls registerBlock)
constexpr uintptr_t VBLOCK_REG_HELPER2  = 0x9893350;  // vanilla block registration helper (sub sp,#0xe0; calls registerBlock)
constexpr uintptr_t VBLOCK_REG_HELPER3  = 0x98917e0;  // vanilla block registration helper (sub sp,#0x120; calls registerBlock)
constexpr uintptr_t ATOMIC_INCR         = 0x8897340;  // shared_ptr control block atomic refcount increment (used by make_shared pattern)

// ---- DATA / VTABLE addresses — NOT function offsets -------------------------
// These are the ONLY remaining RVA-based addresses in FinalMod.cpp. They are
// objects in .data.rel.ro (vtables / the writable-data range used by the Item*
// sanity check), not executable code, so the r-x wildcard signature scanner
// cannot see them. They are used as gBase + off::NAME and are deliberately NOT
// listed in resolveNativeBackend()'s signature table. Do not "convert" these
// to instruction signatures: there are no instructions at these addresses.
constexpr uintptr_t SHAPED_RECIPE_VTABLE    = 0x13d70be0; // ShapedRecipe vtable (diag)
constexpr uintptr_t SHAPED_RECIPE_VTABLE_LO = 0x13d70b00; // vtable family range start
constexpr uintptr_t SHAPED_RECIPE_VTABLE_HI = 0x13d70e00; // vtable family range end
constexpr uintptr_t ITEMINSTANCE_VTABLE     = 0x13d93420; // ItemInstance vtable@+0
constexpr uintptr_t DATA_REL_RO_LO          = 0x13700000; // .data.rel.ro start (Item* guard)
constexpr uintptr_t DATA_REL_RO_HI          = 0x14000000; // .data.rel.ro end   (Item* guard)
}
