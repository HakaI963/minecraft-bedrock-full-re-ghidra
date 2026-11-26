#include "creative_inventory_api/PreloaderCreativeHook.hpp"

#include <pl/memory/Hook.hpp>

namespace creative_inventory_api {

PreloaderCreativeHook* PreloaderCreativeHook::sInstance = nullptr;

PreloaderCreativeHook::~PreloaderCreativeHook() { uninstall(); }

Status PreloaderCreativeHook::install(
    CreativeInventoryAPI& api,
    Callback callback,
    void* userData,
    int priority
) {
    if (mInstalled || sInstance) return {Error::AlreadyInstalled};
    if (!api.resolved() || !api.bindings().addLooseCreativeItemsTarget) return {Error::NotResolved};

    void* originalRaw = nullptr;
    const auto prio = static_cast<pl::memory::HookPriority>(priority);
    const int rc = pl::memory::hook(
        api.bindings().addLooseCreativeItemsTarget,
        reinterpret_cast<void*>(&PreloaderCreativeHook::detour),
        &originalRaw,
        prio
    );
    if (rc != 0 || !originalRaw) return {Error::HookInstallFailed};

    mApi = &api;
    mCallback = callback;
    mUserData = userData;
    mOriginal = reinterpret_cast<EngineBindings::AddLooseCreativeItemsFn>(originalRaw);
    mInstalled = true;
    sInstance = this;
    return {};
}

void PreloaderCreativeHook::uninstall() noexcept {
    if (!mInstalled) return;
    if (mApi && mApi->bindings().addLooseCreativeItemsTarget) {
        pl::memory::unhook(
            mApi->bindings().addLooseCreativeItemsTarget,
            reinterpret_cast<void*>(&PreloaderCreativeHook::detour)
        );
    }
    if (sInstance == this) sInstance = nullptr;
    mInstalled = false;
    mOriginal = nullptr;
    mCallback = nullptr;
    mUserData = nullptr;
    mApi = nullptr;
}

void PreloaderCreativeHook::detour(void* initializer, void const* worldVersion) {
    auto* self = sInstance;
    if (!self) return;

    // Vanilla first. The API then sees the fully-populated vanilla registry,
    // which makes duplicate detection and net-id allocation deterministic.
    if (self->mOriginal) self->mOriginal(initializer, worldVersion);
    if (!self->mApi) return;
    const auto attached = self->mApi->attachInitializer(initializer);
    if (!attached) return;
    if (self->mCallback) self->mCallback(*self->mApi, initializer, worldVersion, self->mUserData);
}

} // namespace creative_inventory_api
