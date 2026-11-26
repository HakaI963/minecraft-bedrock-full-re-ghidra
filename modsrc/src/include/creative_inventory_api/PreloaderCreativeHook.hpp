#pragma once

#include "creative_inventory_api/CreativeInventoryAPI.hpp"

namespace creative_inventory_api {

class PreloaderCreativeHook {
public:
    using Callback = void (*)(
        CreativeInventoryAPI& api,
        void* initializer,
        void const* worldVersion,
        void* userData
    );

    PreloaderCreativeHook() = default;
    PreloaderCreativeHook(PreloaderCreativeHook const&) = delete;
    PreloaderCreativeHook& operator=(PreloaderCreativeHook const&) = delete;
    ~PreloaderCreativeHook();

    Status install(
        CreativeInventoryAPI& api,
        Callback callback,
        void* userData = nullptr,
        int priority = 200
    );

    void uninstall() noexcept;
    [[nodiscard]] bool installed() const noexcept { return mInstalled; }

private:
    static void detour(void* initializer, void const* worldVersion);

    CreativeInventoryAPI* mApi{};
    Callback mCallback{};
    void* mUserData{};
    EngineBindings::AddLooseCreativeItemsFn mOriginal{};
    bool mInstalled{};

    static PreloaderCreativeHook* sInstance;
};

} // namespace creative_inventory_api
