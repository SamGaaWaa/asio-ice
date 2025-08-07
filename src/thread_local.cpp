#include "thread_local.hpp"

#include <thread>
#include <algorithm>
#include <vector>
#include <memory>
#include <mutex>
#include <cassert>
#include <any>

namespace ice::utils {

struct thread_entry {
    std::thread::id id;
};

struct thread_list {
    using list_type = std::vector<std::shared_ptr<thread_entry>>;

    thread_entry *register_thread() {
        auto id = std::this_thread::get_id();
        auto entry = std::make_shared<thread_entry>(thread_entry{id});
        std::lock_guard lk{_mtx};
        auto it = std::find_if(_ths.begin(), _ths.end(),
                               [id](const auto &p) { return p->id == id; });
        if (it != _ths.end())
            return nullptr;
        auto raw = entry.get();
        _ths.push_back(std::move(entry));
        return raw;
    }

    void unregister_thread() noexcept {
        auto id = std::this_thread::get_id();
        std::lock_guard lk{_mtx};
        auto it = std::find_if(_ths.begin(), _ths.end(),
                               [id](const auto &p) { return p->id == id; });
        if (it == _ths.end())
            return;
        _ths.erase(it);
    }

    list_type all_entries() const {
        std::lock_guard lk{_mtx};
        return _ths;
    }

    static auto &instance() noexcept {
        static thread_list g_list{};
        return g_list;
    }

  private:
    thread_list() = default;

    mutable std::mutex _mtx;
    list_type _ths;
};

struct registry_guard {
    static auto &instance() noexcept {
        thread_local registry_guard l_guard;
        return l_guard;
    }

    thread_entry *entry() noexcept { return _entry; }

    const thread_entry *entry() const noexcept { return _entry; }

    ~registry_guard() {
        if (_entry)
            thread_list::instance().unregister_thread();
    }

  private:
    registry_guard() : _entry(thread_list::instance().register_thread()) {}

    thread_entry *_entry;
};

static thread_entry *local_entry() noexcept {
    return registry_guard::instance().entry();
}

} // namespace ice::utils