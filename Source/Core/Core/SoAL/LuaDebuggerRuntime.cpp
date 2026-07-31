// SPDX-License-Identifier: GPL-2.0-or-later
#include "Core/SoAL/LuaDebuggerRuntime.h"

#include <algorithm>
#include <bit>
#include <cstdlib>
#include <fstream>
#include <limits>
#include <unordered_map>
#include <utility>

#include <fmt/format.h>
#include <picojson.h>

#include "Common/DynamicLibrary.h"
#include "Core/SoAL/LuaDebuggerSha256.h"

namespace SoAL
{
namespace
{
const char* EventKindName(LuaDebuggerEventKind kind)
{
  switch (kind)
  {
  case LuaDebuggerEventKind::Instruction: return "instruction";
  case LuaDebuggerEventKind::Frame: return "frame";
  case LuaDebuggerEventKind::MemoryRead: return "memory_read";
  case LuaDebuggerEventKind::MemoryWrite: return "memory_write";
  case LuaDebuggerEventKind::Present: return "present";
  case LuaDebuggerEventKind::GXCommand: return "gx_command";
  case LuaDebuggerEventKind::GXDraw: return "gx_draw";
  case LuaDebuggerEventKind::EFBCopy: return "efb_copy";
  case LuaDebuggerEventKind::EffectivePipeline: return "effective_pipeline";
  }
  return "invalid";
}

struct lua_State;
using lua_Integer = long long;
using lua_Number = double;
using lua_KContext = std::intptr_t;
using lua_CFunction = int (*)(lua_State*);
using lua_KFunction = int (*)(lua_State*, int, lua_KContext);
using lua_Alloc = void* (*)(void*, void*, size_t, size_t);
using lua_Hook = void (*)(lua_State*, void*);

constexpr int LUA_OK = 0;
constexpr int LUA_MULTRET = -1;
constexpr int LUA_TNUMBER = 3;
constexpr int LUA_TSTRING = 4;
constexpr int LUA_MASKCOUNT = 8;

struct LuaApi
{
  lua_Number (*version)(lua_State*) = nullptr;
  lua_State* (*newstate)(lua_Alloc, void*) = nullptr;
  void (*close)(lua_State*) = nullptr;
  int (*loadbufferx)(lua_State*, const char*, size_t, const char*, const char*) = nullptr;
  int (*pcallk)(lua_State*, int, int, int, lua_KContext, lua_KFunction) = nullptr;
  void (*requiref)(lua_State*, const char*, lua_CFunction, int) = nullptr;
  lua_CFunction open_base = nullptr;
  lua_CFunction open_table = nullptr;
  lua_CFunction open_string = nullptr;
  lua_CFunction open_math = nullptr;
  lua_CFunction open_utf8 = nullptr;
  int (*gettop)(lua_State*) = nullptr;
  void (*settop)(lua_State*, int) = nullptr;
  int (*getglobal)(lua_State*, const char*) = nullptr;
  void (*setglobal)(lua_State*, const char*) = nullptr;
  void (*pushnil)(lua_State*) = nullptr;
  void (*pushinteger)(lua_State*, lua_Integer) = nullptr;
  void (*pushnumber)(lua_State*, lua_Number) = nullptr;
  void (*pushboolean)(lua_State*, int) = nullptr;
  const char* (*pushlstring)(lua_State*, const char*, size_t) = nullptr;
  void (*pushcclosure)(lua_State*, lua_CFunction, int) = nullptr;
  void (*createtable)(lua_State*, int, int) = nullptr;
  void (*setfield)(lua_State*, int, const char*) = nullptr;
  int (*type)(lua_State*, int) = nullptr;
  const char* (*tolstring)(lua_State*, int, size_t*) = nullptr;
  lua_Integer (*tointegerx)(lua_State*, int, int*) = nullptr;
  int (*error)(lua_State*) = nullptr;
  void (*sethook)(lua_State*, lua_Hook, int, int) = nullptr;
};

struct AllocationState
{
  size_t used = 0;
  size_t limit = 0;
};

std::mutex s_instances_mutex;
std::unordered_map<lua_State*, LuaDebuggerRuntime*> s_instances;

LuaDebuggerRuntime* Instance(lua_State* state)
{
  std::lock_guard lock(s_instances_mutex);
  const auto it = s_instances.find(state);
  return it == s_instances.end() ? nullptr : it->second;
}

void* LimitedAllocator(void* opaque, void* pointer, size_t old_size, size_t new_size)
{
  auto& allocation = *static_cast<AllocationState*>(opaque);
  if (new_size == 0)
  {
    std::free(pointer);
    allocation.used -= std::min(allocation.used, old_size);
    return nullptr;
  }
  const size_t without_old = allocation.used - std::min(allocation.used, old_size);
  if (new_size > allocation.limit - std::min(allocation.limit, without_old))
    return nullptr;
  void* result = std::realloc(pointer, new_size);
  if (result)
    allocation.used = without_old + new_size;
  return result;
}

std::array<u8, 32> HashFile(const std::string& path, std::vector<u8>* bytes)
{
  std::ifstream stream(path, std::ios::binary);
  bytes->assign(std::istreambuf_iterator<char>(stream), {});
  return Sha256(*bytes);
}

std::string JsonEscape(std::string_view text)
{
  std::string result;
  for (const unsigned char byte : text)
  {
    if (byte == '\\' || byte == '"')
      result += fmt::format("\\{}", static_cast<char>(byte));
    else if (byte == '\n')
      result += "\\n";
    else if (byte == '\r')
      result += "\\r";
    else if (byte == '\t')
      result += "\\t";
    else if (byte < 0x20)
      result += fmt::format("\\u{:04x}", byte);
    else
      result += static_cast<char>(byte);
  }
  return result;
}
}  // namespace

struct LuaDebuggerRuntime::Impl
{
  Common::DynamicLibrary library;
  LuaApi api;
  lua_State* state = nullptr;
  AllocationState allocation;
  u64 budget = 0;
};

namespace
{
template <typename T>
bool Bind(const Common::DynamicLibrary& library, const char* name, T* function, std::string* error)
{
  if (library.GetSymbol(name, function))
    return true;
  *error = fmt::format("Pinned Lua runtime is missing required symbol {}", name);
  return false;
}

bool BindApi(LuaDebuggerRuntime::Impl& impl, std::string* error)
{
  LuaApi& a = impl.api;
  return Bind(impl.library, "lua_version", &a.version, error) &&
         Bind(impl.library, "lua_newstate", &a.newstate, error) &&
         Bind(impl.library, "lua_close", &a.close, error) &&
         Bind(impl.library, "luaL_loadbufferx", &a.loadbufferx, error) &&
         Bind(impl.library, "lua_pcallk", &a.pcallk, error) &&
         Bind(impl.library, "luaL_requiref", &a.requiref, error) &&
         Bind(impl.library, "luaopen_base", &a.open_base, error) &&
         Bind(impl.library, "luaopen_table", &a.open_table, error) &&
         Bind(impl.library, "luaopen_string", &a.open_string, error) &&
         Bind(impl.library, "luaopen_math", &a.open_math, error) &&
         Bind(impl.library, "luaopen_utf8", &a.open_utf8, error) &&
         Bind(impl.library, "lua_gettop", &a.gettop, error) &&
         Bind(impl.library, "lua_settop", &a.settop, error) &&
         Bind(impl.library, "lua_getglobal", &a.getglobal, error) &&
         Bind(impl.library, "lua_setglobal", &a.setglobal, error) &&
         Bind(impl.library, "lua_pushnil", &a.pushnil, error) &&
         Bind(impl.library, "lua_pushinteger", &a.pushinteger, error) &&
         Bind(impl.library, "lua_pushnumber", &a.pushnumber, error) &&
         Bind(impl.library, "lua_pushboolean", &a.pushboolean, error) &&
         Bind(impl.library, "lua_pushlstring", &a.pushlstring, error) &&
         Bind(impl.library, "lua_pushcclosure", &a.pushcclosure, error) &&
         Bind(impl.library, "lua_createtable", &a.createtable, error) &&
         Bind(impl.library, "lua_setfield", &a.setfield, error) &&
         Bind(impl.library, "lua_type", &a.type, error) &&
         Bind(impl.library, "lua_tolstring", &a.tolstring, error) &&
         Bind(impl.library, "lua_tointegerx", &a.tointegerx, error) &&
         Bind(impl.library, "lua_error", &a.error, error) &&
         Bind(impl.library, "lua_sethook", &a.sethook, error);
}

int Fail(lua_State* state, std::string_view message)
{
  LuaDebuggerRuntime* runtime = Instance(state);
  runtime->InternalImpl().api.pushlstring(state, message.data(), message.size());
  return runtime->InternalImpl().api.error(state);
}

bool IntegerArg(LuaDebuggerRuntime& runtime, lua_State* state, int index, u64* value)
{
  int valid = 0;
  const lua_Integer integer = runtime.InternalImpl().api.tointegerx(state, index, &valid);
  if (!valid || integer < 0)
    return false;
  *value = static_cast<u64>(integer);
  return true;
}

std::string_view StringArg(LuaDebuggerRuntime& runtime, lua_State* state, int index)
{
  size_t size = 0;
  const char* value = runtime.InternalImpl().api.tolstring(state, index, &size);
  return value ? std::string_view(value, size) : std::string_view{};
}

template <typename T>
int ReadInteger(lua_State* state)
{
  LuaDebuggerRuntime* runtime = Instance(state);
  u64 address64 = 0;
  if (!runtime || !IntegerArg(*runtime, state, 1, &address64) || address64 > UINT32_MAX ||
      !runtime->ReadProviders().memory)
    return Fail(state, "typed memory read requires a valid 32-bit address and memory provider");
  std::vector<u8> bytes;
  if (!runtime->ReadProviders().memory(static_cast<u32>(address64), sizeof(T), &bytes) ||
      bytes.size() != sizeof(T))
    return Fail(state, "typed memory read failed");
  using U = std::make_unsigned_t<T>;
  U value = 0;
  for (const u8 byte : bytes)
    value = static_cast<U>((value << 8) | byte);
  runtime->InternalImpl().api.pushinteger(state, static_cast<lua_Integer>(static_cast<T>(value)));
  return 1;
}

int ReadFloat32(lua_State* state)
{
  LuaDebuggerRuntime* runtime = Instance(state);
  u64 address64 = 0;
  std::vector<u8> bytes;
  if (!runtime || !IntegerArg(*runtime, state, 1, &address64) || address64 > UINT32_MAX ||
      !runtime->ReadProviders().memory ||
      !runtime->ReadProviders().memory(static_cast<u32>(address64), 4, &bytes) || bytes.size() != 4)
    return Fail(state, "f32 memory read failed");
  u32 bits = 0;
  for (const u8 byte : bytes)
    bits = (bits << 8) | byte;
  runtime->InternalImpl().api.pushnumber(state, std::bit_cast<float>(bits));
  return 1;
}

int ReadFloat64(lua_State* state)
{
  LuaDebuggerRuntime* runtime = Instance(state);
  u64 address64 = 0;
  std::vector<u8> bytes;
  if (!runtime || !IntegerArg(*runtime, state, 1, &address64) || address64 > UINT32_MAX ||
      !runtime->ReadProviders().memory ||
      !runtime->ReadProviders().memory(static_cast<u32>(address64), 8, &bytes) || bytes.size() != 8)
    return Fail(state, "f64 memory read failed");
  u64 bits = 0;
  for (const u8 byte : bytes)
    bits = (bits << 8) | byte;
  runtime->InternalImpl().api.pushnumber(state, std::bit_cast<double>(bits));
  return 1;
}

int ReadRegister(lua_State* state)
{
  LuaDebuggerRuntime* runtime = Instance(state);
  const std::string_view name = runtime ? StringArg(*runtime, state, 1) : std::string_view{};
  u64 value = 0;
  if (!runtime || name.empty() || !runtime->ReadProviders().reg ||
      !runtime->ReadProviders().reg(name, &value) ||
      value > static_cast<u64>(std::numeric_limits<lua_Integer>::max()))
    return Fail(state, "register read failed or value exceeds signed Lua integer range");
  runtime->InternalImpl().api.pushinteger(state, static_cast<lua_Integer>(value));
  return 1;
}

template <typename T>
int WriteInteger(lua_State* state)
{
  LuaDebuggerRuntime* runtime = Instance(state);
  u64 address64 = 0;
  u64 value = 0;
  if (!runtime || !IntegerArg(*runtime, state, 1, &address64) ||
      !IntegerArg(*runtime, state, 2, &value) || address64 > UINT32_MAX ||
      value > static_cast<u64>(std::numeric_limits<T>::max()) ||
      !runtime->ReadProviders().write_memory)
    return Fail(state, "typed memory write arguments or provider are invalid");
  std::array<u8, sizeof(T)> bytes{};
  for (size_t index = 0; index < bytes.size(); ++index)
    bytes[bytes.size() - 1 - index] = static_cast<u8>(value >> (index * 8));
  std::string error;
  if (!runtime->Session().RecordMemoryWrite(static_cast<u32>(address64), bytes, &error))
    return Fail(state, error);
  if (!runtime->ReadProviders().write_memory(static_cast<u32>(address64), bytes))
    return Fail(state, "typed memory write failed after audit authorization");
  return 0;
}

int WriteRegister(lua_State* state)
{
  LuaDebuggerRuntime* runtime = Instance(state);
  const std::string_view name = runtime ? StringArg(*runtime, state, 1) : std::string_view{};
  u64 value = 0;
  if (!runtime || name.empty() || !IntegerArg(*runtime, state, 2, &value) ||
      !runtime->ReadProviders().write_reg)
    return Fail(state, "register write arguments or provider are invalid");
  std::string error;
  if (!runtime->Session().RecordRegisterWrite(std::string(name), value, &error))
    return Fail(state, error);
  if (!runtime->ReadProviders().write_reg(name, value))
    return Fail(state, "register write failed after audit authorization");
  return 0;
}

int LookupSymbol(lua_State* state)
{
  LuaDebuggerRuntime* runtime = Instance(state);
  const std::string_view name = runtime ? StringArg(*runtime, state, 1) : std::string_view{};
  u32 address = 0;
  if (!runtime || name.empty() || !runtime->ReadProviders().symbol ||
      !runtime->ReadProviders().symbol(name, &address))
    return Fail(state, "symbol lookup failed");
  runtime->InternalImpl().api.pushinteger(state, address);
  return 1;
}

int Emit(lua_State* state)
{
  LuaDebuggerRuntime* runtime = Instance(state);
  const std::string_view kind = runtime ? StringArg(*runtime, state, 1) : std::string_view{};
  const std::string_view json = runtime ? StringArg(*runtime, state, 2) : std::string_view{};
  picojson::value parsed;
  const std::string json_text(json);
  const std::string parse_error = picojson::parse(parsed, json_text);
  if (!runtime || kind.empty() || !parse_error.empty() || !parsed.is<picojson::object>())
    return Fail(state, "emit requires a nonempty kind and a JSON object string");
  runtime->RecordOutput(fmt::format("{{\"schema\":\"soal.lua-output.v1\",\"kind\":\"{}\","
                                    "\"payload\":{}}}", JsonEscape(kind), json));
  return 0;
}

int RegisterCallback(lua_State* state, LuaDebuggerEventKind kind, bool address_filter)
{
  LuaDebuggerRuntime* runtime = Instance(state);
  if (!runtime)
    return Fail(state, "callback registration has no runtime");
  std::optional<LuaDebuggerAddressFilter> filter;
  int name_index = 1;
  if (address_filter)
  {
    u64 first = 0;
    u64 last = 0;
    if (!IntegerArg(*runtime, state, 1, &first) || !IntegerArg(*runtime, state, 2, &last) ||
        first > UINT32_MAX || last > UINT32_MAX)
      return Fail(state, "callback address filter is invalid");
    filter = LuaDebuggerAddressFilter{static_cast<u32>(first), static_cast<u32>(last)};
    name_index = 3;
  }
  const std::string_view name = StringArg(*runtime, state, name_index);
  u64 id = 0;
  std::string error;
  if (!runtime->CallbackEvents().Register(kind, filter, std::string(name), &id, &error))
    return Fail(state, error);
  runtime->InternalImpl().api.pushinteger(state, static_cast<lua_Integer>(id));
  return 1;
}

int OnInstruction(lua_State* s) { return RegisterCallback(s, LuaDebuggerEventKind::Instruction, true); }
int OnFrame(lua_State* s) { return RegisterCallback(s, LuaDebuggerEventKind::Frame, false); }
int OnMemoryRead(lua_State* s) { return RegisterCallback(s, LuaDebuggerEventKind::MemoryRead, true); }
int OnMemoryWrite(lua_State* s) { return RegisterCallback(s, LuaDebuggerEventKind::MemoryWrite, true); }
int OnPresent(lua_State* s) { return RegisterCallback(s, LuaDebuggerEventKind::Present, false); }
int OnGXDraw(lua_State* s) { return RegisterCallback(s, LuaDebuggerEventKind::GXDraw, false); }
int OnEFBCopy(lua_State* s) { return RegisterCallback(s, LuaDebuggerEventKind::EFBCopy, false); }
int OnEffectivePipeline(lua_State* s)
{
  return RegisterCallback(s, LuaDebuggerEventKind::EffectivePipeline, false);
}
int OnGXCommand(lua_State* state)
{
  LuaDebuggerRuntime* runtime = Instance(state);
  if (!runtime)
    return Fail(state, "GX callback registration has no runtime");
  const int arguments = runtime->InternalImpl().api.gettop(state);
  if (arguments == 1)
    return RegisterCallback(state, LuaDebuggerEventKind::GXCommand, false);
  if (arguments == 3)
    return RegisterCallback(state, LuaDebuggerEventKind::GXCommand, true);
  return Fail(state, "GX callback requires name or first opcode, last opcode, name");
}

int UnregisterCallback(lua_State* state)
{
  LuaDebuggerRuntime* runtime = Instance(state);
  u64 id = 0;
  if (!runtime || !IntegerArg(*runtime, state, 1, &id) || id == 0 ||
      !runtime->CallbackEvents().Unregister(id))
  {
    return Fail(state, "callback registration id does not exist");
  }
  return 0;
}

void BudgetHook(lua_State* state, void*)
{
  LuaDebuggerRuntime* runtime = Instance(state);
  if (!runtime)
    return;
  if (runtime->InternalImpl().budget <= 1000)
    Fail(state, "Lua debugger instruction budget exhausted");
  runtime->InternalImpl().budget -= 1000;
}

void SetFunction(LuaDebuggerRuntime::Impl& impl, lua_State* state, const char* name,
                 lua_CFunction function)
{
  impl.api.pushcclosure(state, function, 0);
  impl.api.setfield(state, -2, name);
}
}  // namespace

LuaDebuggerRuntime::LuaDebuggerRuntime(LuaDebuggerSession& session,
                                       LuaDebuggerReadProviders providers,
                                       LuaDebuggerRuntimeLimits limits)
    : m_session(session), m_providers(std::move(providers)), m_limits(limits),
      m_events([this](const auto& registration, const auto& event) {
        Dispatch(registration, event);
      }),
      m_impl(std::make_unique<Impl>())
{
}

LuaDebuggerRuntime::~LuaDebuggerRuntime()
{
  Stop();
}

bool LuaDebuggerRuntime::Load(std::string runtime_library, std::span<const u8> script,
                              std::string canonical_name, std::string* error)
{
  if (m_impl->state || script.empty() || runtime_library.empty())
  {
    if (error)
      *error = "Lua debugger load requires a fresh runtime, explicit library, and script";
    return false;
  }
  std::vector<u8> runtime_bytes;
  const std::array<u8, 32> runtime_hash = HashFile(runtime_library, &runtime_bytes);
  if (runtime_bytes.empty() || !m_impl->library.Open(runtime_library.c_str()) ||
      !BindApi(*m_impl, error))
  {
    if (error && error->empty())
      *error = "Pinned Lua runtime could not be read or loaded";
    return false;
  }
  if (m_impl->api.version(nullptr) != 504.0)
  {
    if (error)
      *error = "Pinned Lua runtime is not ABI version 5.4";
    m_impl->library.Close();
    return false;
  }
  if (!m_events.Start(error) || !CreateStateAndRun(script, canonical_name, error))
  {
    Stop();
    return false;
  }
  if (!m_session.LoadInitialScript(script, std::move(canonical_name), runtime_hash, error))
  {
    Stop();
    return false;
  }
  return true;
}

bool LuaDebuggerRuntime::CreateStateAndRun(std::span<const u8> script, std::string_view name,
                                           std::string* error)
{
  bool ok = false;
  std::string task_error;
  if (!m_events.ExecuteSync([&] {
        m_impl->allocation = {0, m_limits.memory_bytes};
        m_impl->state = m_impl->api.newstate(LimitedAllocator, &m_impl->allocation);
        if (!m_impl->state)
        {
          task_error = "Lua state allocation failed";
          return;
        }
        {
          std::lock_guard lock(s_instances_mutex);
          s_instances.emplace(m_impl->state, this);
        }
        LuaApi& a = m_impl->api;
        a.requiref(m_impl->state, "_G", a.open_base, 1);
        a.settop(m_impl->state, -2);
        a.requiref(m_impl->state, "table", a.open_table, 1);
        a.settop(m_impl->state, -2);
        a.requiref(m_impl->state, "string", a.open_string, 1);
        a.settop(m_impl->state, -2);
        a.requiref(m_impl->state, "math", a.open_math, 1);
        a.settop(m_impl->state, -2);
        a.requiref(m_impl->state, "utf8", a.open_utf8, 1);
        a.settop(m_impl->state, -2);
        for (const char* forbidden : {"dofile", "loadfile", "load", "collectgarbage", "require",
                                      "io", "os", "package", "debug"})
        {
          a.pushnil(m_impl->state);
          a.setglobal(m_impl->state, forbidden);
        }
        a.createtable(m_impl->state, 0, 20);
        SetFunction(*m_impl, m_impl->state, "read_u8", ReadInteger<u8>);
        SetFunction(*m_impl, m_impl->state, "read_u16", ReadInteger<u16>);
        SetFunction(*m_impl, m_impl->state, "read_u32", ReadInteger<u32>);
        SetFunction(*m_impl, m_impl->state, "read_s8", ReadInteger<s8>);
        SetFunction(*m_impl, m_impl->state, "read_s16", ReadInteger<s16>);
        SetFunction(*m_impl, m_impl->state, "read_s32", ReadInteger<s32>);
        SetFunction(*m_impl, m_impl->state, "read_f32", ReadFloat32);
        SetFunction(*m_impl, m_impl->state, "read_f64", ReadFloat64);
        SetFunction(*m_impl, m_impl->state, "read_register", ReadRegister);
        SetFunction(*m_impl, m_impl->state, "write_u8", WriteInteger<u8>);
        SetFunction(*m_impl, m_impl->state, "write_u16", WriteInteger<u16>);
        SetFunction(*m_impl, m_impl->state, "write_u32", WriteInteger<u32>);
        SetFunction(*m_impl, m_impl->state, "write_register", WriteRegister);
        SetFunction(*m_impl, m_impl->state, "symbol", LookupSymbol);
        SetFunction(*m_impl, m_impl->state, "emit", Emit);
        SetFunction(*m_impl, m_impl->state, "on_instruction", OnInstruction);
        SetFunction(*m_impl, m_impl->state, "on_frame", OnFrame);
        SetFunction(*m_impl, m_impl->state, "on_memory_read", OnMemoryRead);
        SetFunction(*m_impl, m_impl->state, "on_memory_write", OnMemoryWrite);
        SetFunction(*m_impl, m_impl->state, "on_present", OnPresent);
        SetFunction(*m_impl, m_impl->state, "on_gx_command", OnGXCommand);
        SetFunction(*m_impl, m_impl->state, "on_gx_draw", OnGXDraw);
        SetFunction(*m_impl, m_impl->state, "on_efb_copy", OnEFBCopy);
        SetFunction(*m_impl, m_impl->state, "on_effective_pipeline", OnEffectivePipeline);
        SetFunction(*m_impl, m_impl->state, "unregister", UnregisterCallback);
        a.setglobal(m_impl->state, "soal");
        a.sethook(m_impl->state, BudgetHook, LUA_MASKCOUNT, 1000);
        m_impl->budget = m_limits.instructions_per_call;
        const std::string chunk_name = fmt::format("@{}", name);
        int result = a.loadbufferx(m_impl->state, reinterpret_cast<const char*>(script.data()),
                                   script.size(), chunk_name.c_str(), "t");
        if (result == LUA_OK)
          result = a.pcallk(m_impl->state, 0, LUA_MULTRET, 0, 0, nullptr);
        if (result != LUA_OK)
        {
          size_t size = 0;
          const char* message = a.tolstring(m_impl->state, -1, &size);
          task_error = message ? std::string(message, size) : "Lua script failed without message";
          a.settop(m_impl->state, 0);
          return;
        }
        a.settop(m_impl->state, 0);
        ok = true;
      }, error))
    return false;
  if (!ok && error)
    *error = std::move(task_error);
  return ok;
}

bool LuaDebuggerRuntime::Reload(std::span<const u8> script, std::string canonical_name,
                                std::string* error)
{
  if (!m_impl->state || script.empty())
  {
    if (error)
      *error = "Lua debugger reload requires a running state and script";
    return false;
  }
  if (!m_session.RecordReloadAttempt(script, canonical_name, error))
    return false;
  // Build the replacement transactionally. A failed script retains the previous state and active
  // identity, while the attempted script remains permanently logged and makes the run exploratory.
  m_events.WaitUntilIdle();
  lua_State* const old_state = m_impl->state;
  const std::vector<LuaDebuggerCallbackRegistration> old_registrations =
      m_events.Registrations();
  m_impl->state = nullptr;
  const bool created = CreateStateAndRun(script, canonical_name, error);
  lua_State* const replacement_state = m_impl->state;
  if (!created)
  {
    if (replacement_state)
    {
      m_events.ExecuteSync([&] {
        std::lock_guard lock(s_instances_mutex);
        s_instances.erase(replacement_state);
        m_impl->api.close(replacement_state);
      });
    }
    m_impl->state = old_state;
    for (const auto& registration : m_events.Registrations())
    {
      if (std::ranges::none_of(old_registrations, [&](const auto& old_registration) {
            return old_registration.id == registration.id;
          }))
      {
        m_events.Unregister(registration.id);
      }
    }
    return false;
  }
  m_events.ExecuteSync([&] {
    std::lock_guard lock(s_instances_mutex);
    s_instances.erase(old_state);
    m_impl->api.close(old_state);
  });
  for (const auto& registration : old_registrations)
    m_events.Unregister(registration.id);
  if (!m_session.CommitReloadScript(script, std::move(canonical_name), error))
  {
    AppendError("Lua reload identity commit failed after replacement started");
    return false;
  }
  return true;
}

bool LuaDebuggerRuntime::EvaluateConsole(std::span<const u8> command, std::string* error)
{
  if (!m_session.RecordConsole(command, error))
    return false;
  bool ok = false;
  std::string task_error;
  if (!m_events.ExecuteSync([&] {
        LuaApi& a = m_impl->api;
        m_impl->budget = m_limits.instructions_per_call;
        int result = a.loadbufferx(m_impl->state, reinterpret_cast<const char*>(command.data()),
                                   command.size(), "=console", "t");
        if (result == LUA_OK)
          result = a.pcallk(m_impl->state, 0, LUA_MULTRET, 0, 0, nullptr);
        if (result != LUA_OK)
        {
          size_t size = 0;
          const char* message = a.tolstring(m_impl->state, -1, &size);
          task_error = message ? std::string(message, size) : "Lua console failed";
        }
        a.settop(m_impl->state, 0);
        ok = result == LUA_OK;
      }, error))
    return false;
  if (!ok && error)
    *error = std::move(task_error);
  return ok;
}

void LuaDebuggerRuntime::Dispatch(const LuaDebuggerCallbackRegistration& registration,
                                  const LuaDebuggerEvent& event)
{
  LuaApi& a = m_impl->api;
  m_impl->budget = m_limits.instructions_per_call;
  if (a.getglobal(m_impl->state, registration.lua_function.c_str()) == 0)
  {
    AppendError(fmt::format("callback {} is not defined", registration.lua_function));
    a.settop(m_impl->state, 0);
    return;
  }
  a.createtable(m_impl->state, 0, 48);
  const auto integer_field = [&](const char* name, u64 value) {
    a.pushinteger(m_impl->state, static_cast<lua_Integer>(value));
    a.setfield(m_impl->state, -2, name);
  };
  const std::string_view kind = EventKindName(event.kind);
  a.pushlstring(m_impl->state, kind.data(), kind.size());
  a.setfield(m_impl->state, -2, "kind");
  integer_field("kind_id", static_cast<u8>(event.kind));
  integer_field("emulated_ticks", event.emulated_ticks);
  integer_field("source_ordinal", event.source_ordinal);
  integer_field("address", event.address);
  integer_field("value", event.value);
  integer_field("size", event.size);
  integer_field("auxiliary", event.auxiliary);
  integer_field("pc", event.pc);
  integer_field("link_register", event.link_register);
  integer_field("gx_prefix", event.gx_prefix);
  integer_field("gx_prefix_size", event.gx_prefix_size);
  const char* const gx_payload = event.gx_payload.empty() ?
                                     "" :
                                     reinterpret_cast<const char*>(event.gx_payload.data());
  a.pushlstring(m_impl->state, gx_payload, event.gx_payload.size());
  a.setfield(m_impl->state, -2, "gx_payload");
  integer_field("gx_payload_size", event.gx_payload.size());
  const char* const gx_state_payload = event.gx_state_payload.empty() ?
                                           "" :
                                           reinterpret_cast<const char*>(
                                               event.gx_state_payload.data());
  a.pushlstring(m_impl->state, gx_state_payload, event.gx_state_payload.size());
  a.setfield(m_impl->state, -2, "gx_state_payload");
  integer_field("gx_state_payload_size", event.gx_state_payload.size());
  a.pushlstring(m_impl->state,
                reinterpret_cast<const char*>(event.gx_state_sha256.data()),
                event.gx_state_sha256.size());
  a.setfield(m_impl->state, -2, "gx_state_sha256");
  const char* const pipeline_definition = event.effective_pipeline_definition.empty() ?
                                              "" :
                                              reinterpret_cast<const char*>(
                                                  event.effective_pipeline_definition.data());
  a.pushlstring(m_impl->state, pipeline_definition,
                event.effective_pipeline_definition.size());
  a.setfield(m_impl->state, -2, "effective_pipeline_definition");
  integer_field("effective_pipeline_definition_size",
                event.effective_pipeline_definition.size());
  a.pushlstring(m_impl->state,
                reinterpret_cast<const char*>(
                    event.effective_pipeline_definition_sha256.data()),
                event.effective_pipeline_definition_sha256.size());
  a.setfield(m_impl->state, -2, "effective_pipeline_definition_sha256");
  const char* const pipeline_bindings = event.effective_pipeline_bindings.empty() ?
                                            "" :
                                            reinterpret_cast<const char*>(
                                                event.effective_pipeline_bindings.data());
  a.pushlstring(m_impl->state, pipeline_bindings, event.effective_pipeline_bindings.size());
  a.setfield(m_impl->state, -2, "effective_pipeline_bindings");
  integer_field("effective_pipeline_bindings_size", event.effective_pipeline_bindings.size());
  a.pushlstring(m_impl->state,
                reinterpret_cast<const char*>(event.effective_pipeline_bindings_sha256.data()),
                event.effective_pipeline_bindings_sha256.size());
  a.setfield(m_impl->state, -2, "effective_pipeline_bindings_sha256");
  integer_field("effective_draw_kind", event.effective_draw_kind);
  integer_field("effective_draw_base", event.effective_draw_base);
  integer_field("effective_draw_count", event.effective_draw_count);
  integer_field("effective_base_vertex", event.effective_base_vertex);
  integer_field("video_frame_ordinal", event.video_frame_ordinal);
  integer_field("gx_command_ordinal", event.gx_command_ordinal);
  integer_field("gx_draw_ordinal", event.gx_draw_ordinal);
  integer_field("gx_frame_draw_ordinal", event.gx_frame_draw_ordinal);
  integer_field("gx_primitive", event.gx_primitive);
  integer_field("gx_vat", event.gx_vat);
  integer_field("gx_vertex_size", event.gx_vertex_size);
  integer_field("gx_vertex_count", event.gx_vertex_count);
  integer_field("presentation_snapshot_valid", event.presentation_snapshot_valid ? 1 : 0);
  integer_field("title_state", event.title_state);
  integer_field("fade_status", event.fade_words[0]);
  integer_field("fade_in_progress", event.fade_words[1]);
  integer_field("fade_color_rgba", event.fade_words[2]);
  integer_field("fade_progress_bits", event.fade_words[3]);
  integer_field("fade_duration_bits", event.fade_words[4]);
  integer_field("fade_step_add", event.fade_words[5]);
  integer_field("render_resource_id", event.render_resource_id);
  integer_field("render_resource_hash", event.render_resource_hash);
  integer_field("render_resource_base_hash", event.render_resource_base_hash);
  integer_field("render_resource_content_ordinal", event.render_resource_content_ordinal);
  integer_field("xfb_address", event.xfb_address);
  integer_field("xfb_stride", event.xfb_stride);
  integer_field("xfb_width", event.xfb_width);
  integer_field("xfb_height", event.xfb_height);
  integer_field("efb_left", event.efb_left);
  integer_field("efb_top", event.efb_top);
  integer_field("efb_right", event.efb_right);
  integer_field("efb_bottom", event.efb_bottom);
  integer_field("copy_filter_prev", event.copy_filter_coefficients[0]);
  integer_field("copy_filter_current", event.copy_filter_coefficients[1]);
  integer_field("copy_filter_next", event.copy_filter_coefficients[2]);
  integer_field("copy_gamma_bits", event.copy_gamma_bits);
  integer_field("copy_y_scale_bits", event.copy_y_scale_bits);
  integer_field("copy_parameter_flags", event.copy_parameter_flags);
  integer_field("render_flags", event.render_flags);
  integer_field("raw_pixel_capture_valid", event.raw_pixel_capture_valid ? 1 : 0);
  a.pushlstring(m_impl->state,
                reinterpret_cast<const char*>(event.efb_source_pixels_sha256.data()),
                event.efb_source_pixels_sha256.size());
  a.setfield(m_impl->state, -2, "efb_source_pixels_sha256");
  a.pushlstring(m_impl->state,
                reinterpret_cast<const char*>(event.xfb_copy_pixels_sha256.data()),
                event.xfb_copy_pixels_sha256.size());
  a.setfield(m_impl->state, -2, "xfb_copy_pixels_sha256");
  integer_field("captured_pixel_width", event.captured_pixel_width);
  integer_field("captured_pixel_height", event.captured_pixel_height);
  integer_field("captured_pixel_stride", event.captured_pixel_stride);
  integer_field("captured_pixel_format", event.captured_pixel_format);
  integer_field("presented_frame_number", event.presented_frame_number);
  integer_field("present_pixel_hash_valid", event.present_pixel_hash_valid ? 1 : 0);
  a.pushlstring(m_impl->state,
                reinterpret_cast<const char*>(event.present_pixel_sha256.data()),
                event.present_pixel_sha256.size());
  a.setfield(m_impl->state, -2, "present_pixel_sha256");
  integer_field("present_pixel_width", event.present_pixel_width);
  integer_field("present_pixel_height", event.present_pixel_height);
  integer_field("present_pixel_stride", event.present_pixel_stride);
  integer_field("present_pixel_format", event.present_pixel_format);
  a.pushlstring(m_impl->state, event.render_source.data(), event.render_source.size());
  a.setfield(m_impl->state, -2, "render_source");
  const int result = a.pcallk(m_impl->state, 1, 0, 0, 0, nullptr);
  if (result != LUA_OK)
  {
    size_t size = 0;
    const char* message = a.tolstring(m_impl->state, -1, &size);
    AppendError(message ? std::string(message, size) : "Lua callback failed");
  }
  a.settop(m_impl->state, 0);
}

void LuaDebuggerRuntime::Stop()
{
  if (m_impl && m_impl->state)
  {
    m_events.WaitUntilIdle();
    m_events.ExecuteSync([&] {
      std::lock_guard lock(s_instances_mutex);
      s_instances.erase(m_impl->state);
      m_impl->api.close(m_impl->state);
      m_impl->state = nullptr;
    });
  }
  m_events.Stop();
  if (m_impl)
    m_impl->library.Close();
}

bool LuaDebuggerRuntime::Enqueue(LuaDebuggerEvent event, std::string* error)
{
  return m_events.Enqueue(std::move(event), error);
}

void LuaDebuggerRuntime::WaitUntilIdle()
{
  m_events.WaitUntilIdle();
}

void LuaDebuggerRuntime::AppendOutput(std::string record)
{
  bool exhausted = false;
  {
    std::lock_guard lock(m_records_mutex);
    if (m_output.size() < m_limits.output_records)
      m_output.push_back(std::move(record));
    else
      exhausted = true;
  }
  if (exhausted)
    AppendError("Lua structured output capacity exhausted");
}

void LuaDebuggerRuntime::AppendError(std::string error)
{
  m_session.RecordRuntimeFailure(error);
  std::lock_guard lock(m_records_mutex);
  m_errors.push_back(std::move(error));
}

std::vector<std::string> LuaDebuggerRuntime::TakeOutput()
{
  std::lock_guard lock(m_records_mutex);
  return std::exchange(m_output, {});
}

std::vector<std::string> LuaDebuggerRuntime::TakeErrors()
{
  std::lock_guard lock(m_records_mutex);
  return std::exchange(m_errors, {});
}
}  // namespace SoAL
