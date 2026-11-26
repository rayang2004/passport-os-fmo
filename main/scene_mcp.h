#pragma once
#include <cstddef>
#include <cstdint>
#include <string>
struct cJSON;
namespace scenes {
size_t tool_count();
const char *tool_schema(size_t index);
std::string call(const char *name, const cJSON *arguments, uint64_t token);
}
