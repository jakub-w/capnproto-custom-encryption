#pragma once

namespace {
using byte = unsigned char;

static auto is_all_zeros =
    [](const auto& container){
      return not std::any_of(std::begin(container), std::end(container),
                             [](byte b){ return b != 0; });
    };
}
