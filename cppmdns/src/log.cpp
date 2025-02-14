#include "log.hpp"

#include <filesystem>

namespace __log_detail{
    std::ostream& log_stream(std::ostream& os, const std::source_location& loc){
        std::filesystem::path p(loc.file_name());
        os << p.filename().string() << ":" << loc.line() << ": ";
        return os;
    }
}