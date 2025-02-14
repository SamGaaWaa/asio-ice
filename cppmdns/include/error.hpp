#pragma once

#include <system_error>

namespace mdns{
    enum struct error{
        no_error,
        out_of_range,
        invalid_format,
        invalid_domain_name,
        invalid_result,
        service_already_exists
    };

    struct mdns_error_category final: std::error_category{
        const char *name()const noexcept override{
            return "cpp-mdns";
        }

        std::string message(int ev)const override{
            switch ((error)ev)
            {
            case error::no_error:
                return "No error.";
            case error::out_of_range:
                return "Out of range.";
            case error::invalid_format:
                return "Invalid format.";
            case error::invalid_domain_name:
                return "Invalid domain name.";
            case error::invalid_result:
                return "Invalid result.";
            case error::service_already_exists:
                return "Service already exists.";
            default:
                return "Unknown error.";
            }
        }
    };

    const std::error_category& mdns_category()noexcept;

}