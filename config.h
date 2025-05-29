#ifndef CONFIG_H
#define CONFIG_H

#include <filesystem>
#include <fstream>
#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

struct Config {
    std::string logs_path;
    std::string main_server_ip;
    std::string main_server_port;
    std::string url_abserver;
    std::string api_pass;
    std::string SUPER_SECRET_KEY;
    std::string latest_length_path;
    NLOHMANN_DEFINE_TYPE_INTRUSIVE_WITH_DEFAULT(Config, logs_path, main_server_ip, main_server_port, url_abserver, api_pass, latest_length_path, SUPER_SECRET_KEY)
};

inline Config loadConfig(const std::string &config_path) {
    std::ifstream config_file(config_path);
    auto config = json::parse(config_file);
    config_file.close();
    return config.template get<Config>();
}

#endif // CONFIG_H
