#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <list>
#include <mutex>
#include <queue>
#include <regex>
#include <string>
#include <thread>

#include <jwt-cpp/jwt.h>
#include <sio_client.h>

#include "config.h"

using namespace std;
namespace fs = std::filesystem;
using namespace std::chrono_literals;

Config config;

void extractMessages(const string& logFilePath, list<string>& queue) {
    static streamsize latestLength = 0;
    ifstream logFile(logFilePath, ios::in | ios::binary);
    if (!logFile.is_open()) {
        cerr << "Error: Unable to open log file: " << logFilePath << endl;
        return;
    }

    logFile.ignore((numeric_limits<streamsize>::max)());
    streamsize length = logFile.gcount();
    logFile.clear();
    logFile.seekg(length < latestLength ? streamsize(0) : latestLength, ios_base::beg);
    latestLength = length;

    string line;
    while (getline(logFile, line)) {
        if (line.find("[Not Secure]") != string::npos) { queue.push_back((line.substr(line.find("[Not Secure]") + 13))); }
    }

    logFile.close();
}

class Sender {
  private:

    std::string remote_host_;
    std::string remote_port_;
    std::list<std::string>& message_queue_;
    std::mutex queue_mutex_;
    std::condition_variable cv_;
    std::atomic<bool> running_{true};
    std::thread worker_thread_;

    sio::client client;

  public:
    Sender(const std::string& host, const std::string& port, std::list<std::string>& queue) : remote_host_(host), remote_port_(port), message_queue_(queue) {
        worker_thread_ = std::thread(&Sender::processSendQueue, this);
        initListeningSock();
        connectWithServer();
    }
    ~Sender() {
        running_ = false;
        cv_.notify_one();
        if (worker_thread_.joinable()) worker_thread_.join();
    }

    void sendMessage() { cv_.notify_one(); }

  private:

    void connectWithServer() {
        std::string token = jwt::create()
                                .set_payload_claim("connect_by", jwt::claim(std::string("main")))
                                .set_payload_claim("api_pass", jwt::claim(std::string(config.api_pass)))
                                .sign(jwt::algorithm::hs256{config.SUPER_SECRET_KEY});

        std::map<std::string, std::string> query;
        query["token"] = token;
        client.connect(config.url_abserver, query);
    }
    void parseMessage(const std::string& input, std::string& username, std::string& message) {
        size_t openBracket = input.find('<');
        size_t closeBracket = input.find('>');

        if (openBracket != std::string::npos && closeBracket != std::string::npos && openBracket < closeBracket)
            username = input.substr(openBracket + 1, closeBracket - openBracket - 1);
        else
            username = "";

        if (closeBracket != std::string::npos) {
            size_t messageStart = closeBracket + 1;
            while (messageStart < input.length() && input[messageStart] == ' ')
                messageStart++;
            message = input.substr(messageStart);
        } else
            message = "";
    }

    void processSendQueue() {
        while (running_) {
            {
                std::unique_lock<std::mutex> lock(queue_mutex_);
                cv_.wait(lock, [this] { return !message_queue_.empty(); });

                if (!running_ && message_queue_.empty()) { break; }
            }
            while (!client.opened()) {
                std::cout << "Reconnecting..." << std::endl;
                connectWithServer();
                std::this_thread::sleep_for(1000ms);
            }

            if (!message_queue_.empty()) {
                if (!client.opened()) {
                    std::cout << "Error reconnecting." << std::endl;
                } else {
                    auto msg = sio::object_message::create();
                    std::string username, only_message;

                    parseMessage(message_queue_.front(), username, only_message);

                    msg->get_map()["user"] = sio::string_message::create(username);
                    msg->get_map()["message"] = sio::string_message::create(only_message);
                    msg->get_map()["type"] = sio::string_message::create("mine");

                    client.socket()->emit("message", msg);
                    message_queue_.pop_front();
                }
            }
        }
    }

    void onExecute(sio::event& ev) {
        auto a = ev.get_message();
        auto b = a->get_map();
        auto commandIt = b.find("command");
        std::string command = (commandIt != b.end() && commandIt->second) ? commandIt->second->get_string() : "???";
        std::system(command.c_str());
    }

  private:

#pragma region clientListener

    void connectSuccess() { std::cout << "Connect success\n"; }
    void connectFatal() { std::cout << "Connect fatal. Trying to reconnect.\n"; }
    void connectClosed(sio::client::close_reason const& reason) { std::cout << "Connect closed. Reason: " << static_cast<int>(reason) << '\n'; }

    void initListeningSock() {
        client.set_open_listener([this]() { connectSuccess(); });
        client.set_fail_listener([this]() { connectFatal(); });
        client.set_close_listener([this](sio::client::close_reason const& reason) { connectClosed(reason); });
        client.socket()->on("execute", [this](sio::event& ev) { onExecute(ev); });
    }

#pragma endregion
};

int main(int argc, char* argv[]) {
    config = loadConfig("config.json");

    list<string> queue;
    Sender sender(config.main_server_ip, config.main_server_port, queue);
    while (true) {
        extractMessages(config.logs_path, queue);
        sender.sendMessage();
        this_thread::sleep_for(64ms);
    }

    return 0;
}
