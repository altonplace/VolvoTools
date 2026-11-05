#include <common/CarPlatform.hpp>
#include <common/ICanChannel.hpp>
#include <common/J2534ChannelProvider.hpp>
#include <common/Util.hpp>
#include <common/protocols/D2Messages.hpp>
#include <common/protocols/D2Request.hpp>

#include <j2534/J2534.hpp>

#include <easylogging++.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <deque>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

INITIALIZE_EASYLOGGINGPP

namespace {

constexpr uint32_t kEcuId = 0x7A;
constexpr uint32_t kDefaultStart = 0x800000;
constexpr uint32_t kDefaultSize = 0x100;
constexpr uint32_t kMaxAddressExclusive = 0x1000000; // D2 0xBB uses a 24-bit address.
uint32_t kChunkSize = 8;

uint32_t parseHex(const char* value)
{
    size_t consumed = 0;
    const unsigned long parsed = std::stoul(value, &consumed, 16);
    if (consumed != std::string(value).size()) {
        throw std::runtime_error(std::string("Invalid hex value: ") + value);
    }
    return static_cast<uint32_t>(parsed);
}

std::vector<common::CanFrame> makeD2ResponseFrames(const std::vector<uint8_t>& payload)
{
    std::vector<common::CanFrame> frames;
    constexpr size_t maxPayloadPerFrame = 7;
    uint8_t seriesCounter = 0;

    for (size_t offset = 0; offset < payload.size(); offset += maxPayloadPerFrame) {
        const size_t chunk = std::min(maxPayloadPerFrame, payload.size() - offset);
        const bool first = offset == 0;
        const bool last = offset + chunk >= payload.size();

        uint8_t header = 0;
        if (first && last) {
            header = static_cast<uint8_t>(0xC8 + chunk);
        }
        else if (first) {
            header = static_cast<uint8_t>(0x88 + chunk);
        }
        else if (last) {
            header = static_cast<uint8_t>(0x48 + chunk);
        }
        else {
            seriesCounter = static_cast<uint8_t>((seriesCounter + 1) & 0x07);
            header = static_cast<uint8_t>(0x08 + seriesCounter);
        }

        std::vector<uint8_t> data;
        data.reserve(chunk + 1);
        data.push_back(header);
        data.insert(data.end(), payload.begin() + offset, payload.begin() + offset + chunk);
        frames.push_back({common::D2Message::CanId, std::move(data), true});
    }

    return frames;
}

class MockD2Channel final : public common::ICanChannel {
public:
    bool send(const common::CanFrame& frame, unsigned long) override
    {
        if (frame.id != common::D2Message::CanId || !frame.isExtendedId || frame.data.size() < 7) {
            return false;
        }
        if (frame.data[1] != kEcuId || frame.data[2] != 0xBB) {
            return false;
        }

        const uint32_t address = (static_cast<uint32_t>(frame.data[3]) << 16)
                               | (static_cast<uint32_t>(frame.data[4]) << 8)
                               | static_cast<uint32_t>(frame.data[5]);
        const uint8_t size = frame.data[6];

        std::vector<uint8_t> responsePayload{
            static_cast<uint8_t>(kEcuId),
            0xFB,
            frame.data[3], frame.data[4], frame.data[5], size
        };
        for (uint32_t i = 0; i < size; ++i) {
            responsePayload.push_back(static_cast<uint8_t>((address + i) & 0xFF));
        }

        auto responseFrames = makeD2ResponseFrames(responsePayload);
        for (auto& response : responseFrames) {
            _rx.push_back(std::move(response));
        }
        ++_requestCount;
        return true;
    }

    bool send(const std::vector<common::CanFrame>& frames, unsigned long timeout) override
    {
        for (const auto& frame : frames) {
            if (!send(frame, timeout)) {
                return false;
            }
        }
        return true;
    }

    bool receive(common::CanFrame& frame, unsigned long) override
    {
        if (_rx.empty()) {
            return false;
        }
        frame = std::move(_rx.front());
        _rx.pop_front();
        return true;
    }

    bool receive(std::vector<common::CanFrame>& frames, size_t messagesCount, unsigned long timeout) override
    {
        frames.clear();
        for (size_t i = 0; i < messagesCount; ++i) {
            common::CanFrame frame;
            if (!receive(frame, timeout)) {
                return false;
            }
            frames.push_back(std::move(frame));
        }
        return true;
    }

    void clearRx() override { _rx.clear(); }
    void clearTx() override {}
    bool startPeriodicMsg(const common::CanFrame&, unsigned long, unsigned long&) override { return true; }
    bool stopPeriodicMsg(unsigned long) override { return true; }
    unsigned long getBaudrate() const override { return 250000; }
    bool startMsgFilter(unsigned long, const common::CanFrame&, const common::CanFrame&, const common::CanFrame*, unsigned long&) override { return true; }
    bool stopMsgFilter(unsigned long) override { return true; }
    bool setConfig(unsigned long, unsigned long) override { return true; }
    bool ioctl(unsigned long, const void*, void*) override { return true; }

    size_t requestCount() const { return _requestCount; }

private:
    std::deque<common::CanFrame> _rx;
    size_t _requestCount = 0;
};

std::vector<uint8_t> readRange(common::ICanChannel& channel, uint32_t start, uint32_t size, bool showProgress)
{
    std::vector<uint8_t> data;
    data.reserve(size);

    for (uint32_t offset = 0; offset < size; offset += kChunkSize) {
        const uint32_t currentAddress = start + offset;
        const uint32_t chunk = std::min(kChunkSize, size - offset);

        channel.clearRx();
        channel.clearTx();

        common::D2Request request{
            common::D2Messages::createReadDataByAddrMsg(
                static_cast<uint8_t>(kEcuId),
                currentAddress,
                static_cast<uint8_t>(chunk))
        };

        const auto response = request.process(channel, 1500);
        if (response.size() < chunk) {
            std::ostringstream error;
            error << "Short response at 0x" << std::hex << std::uppercase << currentAddress
                  << ": got " << std::dec << response.size()
                  << " bytes, expected " << chunk;
            throw std::runtime_error(error.str());
        }

        data.insert(data.end(), response.begin(), response.begin() + chunk);

        const uint32_t done = offset + chunk;
        if (showProgress && (done == size || (done % 0x100) == 0)) {
            std::cout << "  " << std::dec << done << "/" << size << " bytes\n";
        }
    }

    return data;
}

int runSelfTest()
{
    MockD2Channel channel;
    const auto data = readRange(channel, kDefaultStart, kDefaultSize, false);

    if (data.size() != kDefaultSize) {
        throw std::runtime_error("Self-test failed: wrong output size");
    }
    if (channel.requestCount() != kDefaultSize / kChunkSize) {
        throw std::runtime_error("Self-test failed: wrong request count");
    }
    for (uint32_t i = 0; i < kDefaultSize; ++i) {
        const uint8_t expected = static_cast<uint8_t>((kDefaultStart + i) & 0xFF);
        if (data[i] != expected) {
            std::ostringstream error;
            error << "Self-test failed at offset 0x" << std::hex << i
                  << ": got 0x" << static_cast<int>(data[i])
                  << ", expected 0x" << static_cast<int>(expected);
            throw std::runtime_error(error.str());
        }
    }

    std::cout << "SELFTEST PASS\n"
              << "  D2 0xBB request framing: OK\n"
              << "  Multi-frame response parsing: OK\n"
              << "  8-byte chunk loop: OK\n"
              << "  256-byte assembled read: OK\n";
    return 0;
}

void printUsage(const char* exe)
{
    std::cout
        << "Read-only Volvo ME7 RAM snapshot tool (D2 service 0xBB), P2 250k by default\n\n"
        << "Usage:\n"
        << "  " << exe << " [output_prefix] [start_hex] [size_hex] [snapshots] [chunk_hex] [platform]\n"
        << "  Each snapshot is saved as <prefix>_<n>.bin; Enter is awaited between snapshots.\n"
        << "  " << exe << " --selftest\n\n"
        << "Defaults:\n"
        << "  output.bin = c70_read_test.bin\n"
        << "  start_hex  = 800000\n"
        << "  size_hex   = 100 (256 bytes)\n\n"
        << "This tool contains NO flash/erase/write commands.\n";
}

} // namespace

int main(int argc, char* argv[])
{
    try {
        common::initLogger("ram_dump.log", true, true);

        if (argc > 1 && (std::string(argv[1]) == "--help" || std::string(argv[1]) == "-h")) {
            printUsage(argv[0]);
            return 0;
        }
        if (argc > 1 && std::string(argv[1]) == "--selftest") {
            return runSelfTest();
        }

        const std::string outputPrefix = argc > 1 ? argv[1] : "ram";
        const uint32_t start = argc > 2 ? parseHex(argv[2]) : 0xE000;
        const uint32_t size = argc > 3 ? parseHex(argv[3]) : 0x2000;
        const unsigned snapshots = argc > 4 ? static_cast<unsigned>(std::stoul(argv[4])) : 1u;
        if (argc > 5) kChunkSize = parseHex(argv[5]);
        const std::string platformName = argc > 6 ? argv[6] : "P2_250";

        if (size == 0 || kChunkSize == 0 || kChunkSize > 0xF0) {
            throw std::runtime_error("Bad size or chunk");
        }
        if (start >= kMaxAddressExclusive || size > kMaxAddressExclusive - start) {
            throw std::runtime_error("Requested range is outside the 24-bit D2 address space");
        }

        const auto devices = common::getAvailableDevices();
        if (devices.empty()) {
            std::cerr << "No J2534 device found\n";
            return 2;
        }
        const auto& device = devices.front();
        std::cout << "Device: " << device.deviceName << "\n";
        std::cout << "Platform: " << platformName << ", ECU: 0x7A\n";
        std::cout << "Read range: 0x" << std::hex << std::uppercase << start
                  << " - 0x" << (start + size - 1) << ", chunk 0x" << kChunkSize << "\n" << std::dec;

        auto j2534 = std::make_unique<j2534::J2534>(device.libraryName);
        j2534->PassThruOpen(device.deviceName.find("DiCE-") != std::string::npos ? device.deviceName : "");

        common::J2534ChannelProvider channelProvider(*j2534, common::parseCarPlatform(platformName));
        auto channel = channelProvider.getChannelForEcu(kEcuId);
        if (!channel) {
            throw std::runtime_error("Could not open the ECM CAN channel");
        }

        for (unsigned n = 1; n <= snapshots; ++n) {
            if (n > 1) {
                std::cout << "Snapshot " << n << ": set the car up, then press Enter\n";
                std::string line;
                std::getline(std::cin, line);
            }
            std::cout << "Reading snapshot " << n << " via D2 service 0xBB...\n";
            const auto t0 = std::chrono::steady_clock::now();
            const auto data = readRange(*channel, start, size, true);
            const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
            const std::string outputPath = outputPrefix + "_" + std::to_string(n) + ".bin";
            std::ofstream output(outputPath, std::ios::binary | std::ios::trunc);
            if (!output) {
                throw std::runtime_error("Could not create output file: " + outputPath);
            }
            output.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
            std::cout << "SUCCESS: saved " << data.size() << " bytes to " << outputPath << " in " << ms << " ms\n";
        }
        return 0;
    }
    catch (const std::exception& ex) {
        std::cerr << "ERROR: " << ex.what() << "\n";
        return 1;
    }
    catch (...) {
        std::cerr << "ERROR: unknown exception\n";
        return 1;
    }
}
