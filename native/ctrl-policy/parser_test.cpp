#include "parser.hpp"
#include <cassert>
#include <cstdio>
#include <utility>
using namespace securelink::ctrl;

Option valid(std::string domain = "portal.example.edu", std::string ips = "192.0.2.1;192.0.2.2") {
    return {"ctrl", "domain:" + domain, "sourceIp:" + ips};
}
void fails(const Options &input, Failure expected) {
    bool rejected = false;
    try { (void)parse(input); }
    catch (const Invalid &error) {
        assert(error.failure == expected);
        assert(std::string(error.what()) == "unsupported ctrl policy");
        assert(std::string(error.what()).find("SECRET") == std::string::npos);
        rejected = true;
    }
    assert(rejected);
}
int main() {
    auto result = parse({valid()});
    assert(result.optionCount == 1 && result.mappings.size() == 1);
    assert(result.mappings[0].domain == "portal.example.edu");
    assert((result.mappings[0].addresses == std::vector<std::string>{"192.0.2.1", "192.0.2.2"}));
    assert(result.mappings[0].addressPolicyAny);
    auto single = parse({{"ctrl", "  domain:portal.example.edu   sourceIp:192.0.2.1&192.0.2.2  "}});
    assert(single.mappings[0].domain == result.mappings[0].domain);
    assert(single.mappings[0].addresses == result.mappings[0].addresses);
    auto keys = parse({{"ctrl", "domain:First.example", "domain:Second.example", "sourceIp:192.0.2.1", "sourceIp:192.0.2.2"}});
    assert(keys.duplicateKeys == 2 && keys.mappings[0].domain == "First.example");
    assert(keys.mappings[0].addresses[0] == "192.0.2.1");
    fails({{"ctrl", "domain:", "domain:example.edu", "sourceIp:192.0.2.1"}}, Failure::UnsupportedDomain);
    fails({{"ctrl", "domain:example.edu", "sourceIp:SECRET", "sourceIp:192.0.2.1"}}, Failure::UnsupportedAddress);
    fails({valid(), valid("portal.example.edu", "SECRET")}, Failure::UnsupportedAddress);
    auto domains = parse({valid(), valid("portal.example.edu", "198.51.100.1")});
    assert(domains.duplicateDomains == 1 && domains.mappings.size() == 1);
    assert(domains.mappings[0].addresses[0] == "192.0.2.1");
    auto caseSensitive = parse({valid("Portal.example.edu"), valid("portal.example.edu")});
    assert(caseSensitive.mappings.size() == 2);
    auto duplicates = parse({valid("portal.example.edu", "192.0.2.1;192.0.2.1")});
    assert(duplicates.mappings[0].addresses.size() == 2);

    // A new generation is a replacement value, and a failed parse cannot
    // partially mutate the caller's already-published policy.
    auto current = parse({valid()});
    try { current = parse({valid("new.example"), {"ctrl", "SECRET"}}); assert(false); }
    catch (const Invalid &) {}
    assert(current.mappings.size() == 1 && current.mappings[0].domain == "portal.example.edu");
    current = parse({valid("new.example", "198.51.100.3")});
    assert(current.mappings.size() == 1 && current.mappings[0].domain == "new.example");
    current = parse({});
    assert(current.mappings.empty() && current.optionCount == 0);

    fails({{}}, Failure::MalformedOption);
    fails({{"domain", "example.edu"}}, Failure::MalformedOption);
    fails({{"ctrl"}}, Failure::MalformedOption);
    fails({{"ctrl", " "}}, Failure::MalformedOption);
    fails({{"ctrl", "domain:example.edu"}}, Failure::MissingField);
    fails({{"ctrl", "sourceIp:192.0.2.1"}}, Failure::MissingField);
    fails({{"ctrl", "Domain:example.edu", "sourceIp:192.0.2.1"}}, Failure::UnsupportedKey);
    fails({{"ctrl", "addr:SECRET", "domain:example.edu", "sourceIp:192.0.2.1"}}, Failure::UnsupportedKey);
    fails({{"ctrl", "unknown:SECRET", "domain:example.edu", "sourceIp:192.0.2.1"}}, Failure::UnsupportedKey);
    fails({{"ctrl", "domain:example.edu", "sourceIp:2001:db8::1"}}, Failure::MalformedOption);
    fails({{"ctrl", "domain:example.edu\nSECRET", "sourceIp:192.0.2.1"}}, Failure::MalformedOption);
    fails({{"ctrl", std::string("domain:example.edu\0SECRET", 25), "sourceIp:192.0.2.1"}}, Failure::MalformedOption);
    fails({{"ctrl", "domain:example.edu\t", "sourceIp:192.0.2.1"}}, Failure::MalformedOption);
    fails({{"ctrl", "domain:é.example", "sourceIp:192.0.2.1"}}, Failure::MalformedOption);
    for (const auto &domain : {"", "*.example.edu", ".example.edu", "example.edu.", "bad..example", "-bad.example", "bad-.example", "bad_name.example"})
        fails({valid(domain)}, Failure::UnsupportedDomain);
    fails({valid(std::string(64, 'a') + ".example")}, Failure::UnsupportedDomain);
    for (const auto &ip : {"", "192.0.2", "192.0.2.256", "192.0.2.-1", "192.0.2.1/32", "192.0.02.1", "192.0.2.1;", ";192.0.2.1", "192.0.2.1;;192.0.2.2", "1.2.3.4.5", "SECRET"})
        fails({valid("example.edu", ip)}, Failure::UnsupportedAddress);
    fails({{"ctrl", "domain:example.edu", "sourceIp:192.0.2.1:80"}}, Failure::MalformedOption);
    assert(ipv4("0.0.0.0") && ipv4("255.255.255.255")); // numeric syntax only; not routing authority

    const std::string longestDomain = std::string(63, 'a') + "." + std::string(63, 'b') + "." + std::string(63, 'c') + "." + std::string(61, 'd');
    assert(longestDomain.size() == 253 && exactDomain(longestDomain));
    assert(parse({valid(longestDomain)}).mappings.size() == 1);
    fails({valid(longestDomain + "e")}, Failure::UnsupportedDomain);
    Option exactLimit{"ctrl", "domain:example.edu", "sourceIp:192.0.2.1" + std::string(512 - 18, ' ')};
    assert(exactLimit[2].size() == 512);
    assert(parse({exactLimit}).mappings.size() == 1);
    exactLimit[2] += ' ';
    fails({exactLimit}, Failure::Limit);
    std::string manyAddresses;
    for (unsigned i = 0; i < 16; ++i) manyAddresses += (i ? ";" : "") + std::string("192.0.2.1");
    assert(parse({valid("example.edu", manyAddresses)}).mappings[0].addresses.size() == 16);
    fails({valid("example.edu", manyAddresses + ";192.0.2.1")}, Failure::Limit);
    Options manyOptions(64, valid());
    assert(parse(manyOptions).optionCount == 64);
    manyOptions.push_back(valid());
    fails(manyOptions, Failure::Limit);
    auto manyArgs = valid();
    while (manyArgs.size() < 33) manyArgs.push_back("domain:example.edu");
    assert(parse({manyArgs}).duplicateKeys == 30);
    manyArgs.push_back("domain:example.edu");
    fails({manyArgs}, Failure::Limit);
    Options total;
    auto padded = valid(); padded[1].resize(512, ' '); padded[2].resize(512, ' ');
    for (unsigned i = 0; i < 32; ++i) total.push_back(padded);
    fails(total, Failure::Limit);
    std::puts("ctrl static policy parser: passed");
}
