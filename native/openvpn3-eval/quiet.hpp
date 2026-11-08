#pragma once
// Never forward upstream logs; they can contain inline secrets and peer addresses.
#define OPENVPN_LOG(...) do {} while (false)
#define OPENVPN_LOG_NTNL(...) do {} while (false)
#define OPENVPN_LOG_STRING(...) do {} while (false)
