# 官方后台边界与替代契约

2026-11-05。目标是移除官方后台依赖。当前已证明原生 GUI 可以连接官方 Client 并刷新财务首页；下述调查不将这项结果升级成独立后台验收。

## 当前判断

控制面、隧道和 DNS 必须分别替代。OpenVPN 3 是有直接调用证据的引擎候选，但官方有至少两条集成路径和自定义扩展，不能直接将通用 OpenVPN 客户端视为兼容实现。

原始二进制、反汇编和静态协议材料留在忽略的 `out/backend-auth/`、`out/backend-tunnel/`。不保存账户令牌、私钥或实时响应内容。来源是安装的 3.11.1.1272；不同版本必须重新验证。

## 组件边界

| 组件 | 已定位职责 | 证据层级与限制 |
| --- | --- | --- |
| Client | GUI IPC、组织预配置、认证令牌、取得并应用连接配置 | Go 反汇编；尚未独立重放完整控制面 |
| Core | OMI 管理命令、OpenVPN 3 连接、外部证书签名、DNS 控制 | 已核对直接调用；学校当前是否走该路径未证实 |
| Agent | 除其他功能外，含自己的 OpenVPN 3 会话和 SDP 模块 | 已核对 NewSession/Start 调用；模式选择仍在追踪 |
| DP | DNS 代理、域名结果、网关/虚拟 IP/IPv6 管理 | 已恢复 HTTP 注册表；未调用控制端点 |

同一时刻 Core 和 Agent 进程都存在，不证明两者都承载当前流量。当前用户权限下 `lsof` 没有返回这些后台的 socket，不能据此断言其没有网络连接。只读运行盘点在 `out/backend-contract/processes.json` 和 `socket-metadata.json`。

## 可以重复核对的调用证据

```sh
scripts/backend-contract-check --app /Applications/SecureLink/SecureLink.app
```

该命令只读指定 App，先校验已调查版本的 SHA-256，再解码 ARM64 BL 的相对地址。任何版本或调用目标不同都失败；PASS 仅证明这些编译调用存在，不证明实际执行。

- Core：`OMI::connection_thread` 的 `0x1001392c8 → 0x10000858c` 调用 `OpenVPNClient::connect`。
- Agent：`mod_vpn.Start` 的 `0x1007fee0c → 0x10066ede0` 调用 `openvpn3.NewSession`；`0x1007fee90 → 0x10066f030` 调用 `Session.Start`。
- Core SHA-256：`5f22f1680a6e2ad20d93550fd4213e9392bd34eacb1ae70e40666e10aef4af40`。REA `ev_23ae403a551e154f924b92fd2ddce56942f8ed65bb04dedcd256477a5942c8c4`。
- Agent SHA-256：`aea6e2d38e7d99476357a4a9b95c1c2eab90321c7ef49874d549be3e6fd8196b`。

## 管理与 DNS 契约

Core 的 `OMI::omi_command_in`（`0x100125304`）分别分派 external-PKI reply、setenv、auth、remote。外部签名意味着连接所需材料未必能由一份静态 `.ovpn` 文件覆盖。Core 另含 `GMSSLTransport::Client` 和标准 TCP/UDP transport，存在符号不代表学校已启用 GMSSL。

DP 的 `_HttpCtrlInit`（`0x10000ec98`）注册 24 个 HTTP handler，首选 `127.0.0.1:9001`，绑定失败请求随机端口。注册表在 `out/backend-tunnel/dp-http-table.json`。这些端点含 Stop/Exit/SetDnsIp/SetGateway/SetDropIpv6 等有副作用的操作，调查期间未调用。

Core 的 `DnsProxy::call_dns_proxy_function`（`0x100041ea4`）构造 curl 控制请求，`dns_proxy_up` 依次涉及启动、加密参数及控制调用；最终执行器仍是未完全解析的间接调用。`MacDNS` 和 watchdog 另负责系统 DNS 变更与恢复。未来与另一款联网软件共存必须验证这部分的所有权和恢复行为，不能仅比较路由表。

## 开源复用

[OpenVPN 3 客户端 API](https://github.com/OpenVPN/openvpn3/blob/master/client/ovpncli.hpp) 提供配置评估、凭据注入、connect、TunBuilder 和 external-PKI 回调。2026-11-05 查询的 API blob 为 `5ed2a00357f4813358f18dc20c474029fc37ae9f`。这是可集成的源码引擎边界，不包含网宿组织发现、设备身份或策略服务。

[上游许可证声明](https://github.com/OpenVPN/openvpn3/blob/master/LICENSE.md) 列出 AGPL-3.0 或 MPL-2.0，当前 blob `6dad2b379b738bd8401caa96f15d6aa27ef1aa27`。这只描述该上游源码；不证明厂商修改代码可以直接分发。暂未添加依赖，待模式、配置、签名及自定义传输契约确认后选择版本和集成方式。

系统 Foundation/URLSession、Security、CommonCrypto 可继续承担自有控制面和密码操作；不引入厂商进程作为所谓独立替代。DNS 代理的行为可单独实现和测试，系统接管留到有恢复验证的阶段。

## 当前缺口和下一步

1. 完成组织发现的 host、公开协议材料、加密请求和错误响应契约，直接实现无账户数据的只读请求。
2. 确定 Client 选择 Core 或 Agent 的条件，以及配置与证书的传递边界。
3. 在真实连接中仅记录模式、字段类型与状态，确认学校实际路径，不保留敏感值。
4. 再实现自有认证和隧道；当前不能卸载官方 App。

## 模式选择与日志观察

Client 的 `handleCustomerConfigSdpMode`（`0x10056e730`）读取 `enable`、`localEnable` 和 `localDisable`。当字符串 `localDisable == "true"` 时关闭 SDP；否则取 `enable || localEnable`，按新旧状态调用 `SDPManager.UserLogin/UserLogout`。这是静态分支契约。

本次有界只读观察只扫描当前 Client 日志末尾最多 1 MiB，只输出固定四布尔模板和时间，未保存原始行。2026-11-05 00:07:28 与 00:09:23 的记录均为 serverEnable=false、effectiveEnable=false、currentEnable=false、isHeartbeat=false。证据为 `out/backend-tunnel/mode-observation.json`。它支持最近记录中 SDP 关闭，不能独自证明当前业务流量走 Core；后续仍须和实时连接证据关联。

Client→Core 的管理通道另有 AES 加密和四字节 little-endian 密文长度，不可将原生 OpenVPN management socket 当作直接可兼容接口。替代后台时应实现自己的引擎调用边界，避免继续依赖该厂商 IPC。

## 已验证的独立组织发现请求

`out/backend-auth/preconfig_probe.py` 已直接请求 `https://sheetaapi.wangsu.com/slAppApi/is/slapp/preConfig?locale=zh_CN`，收到 HTTP 200，AES 解密后的 `returnCode=1` 且 `content` 为对象。最新回执 `out/backend-auth/preconfig-receipt.json` 只含状态和固定字段类型，不含响应原文。这个请求不用账户身份，不调用官方 IPC；官方后台当时仍在运行，因此它证明请求不经后台转发，不证明整个上网环境已摆脱后台。

Client SHA-256 为 `fb0019debdaa4f677fe8a77b39c8caf014d18a946de6c0ceb47a04dd4bc80efe`。静态契约来源：`HandleGUIPreconfig`、`BackendSheetaPost.post/getHeader`、Go 请求类型元数据，以及 `out/backend-auth/` 中的定向反汇编。

- JSON 明文包含 `org` 和可选 `certSign`；首次请求使用 `{"org":"szu"}`。
- 每次生成 16 字节随机 AES key，按协议固定 IV 做 AES-CBC/PKCS7，HTTP body 为标准 base64 字节，Content-Type 为 `application/json`。普通 post 不将 `+` 转义成 `%2B`。
- `secret` header 是 RSA-PKCS1v1.5 加密该 AES key 后的标准 base64。API RSA key 和 IV 与 GUI IPC 材料不同。
- 请求头包括 `apiVersion`、`certId`、`nonce`、`reqTimestamp`、`sheetaSign`、`secret`；未登录时无 Authorization。
- `reqTimestamp` 为毫秒时间戳；签名输入依次为 `certId-timestamp-nonce-body`，SHA1 后先转小写 hex 文本，再 URL-safe base64，最后大写。不能将 SHA1 digest 直接 base64。
- 响应以同一 key/IV 解密，再解析 JSON。未知编码、非成功返回、异常字段和大小超限均不能算成功。

默认 host 在 `config.LoadConifg` 的 `0x100373374`，路径全局 `0x100e2cb70`，请求类型 `0x1008f0460`。默认公开材料由 `GetStApiPubK`（`0x100376ab0`）和 `GetStApiI`（`0x100376fd0`）恢复。现有原型仍读取安装的 Client 静态字节，原生迁移和摆脱文件依赖分开验收。

独立复核发现并修正了首次原型对 `+` 的处理：`AESEncryptBase64Encode` 的 true 分支直接返回标准 base64，false 分支才转义。修正后重新请求成功。首次 HTTP 200 不足以证明转义分支正确；随机密文和服务兼容都可能掩盖错误。

成功响应白名单内未出现 `clientCert` 和 `apiAddress`，不能推断已经取得登录证书或网关配置。静态响应类型允许证书及私钥字段；后续解析禁止将它们写入诊断。完整 CAS token 交换、设备身份、证书生命周期和网关配置仍未验证，正在继续追踪。

组织发现后，已用相同 HTTP 封装独立调用 `/authApi/sso/authConfig/getAuthConfig` 与 `/authApi/sso/authConfig/getAuthUrl`（apiVersion=5.18.0.0）。第一步只传 org=szu，成功返回一个 reportType=9 的提供者；第二步在内存中传递提供者 name，成功返回 action=2，loginUrl 通过现有 CASDiscovery 的学校 HTTPS 域名、路径及 SSO service 校验。未打开浏览器、未提交登录、未保存提供者响应或完整 URL。回执：`out/backend-contract/provider-receipt.json`、`auth-url-receipt.json`。这证明原生登录入口发现可脱离官方 IPC，不证明账户会话或隧道已独立。

## 认证及连接配置的后续契约

[独立认证契约](backend-auth-contract.md) 已明确命令 10 与 11 的边界、请求设备字段、二次认证、毫秒有效期、模块 Code 与退出行为。对应原始分析为 `out/backend-auth-cas/findings.md`；公开材料依赖已由版本化 provider 移除，未实现的校时、续期和挑战提交没有算作完成。

登录后 `networkApi/is/network/initConfig` 使用单独的 apiVersion=5.0.0.0。Body 的 system 为数字；intranetIp、dns、wifiSsid 平铺，空值省略。IP/DNS 各自排序后以分号连接，wifiSsid 为数组。官方采集默认接口地址及系统 DNS；DNS helper 的第二返回集合还需核实，不能凭名字假定所有解析器都应上传。

响应包含 networkConfig、probeConfig、customerConfigList、behaviorConfig。networkConfig 提供服务器及端口、clientConf 字符串、双签名/加密证书、gmtls/SPA 开关和相应材料。它们只可在内存中解析使用，禁止将完整响应或证书私钥写入诊断。配置取得后还有 heartbeat/task、网关选择、UVInfo 和管理命令，不等于已经建隧道。

该边界支持先实现自有控制面，再根据真实返回的传输模式选引擎。OpenVPN 3 是候选，不能预先宣布支持学校当前的全部扩展。运行路径、完整路由/DNS恢复及与另一款联网软件共存仍需后续实测。字段、编译地址与剩余缺口在 `out/backend-network/findings.md`。


独立配置请求还必须携带 `SlServerType`。`GetServerType("VPN")` 映射到 SDP，使用独立的 server-type 表：对 `{"serverType":"SDP","timestamp":"<毫秒字符串>"}` 做公开 RSA PKCS#1 v1.5 加密及标准 base64。它不含 accessToken，不能拿 inUsed 的 token Code、AES secret 或字面量 VPN 代替。静态路径与地址见 `out/backend-network/findings.md` 的 SlServerType 小节；首轮配置实测失败后补齐，真实重测另行记录。

Core 的 clientConf 指令 `gmtls` 与 `tls-proxy` 都进入 GMSSLTransport；标准引擎筛查必须检查两者，不可只看 clientCert.gmtls。UVInfo.Build 的实际预算常数为 2009，并有内部 KEY=value 与最终 setenv 输出两种长度检查；UV_CODE 占预算但通过独立路径交付。完整静态证据、字段顺序和 ExtraParam5 回退规则见 `out/backend-network/transport-followup.md`。这些结论尚不证明真实握手兼容。


## 自有源码握手接线

固定版本 OpenVPN 3 辅助程序已接受补齐远端的真实配置（仅离线 eval）。私有输入经 stdin 传入，凭据不经过 argv、日志或文件；`UV_CODE` 使用当前 accessToken，较长的 `UV_SL_SERVERTYPE` 经 peerInfo 交付，仍计入官方长度预算。默认只检查输入，只有显式 `--allow-handshake` 才尝试连接，并在 TUN 创建回调前停止，不改路由和 DNS。

准备器将配置绑定到同一认证 token 和请求作用域，拒绝未知模式、指令、外部文件、脚本、代理及自定义证书块。标准引擎接受配置不代表厂商扩展兼容。两种辅助程序加入调用者进程组；有界测试结束时必须确认自有进程组清空，再启动官方客户端。Foundation 子进程回收已有真实离线回归。

2026-11-05 首轮接线实测完成认证、取配置与退出，但材料准备报固定错误，未进入握手；官方恢复 Connected。见 `out/live-cas-20261104T184524338394Z/`。下一步只记录所需身份字段的类型和可解析性来定位问题，继续禁止保存响应原文。


真实响应诊断确认：terminalUserId 是可解析正整数，authTypeInternal 缺失。官方 ResetWithResp 新建零值 Go 结构后 JSON 解码，因此仅缺失 authTypeInternal 时按 0 处理；不把字符串、null 或错误类型转换成正常身份。原始类型标签仍为 missing，不伪称服务返回了整数。

UpdateFlowRedirect 在 modeSwitch 为 0 时直接返回，未读取输入 caCert；FlowRedirectAct 仅 mode 1 安装该证书。故 mode 0 下保留但不使用 flow CA，与 OpenVPN 配置自己的信任材料分开处理。官方 Core 和固定上游解析器均支持 tcp/tcp4/tcp6 与 -client 别名；tls 则为独立厂商种类，不按 TCP 放行。静态地址与原文见 out/backend-network/flow-redirect-findings.md。


自有 macOS TUN 的固定上游源码路径已核对：UTun::utun_open、TunMac::Setup、ExternalTun factory 和 Unix fd 传递可作为实现依据。默认 Setup 涉及 /1 重定向路由、主 DNS/search domains、PAC；默认 DNS watchdog 会重写第三方修改，恢复逻辑也不比较当前所有权。因此不能直接开启后宣称与另一款联网软件共存。后续先实现明确的会话计划、仅清理自己仍拥有的网络项及父进程退出回收；具体管理员或 NetworkExtension 授权必须等可审的操作计划准备好后提出。源文件定位与设计边界：out/backend-network/native-tun-options.md。当前未建 TUN、未更改这些网络设置。


独立 HTTP 与握手准备已改用 BackendPublicMaterial.production()，五字段公开协议材料版本化并校验来源指纹，所有生产调用去掉官方 app 参数，没有文件回读 fallback。没有固化混淆解包 key、非空密码加密 key 或用户配置；39 项离线 Backend 测试通过，含旧提取材料与新 provider 的合成加密等价验证。提交 6c6cb62。旧 GUI/IPC 和迁移测试的官方恢复路径仍保留；新 provider 的真实服务验证随下一次有界握手进行，不能据此宣布可卸载。


## 当前 DNS 与路由替代边界

最新有界捕获 `out/live-cas-20261104T200400905193Z/` 已覆盖标准 builder 与 domain option，未得到 domain 条目或业务 route。不能把它视为完整官方路由计划：静态调用证实官方 builder 会为 DNS 地址额外添加 host route；DP 根据匹配域策略的解析结果增减业务 host route，并维护共享引用。未命中域策略走外部解析分支，不能推断空 domain option 意味着全部流量进入校园隧道。该次实测早于 ctrl 捕获实现，不能据空 domainOptions 判定校园域策略为空。证据及未明边界在 `out/backend-network/dns-route-contract.md`。

### ctrl 策略链路（2026-11-05）

固定官方 Core 的静态调用链已闭合：`PUSH_REPLY` / `PUSH_RELOAD_ALL` → 解分片、可选 Base64/LZ4 解压 → CSV/OptionList → `Ctrl_Modify` → `SetSourceIpDomain` → `StaticDomain_Modify` → `UsingNewPolicy` → DP 静态域表。初始与重载分别组装；完整重载替换整代，缺失的 ctrl 映射被删除，不能解释为增量 `PUSH_UPDATE`。初始化后的普通 PUSH_REPLY 只走认证刷新，不重建策略。

`ctrl domain:<name> sourceIp:<IPv4-list>` 提供静态 DNS 地址，不是普通域名后缀路由选择器。同一行重复键、同代重复域名均首个生效；分号转为 `&` 后交给 DP。Core 同时写入地址级 `any/any` 内部策略，不能把它直接解释为系统 /32 路由。DP 静态答复 TTL 为 300 秒，注册与查询均不走动态 host-route 添加路径。原始证据定位分别见 `out/backend-network/ctrl-ingress-contract.md`、`out/backend-network/ctrl-semantics-contract.md`；以上为静态事实，不是校园实际下发内容的观测。

自有 `native/ctrl-policy` 已实现受限解析与整代接收状态机：支持精确 ASCII 域名、规范 IPv4 地址列表、纯文本/压缩分片；失败保留旧代，合法空重载清空。未知键、通配静态域、IPv6/CIDR 等未覆盖格式明确拒绝，不能默默忽略。这是比官方宽松解析更窄的首批支持范围。1 MiB/32 片是自有资源上限；官方解压容量上限 64 MiB，不要求解压结果等于声明容量。

网络计划升级为 schema 2，独立保存 ctrl 捕获标志、计数和静态映射/地址策略意图；旧 schema 1 不再被当作完整计划。纯网络操作规划器遇到非空 ctrl 明确返回 `unapplied-static-control-policy`，直到静态 DNS 与地址策略执行器完成。离线测试覆盖重复项、失效重载、压缩错误与边界；它们不证明系统策略已生效或已能卸载官方客户端。

继续追踪数据面后确认：`Session::tun_recv` 按 IPv4 **目的地址**查询 FastTable；ctrl 的 any/any 对应任意协议/端口。完整策略命中才加密发送，未命中不回退到本地；ctrl 未命中本身不代表完整策略拒绝，因为另有 IpMap/apps 与独立五元组放行。入站解密路径未观察到相同过滤调用。`TunProp::add_routes` 另从 `GetStaticDomainsIp` 读取已提交静态地址，向初始 builder 添加 /32 include route（metric 0）；函数名 add_exclude_route 在 bool=true 时实际调用 add_route，已按 vtable 核对。这补全了内核路由的独立来源，不改变“DP 静态解析本身不添加动态路由”的结论。证据：`out/backend-network/ctrl-address-effects-contract.md`。

下一实现步骤已开始：`native/ctrl-policy/effects.hpp` 提供初始 /32 路由意图和有界 IPv4 目的地址分类；只返回 ctrl 允许、未覆盖或包格式问题，不冒充全局防火墙。整代替换、共享目的地址、源/目的区分、IPv4 options/分片和截断输入均有离线 sanitizer 测试。尚未接入系统路由、DNS 答复或真实数据转发；完整重载后的系统路由重建/删除仍在调查。

重载后续结论：官方确有 include route 新旧集合增删，但 `FastTable::Reload` 先替换全局 ctrl 表，随后才分别从旧/新 OptionList 重新构造 Capture，两次都可能读到同一新 ctrl 表。故该静态差集不能证明旧 ctrl-only 路由一定被删；这不是实测确认的厂商残留。自有执行器应保存实际安装成功的旧代，与新代做差并保留其他来源的共享所有权，不能重新解析“旧配置”冒充已安装状态。调用地址与顺序见 `out/backend-network/ctrl-reload-routes-contract.md`。

实际 helper 控制入口已接线（b2a4934），按连接实例保存接收器，重连清空分片状态。完整重载和标准 PUSH_UPDATE 因数据面执行尚未完成而返回固定 `control-policy-rejected` 并停止；不默默忽略或转为增量。Swift 回执入口已拒绝嵌套/转义重复 JSON 键，防止解码时抹去冲突字段。整体验证：151 项 Swift、71 项 Python，`out/backend-contract/ctrl-integrated-check.log`。

新入口实测（2026-11-05 16:18）：`out/live-cas-20261105T081832549574Z/` 全链路通过——认证、取配置、退出验证，混淆握手到 TUN 边界停止（reason=tunnel-boundary），schema 2 计划 `ctrlOptionsCaptured=true` 且本次真实网关会话 `ctrlOptionCount=0`、无静态映射。这首次把“捕获未实现”与“学校实际下发为空”区分开，但只覆盖会话建立期推送；长连接中的完整重载（PUSH_RELOAD_ALL/UPDATE）仍未观察，不能据此断言校园策略恒为空。更早的 `out/live-cas-20261105T004016259486Z/` 停在学校登录页，不计入。系统 TUN 能力已于 2026-11-05 15:35 管理员探针实测确认（out/utun-capability/authorized-probe-receipt.json，stage=complete、created/closed/removed=true）。

自有代码已有 DNS 答复解析器（系统 libresolv；匹配事务与问题、CNAME链、完整错误码及受限TTL）、限速核心、窄 IPC 状态机及纯操作/清理模型。它们只有离线测试，不是已接通的 DNS 代理、特权系统执行器或真实数据隧道。DNS解析依据：[RFC 1035](https://www.rfc-editor.org/rfc/rfc1035.html)；厂商匹配策略仍以静态与实测证据为准。

普通用户创建独立 UTUN 的实测为 EPERM，socket 已关闭、未建接口。`scripts/authorize-utun-probe` 默认只准备审核命令；只有明确授权后才可使用 `--run-authorized` 弹出系统管理员窗口。已构建的探针只创建动态新接口、读取默认 MTU、关闭并检查移除，进程硬限5秒；不设置地址/路由/DNS，不安装常驻服务。临时 root 副本在有界复制后验证 SHA256，复制前拒绝符号链接/FIFO/异常文件。管理员实机创建与清理已于 2026-11-05 15:35 一次性验证（authorized-probe-receipt.json）；这只确认能力，不代表生产 helper 已实现。


## 已安装的厂商系统服务（2026-11-05 只读列目录）

`scripts/verify-backend finance` 的前置采集只读列出 `/Library/LaunchDaemons` 并用 `plistlib` 读取 `Label`，得到三个厂商标签：`com.securelink.client`、`com.wangsu.edlp.service`、`com.wangsu.securebox.service`。本轮没有加载、卸载、修改或读取这些服务的其他内容，也没有执行它们的程序。

用户域 `launchctl list` 里只出现 `application.com.wangsu.securelink.*`，那是 GUI 应用注册而不是服务；采集器据此区分两者，不把 GUI 注册当作后台服务在跑的证据。非 root 无法查询 system launchd 域，因此 `systemLaunchdChecked=false`，门禁固定给出 `system-launchd-unverified`：`docs/pstack-relay.md` 里“官方 App、Client、Agent、Core、DP 均不运行且不被加载”这一条，必须由特权执行器提供证据，不能用进程列表为空推断。这三个标签与 `edlp`/`securebox` 的实际用途、是否随连接启动，仍属未查明项；它们是 Slice F 卸载验收必须逐个核对的对象，不是可以直接停用或删除的东西。
