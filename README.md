# Clash 代理地址搜索

根据目标 IPv4 地址和网络前缀计算待扫描网段，从单独配置的本机 IPv4
地址发起连接。程序使用三级并发流水线：

1. 扫描配置指定的 TCP 端口。
2. 开放端口立即进入 HTTPS 代理验证队列。
3. 确认成功的代理立即进入出口 IP 和属地探测队列。

三个阶段同时运行，不需要等待整个网段扫描完成。
扫描正常完成且发现可用代理后，**自动在脚本同目录生成 Clash JSON 配置**，
不需要额外导出命令。请仅扫描你拥有或获得授权的网络。

## 环境与运行

需要 Python 3.10 或更高版本：

```powershell
cd E:\git包\proxy_probe
python -m pip install -r requirements.txt
python .\proxy_probe.py
```

也可以指定其他扫描配置文件：

```powershell
python .\proxy_probe.py --config .\other.json
```

不管从哪个工作目录启动，默认都读取脚本旁的 `proxy_probe.json`，
Clash 导出也始终位于脚本目录，不会写到当前工作目录或自定义扫描配置目录。

## 扫描配置

编辑 `proxy_probe.json`（**它是扫描程序的输入配置，不是 Clash 配置，不会被自动删除**）：

- `local_ip`：用于绑定出站连接的本机网卡地址，当前为 `192.168.8.101`。
- `target_ip`：目标网段内的任意地址，当前为 `218.194.50.3`。
- `prefix_length`：网段前缀，当前为 `20`。
- `proxy_ports`：按顺序探测的端口列表，例如 `[7897, 7890]`。
  兼容旧字段 `proxy_port`；随附配置仍是 `"proxy_port": 7897`，因此实际只扫描 `7897`。
  两个字段都未设置时才使用 `[7897, 7890]`。
- `bind_source_ip`：为 `true` 时强制从 `local_ip` 对应的网卡发起连接。
- `connect_timeout` / `proxy_timeout` / `geo_timeout`：端口连接、代理验证和属地查询的超时秒数。
- `workers` / `proxy_workers` / `geo_workers`：三个阶段的线程数。
- `proxy_test_urls`：代理验证使用的 HTTPS 地址，按顺序回退。
- `exclude_ips`：可选，需要跳过的其他地址列表。

随附配置扫描 `218.194.48.0/20`，所有 TCP 连接绑定到 `192.168.8.101`。
运行前请确认此地址仍属于本机；否则修改 `local_ip` 或将 `bind_source_ip` 设为 `false`。

最终结果只包含确认可用的代理。属地探测依次回退使用
`api.myip.la`、`api.ip.sb` 和 `myip.ipip.net`。如果所有接口都失败，
代理仍会保留，出口 IP 和属地显示为“无法探测代理后地址”。

## 自动生成 Clash JSON

导出参照 `nonebot_plugin_proxy_probe` 的 Clash YAML 结构，但使用 UTF-8 JSON：

- 文件名：`clash-<节点数>个-<年月日>-<时分秒>-<微秒>.json`，例如
  `clash-3个-20260102-030405-123456.json`。
- 节点类型为 `http`，使用扫描确认的服务器 IP 和端口。
- 节点以属地命名，重复属地增加 `#1`、`#2` 等后缀，避免节点名和组名冲突。
- `自动选择` 为 `url-test` 组：有新加坡节点时仅使用这些节点，否则使用全部节点。
- `节点选择` 为手动选择组，包含自动选择及所有节点。
- `mixed-port: 7890`、`allow-lan: false`、`mode: rule`，规则为 `MATCH,节点选择`。
  与参考插件一致，不额外开启 TUN 或 DNS。

JSON 是 YAML 1.2 的子集，可供支持该格式的 Clash/Mihomo 内核读取；
部分图形客户端的导入文件过滤器仅显示 `.yaml`/`.yml`，需按客户端要求导入。

### 旧配置替换与失败保护

1. 在脚本目录写临时文件，完整写入并刷新到磁盘后，再原子发布新 JSON。
2. **新文件成功发布后**，才删除同目录旧导出，通常只保留最新一份。
3. 仅删除严格符合上述 `clash-<节点数>个-<年月日>-<时分秒>-<微秒>.json`
   命名、含 `proxies` / `proxy-groups` / `rules` 列表且不含扫描配置字段
   `local_ip` / `target_ip` 的 JSON 文件。不跟随符号链接。
4. `proxy_probe.json`、其他命名的 JSON、无法解析的文件、原有 `proxy.yaml` 均保留，
   不会用 `*.json` 的方式一律清空目录。
5. 没有可用节点、扫描中断、配置错误或新文件写入失败时，旧导出保持不变。
   即使中断时已有部分节点，也不会拿不完整结果替换旧配置。
6. 若新文件已成功生成但某个旧文件被占用、无法删除，会显示警告；新文件仍保留可用。

退出码：成功生成为 `0`；未发现可用代理为 `1`；配置/文件读写等错误为 `2`；
用户中断为 `130`。控制台会输出结果列表和最终生成的文件路径。

## 测试

```powershell
python -B -m unittest discover -s tests -v
```

测试使用临时目录和模拟扫描结果，不扫描外网，也不替换真实导出文件。
