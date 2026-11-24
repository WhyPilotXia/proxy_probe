#!/usr/bin/env python3
"""流水线扫描并验证代理，探测出口属地，自动导出 Clash JSON 配置。"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import queue
import re
import socket
import sys
import tempfile
import threading
import time
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlsplit

import requests
from requests.adapters import HTTPAdapter


DEFAULT_CONFIG = Path(__file__).resolve().with_name("proxy_probe.json")
DEFAULT_OUTPUT_DIR = Path(__file__).resolve().parent
EXPORT_FILENAME_RE = re.compile(r"clash-[1-9][0-9]*个-[0-9]{8}-[0-9]{6}-[0-9]{6}\.json")
UNAVAILABLE = "无法探测代理后地址"
NOT_PROBED = "未探测代理后地址"
STOP = object()
PRINT_LOCK = threading.Lock()


def log(message: str) -> None:
    with PRINT_LOCK:
        print(message, flush=True)


class SourceAddressAdapter(HTTPAdapter):
    """让直连及代理连接均从指定本机 IP 发出。"""

    def __init__(self, source_ip: str, *args: Any, **kwargs: Any) -> None:
        self.source_ip = source_ip
        super().__init__(*args, **kwargs)

    def init_poolmanager(
        self,
        connections: int,
        maxsize: int,
        block: bool = False,
        **pool_kwargs: Any,
    ) -> None:
        pool_kwargs["source_address"] = (self.source_ip, 0)
        super().init_poolmanager(
            connections, maxsize, block=block, **pool_kwargs
        )

    def proxy_manager_for(self, proxy: str, **proxy_kwargs: Any) -> Any:
        proxy_kwargs["source_address"] = (self.source_ip, 0)
        return super().proxy_manager_for(proxy, **proxy_kwargs)


@dataclass(frozen=True)
class Config:
    local_ip: str
    target_ip: str
    prefix_length: int = 20
    proxy_ports: tuple[int, ...] = (7897, 7890)
    connect_timeout: float = 0.35
    proxy_timeout: float = 5.0
    geo_timeout: float = 5.0
    workers: int = 256
    proxy_workers: int = 32
    geo_workers: int = 8
    bind_source_ip: bool = True
    proxy_test_urls: tuple[str, ...] = (
        "https://api.ip.sb/ip",
        "https://cp.cloudflare.com/generate_204",
        "https://www.gstatic.com/generate_204",
    )
    exclude_ips: tuple[str, ...] = ()

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "Config":
        required = {"local_ip", "target_ip"}
        missing = required - raw.keys()
        if missing:
            raise ValueError(f"配置缺少字段: {', '.join(sorted(missing))}")

        values = dict(raw)
        # 兼容旧配置名称。
        if "verify_timeout" in values and "proxy_timeout" not in values:
            values["proxy_timeout"] = values.pop("verify_timeout")
        else:
            values.pop("verify_timeout", None)
        if "probe_url" in values and "proxy_test_urls" not in values:
            values["proxy_test_urls"] = (values.pop("probe_url"),)
        else:
            values.pop("probe_url", None)
        values.pop("verify_http_proxy", None)

        # 新配置使用 proxy_ports；同时兼容旧版 proxy_port（整数或列表）。
        if "proxy_ports" not in values and "proxy_port" in values:
            legacy_ports = values.pop("proxy_port")
            values["proxy_ports"] = (
                legacy_ports
                if isinstance(legacy_ports, (list, tuple))
                else (legacy_ports,)
            )
        else:
            values.pop("proxy_port", None)
        values["proxy_ports"] = tuple(
            values.get("proxy_ports", cls.proxy_ports)
        )
        values["proxy_test_urls"] = tuple(
            values.get("proxy_test_urls", cls.proxy_test_urls)
        )
        values["exclude_ips"] = tuple(values.get("exclude_ips", ()))
        config = cls(**values)
        config.validate()
        return config

    def validate(self) -> None:
        ipaddress.IPv4Address(self.local_ip)
        ipaddress.IPv4Address(self.target_ip)
        if not 0 <= self.prefix_length <= 32:
            raise ValueError("prefix_length 必须在 0 到 32 之间")
        if not self.proxy_ports:
            raise ValueError("proxy_ports 不能为空")
        if len(set(self.proxy_ports)) != len(self.proxy_ports):
            raise ValueError("proxy_ports 不能包含重复端口")
        for port in self.proxy_ports:
            if not isinstance(port, int) or isinstance(port, bool):
                raise ValueError("proxy_ports 中的端口必须是整数")
            if not 1 <= port <= 65535:
                raise ValueError("proxy_ports 中的端口必须在 1 到 65535 之间")
        if min(self.connect_timeout, self.proxy_timeout, self.geo_timeout) <= 0:
            raise ValueError("超时时间必须大于 0")
        for name, count, maximum in (
            ("workers", self.workers, 1024),
            ("proxy_workers", self.proxy_workers, 256),
            ("geo_workers", self.geo_workers, 256),
        ):
            if not 1 <= count <= maximum:
                raise ValueError(f"{name} 必须在 1 到 {maximum} 之间")
        if not self.proxy_test_urls:
            raise ValueError("proxy_test_urls 不能为空")
        for url in self.proxy_test_urls:
            if urlsplit(url).scheme != "https":
                raise ValueError("proxy_test_urls 中的地址必须使用 https://")
        for item in self.exclude_ips:
            ipaddress.IPv4Address(item)


@dataclass(frozen=True)
class VerifiedProxy:
    ip: str
    port: int
    proxy_status: str
    public_ip: str = UNAVAILABLE
    location: str = UNAVAILABLE


def load_config(path: Path) -> Config:
    try:
        raw = json.loads(path.read_text(encoding="utf-8-sig"))
    except FileNotFoundError as exc:
        raise ValueError(f"找不到配置文件: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"配置文件 JSON 格式错误（第 {exc.lineno} 行，第 {exc.colno} 列）"
        ) from exc
    if not isinstance(raw, dict):
        raise ValueError("配置文件顶层必须是 JSON 对象")
    try:
        return Config.from_dict(raw)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"配置无效: {exc}") from exc


def source_address(config: Config) -> tuple[str, int] | None:
    return (config.local_ip, 0) if config.bind_source_ip else None


def check_source_binding(config: Config) -> None:
    if not config.bind_source_ip:
        return
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind((config.local_ip, 0))
    except OSError as exc:
        raise ValueError(
            f"无法绑定本机 IP {config.local_ip}。请确认它是本机网卡当前地址，"
            "或将 bind_source_ip 改为 false。"
        ) from exc
    finally:
        sock.close()


def make_proxy_session(
    ip: str, port: int, config: Config
) -> requests.Session:
    session = requests.Session()
    session.trust_env = False
    if config.bind_source_ip:
        adapter = SourceAddressAdapter(config.local_ip, max_retries=0)
    else:
        adapter = HTTPAdapter(max_retries=0)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    proxy_url = f"http://{ip}:{port}"
    session.proxies = {"http": proxy_url, "https": proxy_url}
    session.headers["User-Agent"] = "proxy-probe/2.0"
    return session


def is_port_open(ip: str, port: int, config: Config) -> bool:
    try:
        with socket.create_connection(
            (ip, port),
            timeout=config.connect_timeout,
            source_address=source_address(config),
        ):
            return True
    except OSError:
        return False


def verify_proxy(
    ip: str,
    port: int,
    config: Config,
    stop_event: threading.Event,
) -> str | None:
    """通过 HTTPS 请求确认该端口确实可作为 HTTP/Clash 代理使用。"""
    session = make_proxy_session(ip, port, config)
    try:
        for url in config.proxy_test_urls:
            if stop_event.is_set():
                return None
            try:
                response = session.get(
                    url,
                    timeout=config.proxy_timeout,
                    allow_redirects=False,
                )
                if 200 <= response.status_code < 500:
                    host = urlsplit(url).hostname or url
                    return f"{host} HTTP {response.status_code}"
            except requests.RequestException:
                continue
    finally:
        session.close()
    return None


def join_location(*parts: Any) -> str:
    result: list[str] = []
    for part in parts:
        text = str(part or "").strip()
        if text and text not in result:
            result.append(text)
    return " / ".join(result) or "未知属地"


def parse_myip_la(data: dict[str, Any]) -> tuple[str, str]:
    location = data.get("location") or {}
    return (
        str(data.get("ip") or "").strip(),
        join_location(
            location.get("country_name"),
            location.get("province"),
            location.get("city"),
        ),
    )


def parse_ip_sb(data: dict[str, Any]) -> tuple[str, str]:
    return (
        str(data.get("ip") or "").strip(),
        join_location(
            data.get("country"),
            data.get("region"),
            data.get("city"),
        ),
    )


def probe_proxy_location(
    ip: str,
    port: int,
    config: Config,
    stop_event: threading.Event,
) -> tuple[str, str]:
    """通过代理查询出口 IP 和属地，并按顺序回退接口。"""
    session = make_proxy_session(ip, port, config)
    json_apis: tuple[
        tuple[str, Callable[[dict[str, Any]], tuple[str, str]]], ...
    ] = (
        ("https://api.myip.la/cn?json", parse_myip_la),
        ("https://api.ip.sb/geoip", parse_ip_sb),
    )
    try:
        for url, parser in json_apis:
            if stop_event.is_set():
                return UNAVAILABLE, UNAVAILABLE
            try:
                response = session.get(url, timeout=config.geo_timeout)
                response.raise_for_status()
                public_ip, location = parser(response.json())
                if public_ip:
                    return public_ip, location
            except (
                requests.RequestException,
                ValueError,
                TypeError,
                KeyError,
                AttributeError,
            ):
                continue

        if stop_event.is_set():
            return UNAVAILABLE, UNAVAILABLE
        try:
            response = session.get(
                "https://myip.ipip.net",
                timeout=config.geo_timeout,
            )
            response.raise_for_status()
            response.encoding = "utf-8"
            match = re.search(
                r"当前\s*IP\s*[：:]\s*(\S+)\s+来自于\s*[：:]\s*(.+)",
                response.text.strip(),
            )
            if match:
                return match.group(1).strip(), (
                    match.group(2).strip() or "未知属地"
                )
        except requests.RequestException:
            pass
    finally:
        session.close()
    return UNAVAILABLE, UNAVAILABLE


def pipeline_scan(
    config: Config,
) -> tuple[list[tuple[str, int]], list[VerifiedProxy], bool]:
    network = ipaddress.ip_network(
        f"{config.target_ip}/{config.prefix_length}", strict=False
    )
    excluded = {ipaddress.IPv4Address(item) for item in config.exclude_ips}
    local_ip = ipaddress.IPv4Address(config.local_ip)
    if local_ip in network:
        excluded.add(local_ip)
    targets = [str(ip) for ip in network.hosts() if ip not in excluded]

    scan_queue: queue.Queue[Any] = queue.Queue()
    proxy_queue: queue.Queue[Any] = queue.Queue()
    geo_queue: queue.Queue[Any] = queue.Queue()
    open_endpoints: list[tuple[str, int]] = []
    results: dict[tuple[str, int], VerifiedProxy] = {}
    state_lock = threading.Lock()
    stop_event = threading.Event()
    progress = {"scanned": 0}

    def scan_worker() -> None:
        while True:
            item = scan_queue.get()
            try:
                if item is STOP:
                    return
                if stop_event.is_set():
                    continue
                ip = str(item)
                opened_ports: list[int] = []
                # 同一个 IP 严格按照配置中的端口顺序探测。
                for port in config.proxy_ports:
                    if stop_event.is_set():
                        break
                    if is_port_open(ip, port, config):
                        opened_ports.append(port)
                with state_lock:
                    progress["scanned"] += 1
                    scanned = progress["scanned"]
                    open_endpoints.extend(
                        (ip, port) for port in opened_ports
                    )
                for port in opened_ports:
                    log(f"发现开放端口: {ip}:{port}")
                    if not stop_event.is_set():
                        proxy_queue.put((ip, port))
                if scanned % 256 == 0 or scanned == len(targets):
                    log(f"扫描进度: {scanned}/{len(targets)}")
            finally:
                scan_queue.task_done()

    def proxy_worker() -> None:
        while True:
            item = proxy_queue.get()
            try:
                if item is STOP:
                    return
                if stop_event.is_set():
                    continue
                ip, port = item
                status = verify_proxy(ip, port, config, stop_event)
                if stop_event.is_set():
                    continue
                if status:
                    proxy = VerifiedProxy(
                        ip=ip,
                        port=port,
                        proxy_status=status,
                    )
                    with state_lock:
                        results[(ip, port)] = proxy
                    log(f"代理确认成功: {ip}:{port} -> {status}")
                    if not stop_event.is_set():
                        geo_queue.put(proxy)
                else:
                    log(f"非代理或代理不可用: {ip}:{port}")
            finally:
                proxy_queue.task_done()

    def geo_worker() -> None:
        while True:
            item = geo_queue.get()
            try:
                if item is STOP:
                    return
                if stop_event.is_set():
                    continue
                proxy = item
                public_ip, location = probe_proxy_location(
                    proxy.ip,
                    proxy.port,
                    config,
                    stop_event,
                )
                if stop_event.is_set():
                    continue
                result = VerifiedProxy(
                    ip=proxy.ip,
                    port=proxy.port,
                    proxy_status=proxy.proxy_status,
                    public_ip=public_ip,
                    location=location,
                )
                with state_lock:
                    results[(proxy.ip, proxy.port)] = result
                if public_ip == UNAVAILABLE:
                    log(
                        f"属地探测失败: {proxy.ip}:{proxy.port} -> "
                        f"{UNAVAILABLE}（代理仍保留）"
                    )
                else:
                    log(
                        f"属地探测成功: {proxy.ip}:{proxy.port} -> "
                        f"{public_ip}，{location}"
                    )
            finally:
                geo_queue.task_done()

    def start_workers(
        count: int, target: Callable[[], None], name: str
    ) -> list[threading.Thread]:
        threads = [
            threading.Thread(
                target=target,
                name=f"{name}-{index + 1}",
                daemon=True,
            )
            for index in range(count)
        ]
        for thread in threads:
            thread.start()
        return threads

    def wait_for_workers(threads: list[threading.Thread]) -> None:
        """短间隔等待线程，确保主线程可以立即响应 Ctrl+C。"""
        while any(thread.is_alive() for thread in threads):
            time.sleep(0.1)

    log(
        f"扫描网段 {network}，目标 {len(targets)} 台，TCP 端口 "
        f"{list(config.proxy_ports)}"
    )
    log(
        f"流水线并发: 扫描 {config.workers} / "
        f"代理验证 {config.proxy_workers} / 属地探测 {config.geo_workers}"
    )
    log(f"源 IP: {config.local_ip if config.bind_source_ip else '由系统路由选择'}")

    geo_threads = start_workers(config.geo_workers, geo_worker, "geo")
    proxy_threads = start_workers(config.proxy_workers, proxy_worker, "proxy")
    scan_threads = start_workers(config.workers, scan_worker, "scan")

    interrupted = False
    try:
        for target in targets:
            scan_queue.put(target)
        for _ in scan_threads:
            scan_queue.put(STOP)

        wait_for_workers(scan_threads)

        for _ in proxy_threads:
            proxy_queue.put(STOP)
        wait_for_workers(proxy_threads)

        for _ in geo_threads:
            geo_queue.put(STOP)
        wait_for_workers(geo_threads)
    except KeyboardInterrupt:
        interrupted = True
        stop_event.set()
        log("\n收到 KeyboardInterrupt，已停止任务，正在输出当前结果...")

    port_order = {
        port: index for index, port in enumerate(config.proxy_ports)
    }
    with state_lock:
        current_open = list(open_endpoints)
        current_results = list(results.values())
    current_open.sort(
        key=lambda item: (
            ipaddress.IPv4Address(item[0]),
            port_order[item[1]],
        )
    )
    current_results.sort(
        key=lambda item: (
            ipaddress.IPv4Address(item.ip),
            port_order[item.port],
        )
    )
    return current_open, current_results, interrupted


def print_result(
    open_endpoints: list[tuple[str, int]],
    results: list[VerifiedProxy],
    config: Config,
    elapsed: float,
    interrupted: bool = False,
) -> None:
    print("\n任务已中断，以下是当前结果" if interrupted else "\n流水线处理完成")
    print(f"开放端口数量: {len(open_endpoints)}")
    print(f"确认代理数量: {len(results)}")
    print(f"总用时: {elapsed:.1f} 秒")

    if open_endpoints:
        print("\n开放端口列表")
        for ip, port in open_endpoints:
            print(f"- {ip}:{port}")

    if not results:
        print("\n未发现确认可用的代理。")
        return

    print("\n代理结果列表")
    for result in results:
        public_ip = result.public_ip
        location = result.location
        if interrupted:
            if public_ip == UNAVAILABLE:
                public_ip = NOT_PROBED
            if location == UNAVAILABLE:
                location = NOT_PROBED

        print(f"- 代理: {result.ip}:{result.port}")
        print(f"  验证状态: {result.proxy_status}")
        print(f"  出口 IP: {public_ip}")
        print(f"  IP 属地: {location}")


def build_clash_config(results: list[VerifiedProxy]) -> dict[str, Any]:
    """按插件的规则构建 Clash 配置：属地命名，新加坡优先自动选择。"""
    if not results:
        raise ValueError("没有确认可用的代理，无法生成 Clash 配置。")
    records = sorted(
        results, key=lambda item: (ipaddress.IPv4Address(item.ip), item.port)
    )
    locations = [str(item.location or "").strip() or "未知属地" for item in records]
    totals = Counter(locations)
    counts: defaultdict[str, int] = defaultdict(int)
    used_names = {"自动选择", "节点选择", "DIRECT", "REJECT", "GLOBAL"}
    names: list[str] = []
    for location in locations:
        counts[location] += 1
        base = (
            location if totals[location] == 1
            else f"{location} #{counts[location]}"
        )
        name = base
        suffix = 2
        while name in used_names:
            name = f"{base} #{suffix}"
            suffix += 1
        used_names.add(name)
        names.append(name)

    singapore_names = [
        name for name, location in zip(names, locations, strict=True)
        if "新加坡" in location or "singapore" in location.casefold()
    ]
    return {
        "mixed-port": 7890,
        "allow-lan": False,
        "mode": "rule",
        "log-level": "info",
        "proxies": [
            {"name": name, "type": "http", "server": item.ip, "port": item.port}
            for name, item in zip(names, records, strict=True)
        ],
        "proxy-groups": [
            {
                "name": "自动选择",
                "type": "url-test",
                "proxies": singapore_names or names,
                "url": "https://www.gstatic.com/generate_204",
                "interval": 300,
                "tolerance": 20,
            },
            {
                "name": "节点选择",
                "type": "select",
                "proxies": ["自动选择", *names],
            },
        ],
        "rules": ["MATCH,节点选择"],
    }


def _is_generated_clash_json(path: Path) -> bool:
    """只清理本工具命名的 Clash 导出，绝不把扫描输入配置当成旧导出。"""
    if not EXPORT_FILENAME_RE.fullmatch(path.name) or path.is_symlink():
        return False
    try:
        document = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, ValueError):
        return False
    return (
        isinstance(document, dict)
        and "local_ip" not in document
        and "target_ip" not in document
        and isinstance(document.get("proxies"), list)
        and isinstance(document.get("proxy-groups"), list)
        and isinstance(document.get("rules"), list)
    )


def export_clash_json(
    results: list[VerifiedProxy],
    output_dir: Path | None = None,
    now: datetime | None = None,
) -> Path:
    """完整落盘并原子发布新 JSON 后，才删除同目录的旧导出。"""
    document = build_clash_config(results)
    content = json.dumps(document, ensure_ascii=False, indent=2, allow_nan=False) + "\n"
    directory = DEFAULT_OUTPUT_DIR if output_dir is None else Path(output_dir)
    directory.mkdir(parents=True, exist_ok=True)
    exported_at = now or datetime.now().astimezone()
    path = directory / f"clash-{len(results)}个-{exported_at:%Y%m%d-%H%M%S-%f}.json"
    # 写入前记录旧文件，避免清理其他进程随后新生成的配置。
    old_paths = [item for item in directory.iterdir() if _is_generated_clash_json(item)]
    if path.exists() and path not in old_paths:
        raise ValueError(f"输出路径已被非本工具配置占用，保留原文件: {path}")

    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", newline="\n", dir=directory,
            prefix=".clash-", suffix=".tmp", delete=False,
        ) as stream:
            temporary = Path(stream.name)
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            try:
                temporary.unlink(missing_ok=True)
            except OSError as exc:
                log(f"警告: 无法清理临时文件 {temporary}: {exc}")

    for old_path in old_paths:
        if old_path == path or not _is_generated_clash_json(old_path):
            continue
        try:
            old_path.unlink(missing_ok=True)
        except OSError as exc:
            log(f"警告: 新配置已生成，但无法删除旧配置 {old_path}: {exc}")
    return path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="流水线扫描代理、探测出口属地并自动生成 Clash JSON 配置"
    )
    parser.add_argument(
        "-c",
        "--config",
        type=Path,
        default=DEFAULT_CONFIG,
        help=f"配置文件路径（默认: {DEFAULT_CONFIG.name}）",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        config = load_config(args.config)
        check_source_binding(config)
        started = time.monotonic()
        open_endpoints, results, interrupted = pipeline_scan(config)
        print_result(
            open_endpoints,
            results,
            config,
            time.monotonic() - started,
            interrupted,
        )
        if interrupted:
            log("扫描已中断，未更新 Clash 配置，保留旧导出。")
            return 130
        if not results:
            log("没有可用代理，未更新 Clash 配置，保留旧导出。")
            return 1
        path = export_clash_json(results)
        log(f"Clash JSON 已生成（{len(results)} 个节点）: {path.resolve()}")
        return 0
    except (ValueError, OSError) as exc:
        print(f"错误: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("\n任务已强制取消，未能完成结果整理。", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
