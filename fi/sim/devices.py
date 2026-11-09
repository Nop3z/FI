"""可插拔设备模型 + 探索占位设备。

纪律：凡"读返回值是模型占位"的设备（placeholder_reads=True），其每次读/写都由
machine 层以 stub=true 写入事实日志（trace 行 mem_access.stub）。占位值不是硬件
观测；任何引用该值做结论的地方必须标注 hypothesis/占位，不许静默伪造。
"""
from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:  # 避免运行时循环依赖
    from .machine import Simulator


class DeviceModel:
    """设备模型基类。子类注册进 DEVICE_REGISTRY 后可在 region.device 引用。"""

    name = "device"
    #: True=读返回值是模型占位（行级 stub 标记 + hypothesis）；False=建模读取。
    placeholder_reads = False

    def on_read(self, sim: "Simulator", addr: int, size: int) -> int:
        """返回该次读取的值（仿真器会把该值写入映射内存供 unicorn 实际读取）。"""
        raise NotImplementedError

    def on_write(self, sim: "Simulator", addr: int, size: int, value: int) -> None:
        """处理一次写入（副作用由子类决定；默认丢弃）。"""
        raise NotImplementedError

    def describe(self) -> dict:
        return {"name": self.name}


class NullStubDevice(DeviceModel):
    """探索占位设备：读恒返回 stub_value，写丢弃。

    用途：MMIO 区域尚未建模时的探索模式。它产生的一切数据都是占位值，
    全部访问都会被 machine 层记录进事实日志（stub=true）。
    """

    name = "null-stub"
    placeholder_reads = True

    def __init__(self, region_name: str, stub_value: int = 0):
        self.region_name = region_name
        self.stub_value = stub_value

    def on_read(self, sim: "Simulator", addr: int, size: int) -> int:
        return self.stub_value & ((1 << (size * 8)) - 1)

    def on_write(self, sim: "Simulator", addr: int, size: int, value: int) -> None:
        return None

    def describe(self) -> dict:
        return {"name": self.name, "region": self.region_name, "stub_value": self.stub_value}


class UartLogDevice(DeviceModel):
    """UART 文本输出收集设备 v0（boot log 观测假设模型）。

    行为假设（全部 hypothesis，待 ROM 对照/资料确认）：
    - 读：恒返回 ready_value（默认 0x1）。依据：BootROM 串口输出路径会轮询状态
      寄存器等待就绪位（观测：0x<ADDR>-0x<ADDR> 循环 lw 状态→andi 0x3f→条件
      跳转等待）；返回就绪值让输出路径推进。真实寄存器布局/位语义未知。
    - 写：收集全部写入字节进 log（数据寄存器与配置寄存器不区分，人工辨认文本）。

    产出：run_end.detail.uart_log 与 CLI 的 boot log 输出。写收集是仿真器
    模型让固件走到输出路径后产生的【仿真观测】，不代表真实串口时序。
    """

    name = "uart-log"
    placeholder_reads = True

    def __init__(self, region_name: str, stub_value: int = 0, ready_value: int = 1):
        self.region_name = region_name
        self.ready_value = ready_value
        self.log = bytearray()
        self.write_count = 0

    def on_read(self, sim: "Simulator", addr: int, size: int) -> int:
        return self.ready_value & ((1 << (size * 8)) - 1)

    def on_write(self, sim: "Simulator", addr: int, size: int, value: int) -> None:
        self.write_count += 1
        self.log.extend(int(value).to_bytes(size, "little"))

    @property
    def text(self) -> str:
        out = []
        for b in self.log:
            if 32 <= b < 127:
                out.append(chr(b))
            elif b == 0x0A:
                out.append("\\n")
            elif b == 0x0D:
                out.append("\\r")
            else:
                out.append(f"\\x{b:02x}")
        return "".join(out)

    def describe(self) -> dict:
        return {
            "name": self.name,
            "region": self.region_name,
            "ready_value": self.ready_value,
            "note": "读返回就绪值为模型假设(hypothesis)；写全量收集进 boot log",
        }


DEVICE_REGISTRY: dict[str, type[DeviceModel]] = {
    "null-stub": NullStubDevice,
    "uart-log": UartLogDevice,
}
