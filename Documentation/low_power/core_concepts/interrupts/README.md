# Interrupts（中断与唤醒）

中断是“唤醒链路”的载体，做低功耗定位时需要同时理解：中断控制器拓扑、触发类型、亲和性、以及 wakeup-source/wakeirq 在设备电源管理中的绑定方式。

## 目录内容

- [第二章_中断控制器详解.md](第二章_中断控制器详解.md)

## 关联资料

- GIC 规格与架构资料：见 [hardware_specs/gic/README.md](../../hardware_specs/gic/README.md)
- 内核 PM 代码地图（wakeup source / wakeirq / suspend-interrupts）：见 [kernel_pm_map.md](../../kernel_pm_map.md)
