# 2012：PCI D3cold 下 unbind 与 pci_walk_bus 嵌套加锁死锁

## 1. 提交基础信息

- **Commit ID**：`90b5c1d7c45eeb622302680ff96ed30c1a2b6f0e`
- **标题**：`PCI/PM: Fix deadlock when unbinding device if parent in D3cold`
- **作者**：Ying Huang（Intel）
- **涉及子系统**：`drivers/pci`、Runtime PM、PCIe AER（间接）
- **关键词**：`device_lock`、`pci_walk_bus`、`D3cold`、`driver_unbind`

## 2. 背景信息

- **Runtime resume** 可能沿 PCI 树向上唤醒父设备、遍历总线，以恢复链路与电源域。
- **`pci_walk_bus()`** 历史上在遍历时对 **每个设备**加 `device_lock`，意图保护回调中的并发。
- **`driver_unbind` 路径**已在目标设备上持有 **`device_lock(dev)`**，若 resume 过程中再次 walk 到同一设备并尝试 **再次获取同一把锁**，即形成 **自锁/ABBA** 类死锁。

**为何是低功耗场景触发**：`D3cold` 下设备深度断电，unbind 往往触发 **完整 runtime resume** 才能把设备带回可探测状态，从而踩中嵌套锁路径。

## 3. 故障现象

- 在 **父设备处于 D3cold** 时，通过 sysfs **unbind** 子设备，系统 **挂死**。
- 影响 **动态卸载驱动、测试脚本、热插拔工具链**；无错误日志时表现为整体失去响应。

## 4. 复现手法

1. 准备可使 PCI 设备进入 **D3cold** 的平台与驱动（启用 runtime PM，允许深度掉电）。
2. 将设备置于 **runtime suspended / D3cold**。
3. 执行：`echo <pci_id> > .../unbind`（或对绑定节点写 unbind）。
4. 若 walk 路径与 unbind 锁序冲突，可稳定复现挂起。

## 5. 调试方法

- **lockdep**（若构建开启）：可能提前报告 **lock recursion** 或 **inconsistent lock state**。
- **hung task / sysrq-w**：观察 `driver_unbind` 与 `pci_walk_bus` 是否在同栈上嵌套等待。
- **对照 commit 中的调用链**：从 `device_release_driver` → `pm_runtime_get_sync` → `pci_walk_bus` 逐层展开。

## 6. 解决办法

- **从 `pci_walk_bus()` 中移除“无条件 device_lock”**，改为 **由真正需要锁的回调自行加锁**。
- 审计所有调用者；例如 **PCIe AER** 等路径在回调内部对设备加锁，而 **不需要**全局 walk 层强行加锁。

**修复原理**：**遍历总线**与 **设备生命周期互斥**是两类 concern；把锁下放到最小必要范围，避免与 **已持有 device_lock 的上层路径**重入。

## 7. 经验总结

- **“在通用遍历函数里统一加 device_lock”** 在 PM + sysfs 卸载场景极易踩雷。
- 排障时画出 **持锁点 → runtime PM → 总线遍历 → 再次持锁** 的有向图，一眼可见环。
