# 2018：Nouveau `nouveau_connector_detect()` 与 runtime PM 的循环死锁

## 1. 提交基础信息

- **Commit ID**：`3e1a12754d4df5804bfca5dedf09d2ba291bdc2a`
- **标题**：`drm/nouveau: Fix deadlocks in nouveau_connector_detect()`
- **作者**：Lyude Paul（Red Hat）
- **涉及子系统**：`drivers/gpu/drm/nouveau`、Runtime PM、workqueue
- **关键词**：`pm_runtime_get`、`hpd_work`、`pm_runtime_work`、Optimus 笔记本

## 2. 背景信息

- **NVIDIA Optimus** 类笔记本上，集成显卡负责显示管线，独显常通过 **runtime PM** 省电。
- **热插拔检测（HPD）** 在 workqueue 中运行；检测路径会尝试 **resume GPU** 以读连接器状态。
- **Runtime suspend 路径**又可能 **flush** 与 HPD 相关的 work，形成 **A 等 B、B 等 C、C 等 A** 的环。

**为何典型“低功耗海森堡”**：不加负载时 GPU 易 autosuspend；HPD 与 PM work 交错触发，表现为 **偶发 hung task**。

## 3. 故障现象

- 系统报告 **hung task**（如阻塞 120s），最终可能 **panic**；ThinkPad + Nouveau 场景报告较多。
- 用户感知：**外接显示器热插拔、 lid 事件、随机卡顿后死锁**。

## 4. 复现手法

1. Optimus 笔记本，启用 Nouveau，打开 **runtime PM**（默认策略因发行版而异）。
2. 反复 **插拔 DP/HDMI** 或触发 **HPD storm**。
3. 并行压力：**同时播放视频 + 电源策略切换** 迫使 autosuspend 与 resume 交替。

## 5. 调试方法

- **hung task 报告**中的 **全锁与栈**：对比 `kworker/events`、`kworker/pm` 是否互等。
- **确认 `__pm_runtime_resume()` 是否在已持有某些 work 同步原语的情况下阻塞**。
- **ftrace workqueue**：观察 `nouveau_display_hpd_work` 与 `pm_runtime_work` 的交错顺序。

## 6. 解决办法

- 在 **`nouveau_connector_hotplug()`** 使用 **`pm_runtime_get()`** 的 **非阻塞语义**：
  - 若返回 **0**（表示有 pending 请求/未就绪），**不阻塞等待**，而是 **defer** 到 `hpd_work` 在设备完全 active 后再处理。
  - 处理完 **`pm_runtime_mark_last_busy()`** 与 **`pm_runtime_put_autosuspend()`** 配对，维持 autosuspend 语义。

**修复原理**：打破环的关键是 **禁止在可能参与 PM 工作队列同步的路径上同步等待 resume**；改为 **异步重入同一状态机**。

## 7. 经验总结

- **DRM connector detect 路径默认假设设备已上电**；与 runtime PM 结合时必须定义 **“未上电时如何排队”**。
- 看到 **pm work 与驱动私有 work 互等**，优先画 **等待图** 找环。
