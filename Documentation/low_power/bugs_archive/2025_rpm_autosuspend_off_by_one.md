# 2025：Runtime PM autosuspend 定时器回调边界 off-by-one 致永久不再自动挂起

## 1. 提交基础信息

- **Commit ID**：`40d3b40dce375d6f1c1dbf08d79eed3aed6c691d`（上游）
- **标题**：`PM: runtime: fix denying of auto suspend in pm_suspend_timer_fn()`
- **作者**：Charan Teja Kalla、Patrick Daly（Qualcomm）
- **稳定回合参考**：`0bd887636e7642664905bae2a7fdd5092e69310e` 等 stable cherry-pick（以发行版为准）
- **涉及子系统**：`drivers/base/power/runtime.c`
- **关键词**：`pm_suspend_timer_fn`、`timer_expires`、hrtimer、autosuspend

## 2. 背景信息

- **Runtime PM autosuspend** 依赖 **高精度定时器** 在 **空闲超时** 后触发 **`pm_suspend_timer_fn()`**，再进入 **`rpm_suspend()`** 路径。
- 若定时器回调里对 **过期条件**判断使用 **严格小于（`<`）** 而非 **小于等于（`<=`）**，在 **`expires == now`** 的边界上可能 **误判为未到期**。
- 更糟的是：**`timer_expires` 可能残留非零值**，导致后续 **自动挂起请求被永久拒绝**，设备 **一直 active**。

**为何像海森堡**：依赖 **纳秒级对齐**；负载、CPU 频率、timer 合并策略改变 **命中边界的概率**。

## 3. 故障现象

- **个别设备**在运行一段时间后 **再也不进入 runtime suspend**，功耗 **异常偏高**。
- 可能需 **重启** 才恢复；**高通 SoC 上 GPU/DSP 等高 autosuspend 频率设备**更易观测。

## 4. 复现手法

1. 对某设备启用 **`power/control=auto`** 与较短 **`autosuspend_delay_ms`**。
2. 长时间 **周期性触发 I/O** 使 timer **反复 armed**，增加 **expires 与回调时刻相等** 的机会。
3. 用 **`/sys/kernel/debug/pm_genpd/pm_genpd_summary`** 或驱动私有计数器观察 **suspend 次数是否在某次后归零**。

## 5. 调试方法

- **代码审阅 `pm_suspend_timer_fn()`**：检查 **时间与 `timer_expires` 的比较边界**。
- **trace event：`rpm`** 观察 **是否仍有 suspend 请求** 但 **timer 不再触发**。
- **二分内核**：定位到本 commit 后问题消失。

## 6. 解决办法

- 将条件由：
  - `expires > 0 && expires < ktime_get_mono_fast_ns()`
- 改为：
  - `expires > 0 && expires <= ktime_get_mono_fast_ns()`

**修复原理**：**到期语义**应包含 **恰好在到期时刻触发** 的情形；否则边界上 **既不挂起又不重设状态机**，会留下 **持久性错误标志**。

## 7. 经验总结

- **时间比较**在 PM 里是高频 bug 源：务必写清 **开区间/闭区间** 与 **单调时钟语义**。
- **“一字之改”** 可能修复 **持续性高功耗**——值得在 code review 中 **单独高亮**。
