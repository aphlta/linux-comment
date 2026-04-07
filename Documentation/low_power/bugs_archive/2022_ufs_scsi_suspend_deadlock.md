# 2022：UFS 系统 suspend 与 SCSI error handler 互锁（ABBA）

## 1. 提交基础信息

- **Commit ID**：`7029e2151a7c6a5c60b35996d026528e7d51aae3`
- **标题**：`scsi: ufs: Fix a deadlock between PM and the SCSI error handler`
- **作者**：Bart Van Assche（Western Digital）
- **涉及子系统**：`drivers/scsi/ufs`、SCSI 错误处理、`blk_execute_rq`
- **关键词**：`host_sem`、`SHOST_RECOVERY`、`START STOP UNIT`、`ufshcd_eh_timed_out`

## 2. 背景信息

- **UFS suspend** 路径可能通过 **SCSI 命令**（如 **START STOP UNIT**）让设备进入低功耗；实现上常 **`blk_execute_rq()`** 并持有主机侧 **信号量/锁**。
- **SCSI error handler** 在 **recovery** 状态会尝试获取同一组互斥资源以重置链路、重试命令。
- 若 suspend 线程 **持锁等待 SCSI 完成**，而 error path **需要同一把锁推进 recovery**，且 **命令层又因 recovery 状态无法完成**，即 **经典 ABBA / 交叉等待**。

**为何是移动端核心路径**：手机/平板上 UFS + aggressive suspend 是默认；死锁表现为 **睡不下去或整机卡死**。

## 3. 故障现象

- **Suspend 挂起**：长时间无响应，hung task；或 **存储子系统与 PM 同时阻塞**。
- 多平台测试中被 WD 等报告为 **系统性问题**（非单板个案）。

## 4. 复现手法

1. 启用 UFS + runtime/system PM 压力测试。
2. 在 **链路不稳定**或 **注入错误**（若测试夹具支持）时并行 **suspend**。
3. 使用 **fio + suspend 循环** 提高 **SCSI 超时与 PM** 交叠概率。

## 5. 调试方法

- **hung task 栈**：一线程在 **`blk_execute_rq`**，另一在 **`ufshcd_err_handler`** 等路径等 **`host_sem`**。
- **确认 `SHOST_RECOVERY` 与 `blk_execute_rq` 的交互**是否构成循环等待。
- **审阅 commit**：作者给出的 **两条等待链**即标准答案。

## 6. 解决办法

- **为 START STOP UNIT 设置 `SCMD_FAIL_IF_RECOVERING`**：recovery 活跃时 **快速失败**而非卡死等待。
- 新增 **`ufshcd_eh_timed_out()`**：在 **system suspending** 且命令超时场景，**绕过**常规 error handler 激活路径，**直接在 timeout 上下文做链路恢复**（`ufshcd_link_recovery()`），打破环。

**修复原理**：在 **PM 临界区**提供 **不受 recovery 状态机互锁** 的 **逃生通道**；并避免在互斥锁下等待 **可能被 recovery 阻塞** 的完成点。

## 7. 经验总结

- **块层 + SCSI EH + PM** 是三高风险叠加：任何 **`flush`/互斥等待** 都要问 **另一线程能否释放条件**。
- **超时回调**往往是 **唯一可安全做打破环操作** 的地方。
