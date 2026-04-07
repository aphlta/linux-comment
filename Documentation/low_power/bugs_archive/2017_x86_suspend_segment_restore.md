# 2017：x86 resume 时 `restore_processor_context()` 顺序错误导致 S2RAM 挂死

## 1. 提交基础信息

- **Commit ID**：`7ee18d677989e99635027cee04c878950e0752b9`
- **标题**：`x86/power: Make restore_processor_context() sane`
- **作者**：Andy Lutomirski（Analyzed-by: Linus Torvalds 等）
- **涉及子系统**：`arch/x86/power/cpu.c`、段寄存器、GDT/LDT、per-CPU 访问
- **关键词**：`load_gs_index`、`KERNEL_GS_BASE`、IDT、`fix_processor_context`

## 2. 背景信息

- **S2RAM（suspend to RAM）** 需保存/恢复大量 CPU 上下文；x86_64 上 **GSBASE、用户/内核 GS 语义**极易混淆（`MSR_KERNEL_GS_BASE` 实际与用户态 GS 相关，命名历史包袱）。
- **错误的恢复顺序**会导致：在 **per-CPU 访问尚不可用** 时调用依赖 per-CPU 的 helper，或在 **LDT/GDT 未就绪** 时加载段寄存器，从而 **死机或 silent hang**。
- 本修复是对先前“修顺序 bug 的补丁”引入 **新回归** 的再修复，说明该路径对顺序 **极度敏感**。

## 3. 故障现象

- **Suspend 后无法 resume**，系统黑屏或挂死；由多位 PM 维护者与 Linus 参与分析的严重回归级问题。
- 无明显统一用户态错误码，表现为 **电源灯亮但系统不活**。

## 4. 复现手法

1. 受影响内核版本 + 常见 x86 笔记本/台式，执行 **S3**。
2. 与 **KMS、tracing、GS 基址相关特性**组合可能改变触发率（视回归窗口而定）。
3. 使用 **bisect** 在 `5b06bbcfc2c6` 一类相邻提交间定位。

## 5. 调试方法

- **串口 early console**：若仍可在早期打印，确认 hang 在 **resume 汇编/C 交界**。
- **代码审阅顺序**：严格按依赖排列——**IDT → 内核段 → per-CPU（GS/FS）→ 描述符表修复 → 用户段与 MSR**。
- **对照本 commit**：Linus 的分析链即最佳“思维导图”。

## 6. 解决办法

- **重写 `__restore_processor_context()`**：厘清 **kernelmode_gs_base / usermode_gs_base** 命名与语义；只保存必要寄存器；用 **`loadsegment()`** 等宏统一段加载。
- 按 **“先能安全执行内核代码（per-CPU 可用）→ 再恢复用户可见状态”** 的顺序恢复。

**修复原理**：resume 路径是在 **极脆弱环境**执行：**中断、段、per-CPU、页表** 的依赖构成全序；违反任一步即 undefined behavior。

## 7. 经验总结

- **架构级 PM 代码**尽量避免 inline asm 与 C helper 混用导致的隐式顺序；应用 **单一函数严格分层**。
- **命名错误的 MSR/变量**是长期地雷：代码评审要对照 **ABI 手册**而非仅看变量名。
