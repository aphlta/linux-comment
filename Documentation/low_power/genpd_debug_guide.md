# genpd 调试手册（为什么域没关）

目标：当功耗不降或深 idle 驻留异常时，快速判断是不是电源域（genpd）没有真正断电，并定位阻塞原因。

## 1. 关键观测：`pm_genpd_summary`

- 文件位置：`/sys/kernel/debug/pm_genpd/pm_genpd_summary`
- 最常用场景：
  - “驻留很好但功耗不降”
  - “设备都睡了但域还常开”

建议配合证据包采集：[`scripts/power/collect_idle_baseline.sh`](../../scripts/power/collect_idle_baseline.sh)

## 2. 常见阻塞模式（按工程经验排序）

### 2.1 设备未 runtime suspend

- 典型原因：get/put 不平衡、autosuspend 未启用、驱动 runtime 回调未实现
- 辅助：[`scripts/power/runtime_pm_audit.sh`](../../scripts/power/runtime_pm_audit.sh)

### 2.2 依赖未满足

- child/parent domain 的依赖链导致上游不能关
- interconnect/devfreq/clk/regulator 关联未正确下电

### 2.3 唤醒能力或 IRQ 绑定导致域被保持

- wakeirq/wakeup-source 设计导致某些设备必须保持供电
- 中断亲和性/IRQ storm 使域条件永远不满足

## 3. 从“域没关”到“谁挡住了”的收敛步骤

1. 先锁定问题域（域名、目标期望状态）
2. 列出域内设备清单（找常开设备）
3. 对可疑设备逐个验证：
   - runtime 状态（active/suspended）
   - usage_count 是否归零
   - 是否存在 wakeup 保持
4. 用 A/B 禁用或移除对照验证（必须可回归）

## 4. 输出结论模板

- 域：`<domain-name>`
- 阻塞设备：`<device>`
- 阻塞原因：runtime PM / dependency / wakeup / irq
- 证据：`pm_genpd_summary` 片段 + 对比数据包
- 修复：驱动/DT/策略侧动作 + 回归脚本
