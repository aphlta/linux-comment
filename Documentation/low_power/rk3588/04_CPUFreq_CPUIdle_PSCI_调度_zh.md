# RK3588：CPUFreq、CPUIdle、PSCI 与调度

## 1. 文档目的

说明 RK3588 **big.LITTLE** 场景下，**动态调频（CPUFreq）**、**CPU 空闲状态（CPUIdle）**、**PSCI** 与 **内核调度器** 如何共同影响 **功耗与响应延迟**，以及低功耗负责人需要盯的 **配置与常见问题**。

**原因**：仅优化 **system suspend** 不够；日常 **亮屏 idle** 耗电主要由 **freq + idle state + 后台任务** 决定。

---

## 2. 本仓库设备树：CPU 拓扑、`psci`、SCMI 时钟与 idle 状态

**SoC 根**：`rk3588-base.dtsi` 中 **`cpus`** 描述 **4× Cortex-A55（`cpu_l0`–`l3`）+ 4× Cortex-A76（`cpu_b0`–`b3`）**，**`enable-method = "psci"`**，小核/大核分别绑定 **`SCMI_CLK_CPUL`** / **`SCMI_CLK_CPUB01`** / **`SCMI_CLK_CPUB23`**（来自 `firmware/scmi`），并指向同一 **`CPU_SLEEP` idle 状态**：

```91:110:arch/arm64/boot/dts/rockchip/rk3588-base.dtsi
		cpu_l0: cpu@0 {
			device_type = "cpu";
			compatible = "arm,cortex-a55";
			reg = <0x0>;
			enable-method = "psci";
			capacity-dmips-mhz = <530>;
			clocks = <&scmi_clk SCMI_CLK_CPUL>;
			assigned-clocks = <&scmi_clk SCMI_CLK_CPUL>;
			assigned-clock-rates = <816000000>;
			cpu-idle-states = <&CPU_SLEEP>;
```

```169:178:arch/arm64/boot/dts/rockchip/rk3588-base.dtsi
		cpu_b0: cpu@400 {
			device_type = "cpu";
			compatible = "arm,cortex-a76";
			reg = <0x400>;
			enable-method = "psci";
			capacity-dmips-mhz = <1024>;
			clocks = <&scmi_clk SCMI_CLK_CPUB01>;
			assigned-clocks = <&scmi_clk SCMI_CLK_CPUB01>;
			assigned-clock-rates = <816000000>;
			cpu-idle-states = <&CPU_SLEEP>;
```

**Idle 状态表**（**`entry-method = "psci"`**，参数 **`0x0010000`**，带 **local-timer-stop** 与 latency/residency）：

```249:258:arch/arm64/boot/dts/rockchip/rk3588-base.dtsi
		idle-states {
			entry-method = "psci";
			CPU_SLEEP: cpu-sleep {
				compatible = "arm,idle-state";
				local-timer-stop;
				arm,psci-suspend-param = <0x0010000>;
				entry-latency-us = <100>;
				exit-latency-us = <120>;
				min-residency-us = <1000>;
			};
		};
```

**原因**：**DVFS 与 idle** 都依赖 **SCMI 时钟 + PSCI**；调 OPP 或改 idle 参数而不对齐固件，易出现 **卡死在高频** 或 **进 idle 无法按时退出**。

---

## 3. CPUFreq：OPP 表如何挂到每个 CPU（`rk3588-opp.dtsi`）

`arch/arm64/boot/dts/rockchip/rk3588.dtsi` **include** `rk3588-opp.dtsi`。其中定义 **`cluster0_opp_table` / `cluster1_opp_table` / `cluster2_opp_table`**（`operating-points-v2`），并在 OPP 节点上标 **`opp-microvolt`** 与 **`clock-latency-ns`**。小核簇示例（含 **`opp-suspend`** 标记，供 suspend 路径选 OPP 参考）：

```4:24:arch/arm64/boot/dts/rockchip/rk3588-opp.dtsi
	cluster0_opp_table: opp-table-cluster0 {
		compatible = "operating-points-v2";
		opp-shared;

		opp-1008000000 {
			opp-hz = /bits/ 64 <1008000000>;
			opp-microvolt = <675000 675000 950000>;
			clock-latency-ns = <40000>;
		};
...
		opp-1416000000 {
			opp-hz = /bits/ 64 <1416000000>;
			opp-microvolt = <762500 762500 950000>;
			clock-latency-ns = <40000>;
			opp-suspend;
		};
```

**绑定到逻辑 CPU**（片段）：

```156:186:arch/arm64/boot/dts/rockchip/rk3588-opp.dtsi
&cpu_b0 {
	operating-points-v2 = <&cluster1_opp_table>;
};
...
&cpu_l0 {
	operating-points-v2 = <&cluster0_opp_table>;
};
```

**GPU OPP** 亦在同文件 **`gpu_opp_table`**，并由 **`&gpu { operating-points-v2 = <&gpu_opp_table>; }`** 绑定（与 `08` 文档呼应）。

**负责人关注点**：**regulator/DVS** 与 **`opp-microvolt` 范围** 一致；修改 OPP 后需重跑 **thermal + cpufreq** 回归。

---

## 4. CPUIdle 与 PSCI（与 `02` 的衔接）

- **cpuidle 驱动** 根据 **`CPU_SLEEP`** 的 **`arm,psci-suspend-param`** 调用 **`psci_ops.cpu_suspend`**（见 `drivers/firmware/psci/psci.c` 中 **`psci_cpu_suspend_enter()`**）。  
- **与 SYSTEM_SUSPEND 不同**：idle **不执行** `suspend_devices_and_enter()` 全路径，外设驱动多数仍在 **runtime 活跃** 状态。

**调试**：`sysfs` **`/sys/devices/system/cpu/cpu*/cpuidle/state*`** 读 **`name`/`disabled`/`usage`**；必要时用内核参数临时禁用某 state 做 A/B。

---

## 5. 调度器（scheduler）

- **EAS / 能耗感知调度**（若内核启用）：任务倾向跑在 **能效核**。  
- **原因**：调度不当会导致 **大核常醒**、**小核空转**，功耗变差。

**负责人关注点**：与 **性能组** 对齐：**benchmark 模式** 是否错误地 **绑大核全开** 作为默认。

---

## 6. Thermal 联动

- **cpufreq cooling device**：降频降温。  
- **原因**：thermal 过敏感 → **体验差**；过钝 → **漏电与可靠性风险**。低功耗负责人应参与 **DVFS 与 thermal 曲线** 评审。

---

## 7. 验证与指标

- **亮屏 idle 电流** @ 固定亮度、关闭无线电变量。  
- **Monkey/UI 流畅度** vs **平均功耗**（功耗墙）。  
- **压力测试** 后温度与 **是否触发 throttling**。

---

## 8. 常见坑

- OPP 表与 **实际 PMIC 电压** 不匹配 → **不稳定或浪费**。  
- **idle 驱动** 未更新导致 **新 stepping** 无法用最深 state。  
- 用户态 **固定 performance** 做「优化」导致 **续航崩溃**。

---

## 9. 负责人交付物

- 《产品 cpufreq/cpuidle 默认策略说明》。  
- **thermal + DVFS** 联合测试报告模板。  
- 与固件团队确认 **PSCI idle 能力** 的变更记入 release note。
