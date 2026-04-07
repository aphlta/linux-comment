# RK3588：固件与信任链（BL31 / DDR / PSCI）

## 1. 文档目的

说明 **ARM Trusted Firmware-A（TF-A）BL31**、**PSCI** 与 **DDR 初始化/自刷新** 在 **系统休眠（SYSTEM_SUSPEND）** 路径中的作用，以及原厂负责人与固件、内核的 **契约** 应包含哪些内容。

**原因**：RK3588 上大量「睡不醒」「随机死机」类问题，根因在 **BL31 + DDR blob 版本** 与 **内核假设** 不一致；仅改内核往往无效。

---

## 2. 信任链与启动角色（概念）

典型 AArch64 启动：**BootROM → SPL/Miniloader → U-Boot/UEFI → Linux**，安全世界侧为 **BL31** 常驻，提供 **PSCI** 服务（CPU on/off、idle、suspend 等）。

**负责人需明确**：你们产品线上 **BL31 构建来源**（厂商发布包 / 自编译）、**DDR bin** 是否独立更新、与 **内核 DT** 的匹配关系。

---

## 3. PSCI、SCMI 与系统休眠（本仓库代码）

### 3.1 设备树：`psci` + `arm,scmi-smc`

```360:377:arch/arm64/boot/dts/rockchip/rk3588-base.dtsi
	firmware {
		scmi: scmi {
			compatible = "arm,scmi-smc";
			arm,smc-id = <0x82000010>;
			shmem = <&scmi_shmem>;
			#address-cells = <1>;
			#size-cells = <0>;

			scmi_clk: protocol@14 {
				reg = <0x14>;
				#clock-cells = <1>;
			};

			scmi_reset: protocol@16 {
				reg = <0x16>;
				#reset-cells = <1>;
			};
		};
	};
```

```406:409:arch/arm64/boot/dts/rockchip/rk3588-base.dtsi
	psci {
		compatible = "arm,psci-1.0";
		method = "smc";
	};
```

### 3.2 通用休眠：`suspend_ops->enter` → `PSCI SYSTEM_SUSPEND`

```452:458:kernel/power/suspend.c
	error = syscore_suspend();
	if (!error) {
		*wakeup = pm_wakeup_pending();
		if (!(suspend_test(TEST_CORE) || *wakeup)) {
			trace_suspend_resume(TPS("machine_suspend"),
				state, true);
			error = suspend_ops->enter(state);
```

```530:548:drivers/firmware/psci/psci.c
static int psci_system_suspend(unsigned long unused)
{
	int err;
	phys_addr_t pa_cpu_resume = __pa_symbol(cpu_resume);

	err = invoke_psci_fn(PSCI_FN_NATIVE(1_0, SYSTEM_SUSPEND),
			      pa_cpu_resume, 0, 0);
	return psci_to_linux_errno(err);
}

static int psci_system_suspend_enter(suspend_state_t state)
{
	return cpu_suspend(0, psci_system_suspend);
}

static const struct platform_suspend_ops psci_suspend_ops = {
	.valid          = suspend_valid_only_mem,
	.enter          = psci_system_suspend_enter,
};
```

### 3.3 Rockchip SIP（DDR / PD 与固件对话的 SMC 号）

```9:21:include/soc/rockchip/rockchip_sip.h
#define ROCKCHIP_SIP_SUSPEND_MODE		0x82000003
#define ROCKCHIP_SLEEP_PD_CONFIG		0xff

#define ROCKCHIP_SIP_DRAM_FREQ			0x82000008
#define ROCKCHIP_SIP_CONFIG_DRAM_INIT		0x00
#define ROCKCHIP_SIP_CONFIG_DRAM_SET_RATE	0x01
#define ROCKCHIP_SIP_CONFIG_DRAM_ROUND_RATE	0x02
#define ROCKCHIP_SIP_CONFIG_DRAM_SET_AT_SR	0x03
```

**原因**：**系统休眠** 走 **PSCI SYSTEM_SUSPEND**；**运行期 genpd** 写 PMU 后还会通过 **`ROCKCHIP_SIP_SUSPEND_MODE`** 通知固件（见 `01` 文档 `rockchip_do_pmu_set_power_domain()` 片段）。**DDR 自刷新参数** 则落在 **`ROCKCHIP_SIP_DRAM_*`** 子命令空间，需与 BL31/blob 一致。

### 3.4 CPU idle（对比）

**CPU idle** 使用 DTS **`cpu-idle-states`** 的 **`arm,psci-suspend-param`**（`rk3588-base.dtsi` `cpus/idle-states`），走 **`psci_cpu_suspend_enter()`**，与上一节的 **SYSTEM_SUSPEND** 是 **不同 PSCI 函数**。

---

## 4. DDR 与自刷新（SFR）

- **Suspend**：期望 DDR 进入 **自刷新** 以降低功耗；PHY/控制器状态由 **训练结果 + 固件流程** 决定。  
- **Resume**：需 **正确退出自刷新**、恢复时钟与 PHY；若 **blob 与板级 DRAM 型号/走线** 不匹配，易出现 **偶发训练失败**。

**社区现象**：维护者提及 **更新 DDR 与 BL31 blob** 可修复部分 suspend 问题（需整包验证，避免引入新不稳定）。详见案例库 [10_故障案例库_RK3588_zh.md](10_故障案例库_RK3588_zh.md) **案例 B**（及可与 **案例 A** 并行排查）。

---

## 5. 固件—内核契约清单（建议写入 Release Note）

| 项目 | 说明 |
|------|------|
| BL31 版本 / Git SHA | 与内核发布绑定 |
| DDR init 训练 blob 版本 | 是否变更 timing、PHY 参数 |
| 支持的 PSCI 功能 | SYSTEM_SUSPEND 是否启用、平台特定保留 |
| 传递参数 | 共享内存、OS_REG、GRF 保留位含义 |
| 已知限制 | 某 stepping 需 workaround |

**原因**：缺少矩阵时，客户 **单独升级内核** 或 **单独升级固件** 都会触发不可预期休眠故障。

---

## 6. 调试建议

- **串口**：观察 BL31 侧若可配 **log level**（视构建选项）。  
- **对比实验**：仅回滚 BL31+DDR，保持内核不变，若问题消失则 **优先固件**。  
- **硬件**：不同 DRAM 容量/厂商颗粒需单独认证。

---

## 7. 与 OP-TEE / 其他 EL3 常驻固件

若平台启用 **TEE**，suspend 路径可能涉及 **安全外设保存**；负责人需确认 **TEE 与 NS 世界 suspend 顺序** 由谁定义，避免 **共享资源未释放**。

---

## 8. 常见坑

- 客户混用 **不同板型** 的 DDR blob。  
- 调试版 BL31 打开过多 log 导致 **时序裕量变化**（偶发问题）。  
- 未文档化的 **GRF/OS_REG** 被内核或 U-Boot 改写，resume 后 **带宽/类型信息** 错误。

---

## 9. 负责人交付物

- **《固件-内核兼容性矩阵》** 每版发布更新。  
- suspend 问题 **分层规则**：先查矩阵再开内核 bug。  
- 对 IC 反馈的 **silicon errata**，推动在 BL31 侧 **统一修复**，避免各 ODM 各写一套。
