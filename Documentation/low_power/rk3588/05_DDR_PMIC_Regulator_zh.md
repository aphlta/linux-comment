# RK3588：DDR、PMIC 与 Regulator

## 1. 文档目的

从 **低功耗负责人** 视角说明 **DDR 功耗形态**、**PMIC 供电轨** 与 Linux **regulator 框架** 在 **运行态 / suspend** 下的配合，以及 **待机电流分解** 时常用的分析维度。

**原因**：suspend 电流不达标时，大量问题落在 **DDR 未进自刷新**、**某 rail 常开** 或 **DVS 配置错误**，而非应用层。

---

## 2. DDR 功耗要点与内核可见的「固件接口」

- **活动态**：时钟与读写切换耗电最高。  
- **自刷新（Self-Refresh）**：suspend 目标态之一；**具体进入/退出** 在 **`PSCI SYSTEM_SUSPEND`** 路径上由 **BL31** 主导，内核侧还可通过 **Rockchip SIP** 子命令影响 DRAM 配置（**本仓库** 仅见 **常量定义**，实现在固件）：见 **`include/soc/rockchip/rockchip_sip.h`** 中 **`ROCKCHIP_SIP_CONFIG_DRAM_SET_AT_SR`** 等（`02` 已引用）。  
- **原因**：若软件或固件路径错误，DDR 可能 **长时间保持较高功耗**，或 **resume 训练失败**。

**调试线索**：示波器观察 **CKE**、**CK**；软件侧对比 **不同 BL31+DDR blob** 下 **`/sys/kernel/debug`** 中 Rockchip 若有暴露的 DRAM 节点（BSP 常见，主线未必启用）。

---

## 3. PMIC 与供电轨（原则）

典型 RK3588 整机含多路 **Buck / LDO**：SoC 主核、DDR、PLL、IO、外设等。

**负责人需维护**（内部文档）：

| Rail | 负载 | suspend 策略 | DTS regulator 名 |
|------|------|--------------|------------------|
| 示例 | SoC logic | 可能由 PMIC 序列降电 | `vdd_logic` 等 |
| 示例 | DDR | 与 SRF 协同 | `vdd_ddr` 等 |

*表内为占位；真实名称以 **原理图 + BSP DTS** 为准。*

**原因**：ODM 改 **PMIC 型号** 但未改 DTS → **电压错配或序错** → boot/suspend 异常。

---

## 4. Linux Regulator 与 RK3588 genpd（本仓库：`pm-domains.c`）

**说明**：板级 **RK806** 等 PMIC 的 **suspend 序列** 多在 **厂商 BSP**；主线可对照的是 **SoC genpd 何时开关外部 supply**。

**`need_regulator` 域**：`rk3588_pm_domains[]` 中 **GPU、NPU** 等为 **`true`**。`rockchip_pd_power_on/off()` 在 **`rockchip_pd_power()` 前后** 调用 **`rockchip_pd_regulator_enable/disable()`**（从对应 PD 设备树节点的 **`domain` phandle** 解析 `regulator`）：

```662:690:drivers/pmdomain/rockchip/pm-domains.c
static int rockchip_pd_power_on(struct generic_pm_domain *domain)
{
	struct rockchip_pm_domain *pd = to_rockchip_pd(domain);
	int ret;

	ret = rockchip_pd_regulator_enable(pd);
	if (ret) {
		dev_err(pd->pmu->dev, "Failed to enable supply: %d\n", ret);
		return ret;
	}

	ret = rockchip_pd_power(pd, true);
	if (ret)
		rockchip_pd_regulator_disable(pd);

	return ret;
}

static int rockchip_pd_power_off(struct generic_pm_domain *domain)
{
	struct rockchip_pm_domain *pd = to_rockchip_pd(domain);
	int ret;

	ret = rockchip_pd_power(pd, false);
	if (ret)
		return ret;

	rockchip_pd_regulator_disable(pd);
	return 0;
}
```

**系统级 suspend**：各 PMIC 驱动可实现 **`regulator_suspend_prepare`/`finish`**（`CONFIG_PM_SLEEP`），在 **`suspend_devices_and_enter()`** 路径上 **批量调整电压/开关**——需在内核配置中启用并与 **板级 DTS constraints** 一致。

**DVS 与 OPP**：`rk3588-opp.dtsi` 的 **`opp-microvolt`** 需与 **实际 `cpu-supply`/`gpu` supply** 能力匹配（见 `04`）。

**原因**：**DTS 漏配 domain supply** → **上电失败**；**OPP 电压超出 PMIC 能力** → ** cpufreq 报错或 silent 限频**。

---

## 5. `regulator-always-on` / `boot-on` 审计

- **`regulator-always-on`**：内核永不关断；过多会 **抬高待机底电流**。  
- **`regulator-boot-on`**：启动阶段保持，后续是否可关依设计。

**负责人动作**：新产品 **逐项审计**：是否必须 always-on；能否改为 **驱动 runtime 控制**。

---

## 6. 与电源域（PD）的关系

- **PD 关断** 前常需 **关联 rail** 仍满足 **Retention 电压**（若有）；顺序由 **硬件 TRM** 定义。  
- **原因**：先断 rail 再关 PD 或相反错误 → **死锁或损坏风险**（依设计）。

---

## 7. 待机电流分解方法（概要）

1. 测 **整机 suspend 电流**。  
2. **移除外设**（USB 设备、SSD、屏背光独立供电等）对比。  
3. 若可 **飞线/跳线帽**：分段测 **SoC+DDR** vs **底板**。  
4. 软件 **最小 rootfs** 排除守护进程漏电。

详见 [09_现场测量与日志方法论_zh.md](09_现场测量与日志方法论_zh.md)、案例 [10](10_故障案例库_RK3588_zh.md) **附录 B**（待机电流条目）。

---

## 8. 常见坑

- **原理图与 DTS regulator 名** 不一致。  
- **suspend 时序** 与 **唤醒源供电** 冲突（例如关掉唤醒脚所在 rail）。  
- **DDR 参考电压** 与颗粒认证不符 → 低温/高温 suspend 失败。

---

## 9. 负责人交付物

- 《PMIC rail — DTS — 驱动》三方对照表。  
- 每款 PMIC **suspend 序列** 由模拟签字。  
- 待机电流 **baseline** 与偏差告警阈值。
