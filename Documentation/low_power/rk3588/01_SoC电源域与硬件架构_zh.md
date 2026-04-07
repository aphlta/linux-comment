# RK3588：SoC 电源域与硬件架构

## 1. 文档目的与职责边界

**目的**：让低功耗负责人与驱动 owner 对 RK3588 **电源域（Power Domain, PD）** 与 **电压域** 有统一心智模型，避免关电顺序错误、漏电或唤醒异常。

**边界**：寄存器级细节以 **Rockchip TRM / 内部文档** 为准；本文 **电源域枚举** 与 Linux 设备树绑定一致，便于对照 BSP DTS。

**原因**：内核 `generic_pm_domain` 通过 **ID** 与硬件 PD 控制器对话；ID 错误或依赖未声明会导致 **timeout、hang 或 silent 漏电**。

---

## 2. 主线绑定：`rk3588-power.h` 全表与业务映射

下列定义来自 Linux 主线头文件  
[`include/dt-bindings/power/rk3588-power.h`](../../include/dt-bindings/power/rk3588-power.h)  
（路径相对于本仓库根目录：`linux-stable/include/dt-bindings/power/rk3588-power.h`）。

### 2.0 设备树里的 PD 控制器与外设挂接（本仓库）

SoC 在 **`arch/arm64/boot/dts/rockchip/rk3588-base.dtsi`** 中把 PMU 块声明为 `rockchip,rk3588-pmu`，其下子节点 **`power-controller`** 的 compatible 为 **`rockchip,rk3588-power-controller`**，并展开 **嵌套 `power-domain@RK3588_PD_*`**：每个节点 `reg = <RK3588_PD_xxx>` 与 `rk3588-power.h` 中宏一一对应，且可为子域列出 **`clocks`**、**`pm_qos`** 等，供驱动在开关域时配合 **时钟门控与 NIU QoS**。

```827:836:arch/arm64/boot/dts/rockchip/rk3588-base.dtsi
	pmu: power-management@fd8d8000 {
		compatible = "rockchip,rk3588-pmu", "syscon", "simple-mfd";
		reg = <0x0 0xfd8d8000 0x0 0x400>;

		power: power-controller {
			compatible = "rockchip,rk3588-power-controller";
			#address-cells = <1>;
			#power-domain-cells = <1>;
			#size-cells = <0>;
			status = "okay";
```

外设通过 **`power-domains = <&power RK3588_PD_xxx>`** 声明自己属于哪个 genpd。例如 GPU、USB3 主机：

```454:470:arch/arm64/boot/dts/rockchip/rk3588-base.dtsi
	gpu: gpu@fb000000 {
		compatible = "rockchip,rk3588-mali", "arm,mali-valhall-csf";
		reg = <0x0 0xfb000000 0x0 0x200000>;
		#cooling-cells = <2>;
		assigned-clocks = <&scmi_clk SCMI_CLK_GPU>;
		assigned-clock-rates = <200000000>;
		clocks = <&cru CLK_GPU>, <&cru CLK_GPU_COREGROUP>,
			 <&cru CLK_GPU_STACKS>;
		clock-names = "core", "coregroup", "stacks";
		dynamic-power-coefficient = <2982>;
		interrupts = <GIC_SPI 92 IRQ_TYPE_LEVEL_HIGH 0>,
			     <GIC_SPI 93 IRQ_TYPE_LEVEL_HIGH 0>,
			     <GIC_SPI 94 IRQ_TYPE_LEVEL_HIGH 0>;
		interrupt-names = "job", "mmu", "gpu";
		power-domains = <&power RK3588_PD_GPU>;
		status = "disabled";
	};
```

**驱动侧**：**`drivers/pmdomain/rockchip/pm-domains.c`** 中 **`rk3588_pmu`** 描述该 SoC PMU 寄存器布局（`pwr_offset`、`status_offset`、`req_offset` 等），**`rk3588_pm_domains[]`** 用 `DOMAIN_RK3588()` 把 **每个 PD ID 映射到 PMU 里的 bit 掩码**（电源请求/状态/idle/ack/mem 等）。`rockchip_pd_power_on/off()` 最终调用 **`rockchip_pd_power()`**：先 **`clk_bulk_enable`**、按需 **`rockchip_pmu_set_idle_request()`**，再 **`rockchip_do_pmu_set_power_domain()`** 写寄存器并 **轮询 `rockchip_pmu_domain_is_on()`** 等待硬件确认。

```593:637:drivers/pmdomain/rockchip/pm-domains.c
static int rockchip_pd_power(struct rockchip_pm_domain *pd, bool power_on)
{
	struct rockchip_pmu *pmu = pd->pmu;
	int ret;

	guard(mutex)(&pmu->mutex);

	if (rockchip_pmu_domain_is_on(pd) == power_on)
		return 0;

	ret = clk_bulk_enable(pd->num_clks, pd->clks);
	if (ret < 0) {
		dev_err(pmu->dev, "failed to enable clocks\n");
		return ret;
	}

	rockchip_pmu_ungate_clk(pd, true);

	if (!power_on) {
		rockchip_pmu_save_qos(pd);

		/* if powering down, idle request to NIU first */
		ret = rockchip_pmu_set_idle_request(pd, true);
		if (ret < 0)
			goto out;
	}

	ret = rockchip_do_pmu_set_power_domain(pd, power_on);
	if (ret < 0)
		goto out;

	if (power_on) {
		/* if powering up, leave idle mode */
		ret = rockchip_pmu_set_idle_request(pd, false);
		if (ret < 0)
			goto out;

		rockchip_pmu_restore_qos(pd);
	}

out:
	rockchip_pmu_ungate_clk(pd, false);
	clk_bulk_disable(pd->num_clks, pd->clks);

	return ret;
}
```

对 **需要外部稳压器** 的域（表中 `need_regulator = true`），`rockchip_pd_power_on()` 还会在 **`rockchip_pd_power(..., true)` 之前** `regulator_enable()`，关断时 **`power_off` 之后** `regulator_disable()`。RK3588 上 **GPU、NPU** 在 `rk3588_pm_domains[]` 里标记为 **`need_regulator`**（见同文件约 1235–1236 行），与 DTS 里可选的 **`domain` supply** 配合。

固件侧通知：在 **`rockchip_do_pmu_set_power_domain()`** 成功写 PMU 后，若存在 SMC 通道，会调用 **`arm_smccc_smc(ROCKCHIP_SIP_SUSPEND_MODE, ROCKCHIP_SLEEP_PD_CONFIG, ...)`**（常量定义见 **`include/soc/rockchip/rockchip_sip.h`**），让 **TF-A/BL31** 在 **系统级休眠** 时记住各 PD 目标状态——这是 **genpd runtime** 与 **深度睡眠** 必须一致的关键耦合点。

### 2.1 电压域与 CPU 簇

| 宏名 | ID | 头文件注释电压域 | 语义 |
|------|----|------------------|------|
| `RK3588_PD_CPU_0` … `RK3588_PD_CPU_3` | 0–3 | VD_LITDSU | 小核簇相关（per-CPU 域，具体映射以 TRM 为准） |
| `RK3588_PD_CPU_4` … `RK3588_PD_CPU_5` | 4–5 | VD_BIGCORE0 | 大核簇 0 |
| `RK3588_PD_CPU_6` … `RK3588_PD_CPU_7` | 6–7 | VD_BIGCORE1 | 大核簇 1 |

**原因**：big.LITTLE 下 **CPU offline / idle** 与 **簇级关电** 由 PSCI、驱动与硬件策略共同决定；DTS 中 `power-domains = <&xxx RK3588_PD_CPU_n>` 需与 **实际硬接线** 一致。

### 2.2 NPU / GPU

| 宏名 | ID | 电压域 | 语义 |
|------|----|--------|------|
| `RK3588_PD_NPU` | 8 | VD_NPU | NPU 根域 |
| `RK3588_PD_NPUTOP` | 9 | VD_NPU | NPU 顶部逻辑 |
| `RK3588_PD_NPU1` | 10 | VD_NPU | NPU 子分区 |
| `RK3588_PD_NPU2` | 11 | VD_NPU | NPU 子分区 |
| `RK3588_PD_GPU` | 12 | VD_GPU | GPU |

**原因**：NPU 常拆 **多子域**；驱动需按 **使用顺序** 上电，idle 时 **从叶到根** 下电，避免悬空时钟或总线访问已关域。

### 2.3 视频编解码

| 宏名 | ID | 电压域 | 语义 |
|------|----|--------|------|
| `RK3588_PD_VCODEC` | 13 | VD_VCODEC | 编解码公共 |
| `RK3588_PD_RKVDEC0` / `RKVDEC1` | 14–15 | VD_VCODEC | 解码实例 |
| `RK3588_PD_VENC0` / `VENC1` | 16–17 | VD_VCODEC | 编码实例 |

### 2.4 DDR 控制器域

| 宏名 | ID | 电压域 | 语义 |
|------|----|--------|------|
| `RK3588_PD_DDR01` | 18 | VD_DD01 | DDR 通道组 |
| `RK3588_PD_DDR23` | 19 | VD_DD23 | DDR 通道组 |

**原因**：**系统级 suspend** 时常与 **DDR 自刷新** 强相关；DDR 域策略错误可导致 **无法进深睡或 resume 失败**（见 `02`、`05`）。

### 2.5 逻辑大域（多媒体、IO、安全等）

| 宏名 | ID | 电压域 | 典型关联 IP |
|------|----|--------|----------------|
| `RK3588_PD_CENTER` | 20 | VD_LOGIC | 中心互连等 |
| `RK3588_PD_VDPU` | 21 | VD_LOGIC | 视频处理 |
| `RK3588_PD_RGA30` / `RGA31` | 22, 30 | VD_LOGIC | RGA |
| `RK3588_PD_AV1` | 23 | VD_LOGIC | AV1 |
| `RK3588_PD_VOP` | 24 | VD_LOGIC | 显示控制器 |
| `RK3588_PD_VO0` / `VO1` | 25–26 | VD_LOGIC | 显示输出通道 |
| `RK3588_PD_VI` | 27 | VD_LOGIC | 视频输入 |
| `RK3588_PD_ISP1` | 28 | VD_LOGIC | ISP |
| `RK3588_PD_FEC` | 29 | VD_LOGIC | FEC |
| `RK3588_PD_USB` | 31 | VD_LOGIC | USB |
| `RK3588_PD_PHP` | 32 | VD_LOGIC | PHP（按 TRM） |
| `RK3588_PD_GMAC` | 33 | VD_LOGIC | 以太网 MAC |
| `RK3588_PD_PCIE` | 34 | VD_LOGIC | PCIe |
| `RK3588_PD_NVM` / `NVM0` | 35–36 | VD_LOGIC | 存储相关 |
| `RK3588_PD_SDIO` | 37 | VD_LOGIC | SDIO |
| `RK3588_PD_AUDIO` | 38 | VD_LOGIC | 音频 |
| `RK3588_PD_SECURE` | 39 | VD_LOGIC | 安全子系统 |
| `RK3588_PD_SDMMC` | 40 | VD_LOGIC | SD/MMC |
| `RK3588_PD_CRYPTO` | 41 | VD_LOGIC | 加解密 |
| `RK3588_PD_BUS` | 42 | VD_LOGIC | 总线相关 |

### 2.6 PMU 域

| 宏名 | ID | 电压域 | 语义 |
|------|----|--------|------|
| `RK3588_PD_PMU1` | 43 | VD_PMU | PMU 侧常电逻辑 |

**原因**：`VD_PMU` 上模块往往在 **深睡仍保持最小逻辑**；调试 **唤醒源** 时常需看 PMU/GRF 相关寄存器（BSP/文档）。

---

## 3. GRF / PMUGRF 与 OS_REG

RK3588 使用 **系统 GRF**、**PMU GRF** 等 syscon 做 **strap、复用、低功耗旁路** 配置。主线可见如 `include/soc/rockchip/rk3588_grf.h` 中与 **OS 可见寄存器** 相关的定义（例如 DRAM 类型、带宽信息位），多用于 **启动与固件交接**，suspend 路径上具体行为以 BSP 为准。

**负责人关注点**：任何 **跨休眠保留字段** 的修改必须经 **固件+内核** 双方评审，避免 resume 后 **DRAM/总线参数** 与训练结果不一致。

---

## 4. 关电顺序（原则性，非替代 TRM）

1. **停止业务**：DMA 停、时钟门控前置条件满足。  
2. **子设备 runtime 空闲**：无用户 hold `power-domain`。  
3. **自叶向根** 关闭 PD（与 DTS `power-domain` 父子关系一致）。  
4. **上电反向**：先父后子，再解 reset、开时钟。

**原因**：违反顺序的典型后果：**总线访问黑洞**（timeout）、**硬件 lockup**、**内核 PM 回调永久等待**。

---

## 5. 与软件栈的衔接

- **设备树**：各 IP 通过 `power-domains = <&power RK3588_PD_xxx>` 声明依赖。  
- **驱动**：`pm_runtime_get_sync` / `pm_runtime_put_sync` 与 **genpd** 联动。  
- **system suspend**：部分域由 **固件** 在最终阶段统一处理；与内核 `suspend` 顺序需一致（见 `03`、`02`）。

---

## 6. 验证与指标

- 压力场景下 **无 PD 超时日志**（具体字段依 BSP）。  
- 待机时 **多媒体/PCIe 域** 应随 idle 关闭（若硬件设计允许）。  
- 与 **电流分解** 对照（见 `09`、`10` **附录 B** 待机电流）。

---

## 7. 常见坑

- DTS **PD ID 抄错** 或 **父子关系缺失**。  
- 驱动 **probe 阶段** 过早开域导致 **boot 顺序** 与硬件默认冲突。  
- **忽略 NPU/GPU 多子域** 只关其中一个，其余漏电。  
- **PCIe/USB** 外设未 runtime idle，长期撑住父域。

---

## 8. 负责人交付物建议

- 《RK3588 电源域与驱动映射表》（Excel）：IP → PD 宏 → 驱动文件 → owner。  
- DTS 变更 **PD 相关** 必过 **低功耗评审**。  
- 新版本 TRM **PD 章节** diff 同步到软件团队。
