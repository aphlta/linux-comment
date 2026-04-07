# RK3588：显示子系统（VOP / DP / MIPI）

## 1. 文档目的

说明 **显示路径** 在 **runtime PM** 与 **system suspend/resume** 中的特点，以及 **黑屏、花屏、resume 后无画面** 类问题的典型技术点（RK3588 上涉及 **VOP、VO、bridge、panel** 等，见 `01` 电源域表）。

**原因**：显示链路 **寄存器多、时序严**，resume 顺序稍错即可 **无输出但系统仍活**（SSH 可连），易被误判为「整机死机」。

---

## 1.5 本仓库：设备树 VOP 节点与驱动中的 **两层** 电源

### DTS：`power-domains` 挂到 SoC genpd

**`arch/arm64/boot/dts/rockchip/rk3588-base.dtsi`** 中 **`vop@fdd90000`** 声明 **`rockchip,rk3588-vop`**，绑定 **`power-domains = <&power RK3588_PD_VOP>`**，并连接 **CRU 多路时钟、IOMMU、`sys_grf`/`vop_grf`/`vo1_grf`、`pmu`**：

```1263:1290:arch/arm64/boot/dts/rockchip/rk3588-base.dtsi
	vop: vop@fdd90000 {
		compatible = "rockchip,rk3588-vop";
		reg = <0x0 0xfdd90000 0x0 0x4200>, <0x0 0xfdd95000 0x0 0x1000>;
		reg-names = "vop", "gamma-lut";
		interrupts = <GIC_SPI 156 IRQ_TYPE_LEVEL_HIGH 0>;
		clocks = <&cru ACLK_VOP>,
			 <&cru HCLK_VOP>,
			 <&cru DCLK_VOP0>,
			 <&cru DCLK_VOP1>,
			 <&cru DCLK_VOP2>,
			 <&cru DCLK_VOP3>,
			 <&cru PCLK_VOP_ROOT>,
			 <&hdptxphy0>;
...
		iommus = <&vop_mmu>;
		power-domains = <&power RK3588_PD_VOP>;
		rockchip,grf = <&sys_grf>;
		rockchip,vop-grf = <&vop_grf>;
		rockchip,vo1-grf = <&vo1_grf>;
		rockchip,pmu = <&pmu>;
		status = "disabled";
```

**原因**：**外设级 genpd（RK3588_PD_VOP）** 由 `pm-domains.c` 驱动；与 **VOP 内部子模块** 不是同一层。

### 驱动：`rockchip_drm_vop2.c` 在 **RK3588** 上写 **内部 PD 寄存器**

**`vop2_enable()`** 在探测到 **`vop2->version == VOP_VERSION_RK3588`** 时调用 **`rk3588_vop2_power_domain_enable_all()`**：向 **`RK3588_SYS_PD_CTRL`** 写入，**清除** `VOP2_PD_CLUSTER0..3` 与 **`VOP2_PD_ESMART`** 位（即 **打开** Cluster/Esmart 内部电源域）：

```807:816:drivers/gpu/drm/rockchip/rockchip_drm_vop2.c
static void rk3588_vop2_power_domain_enable_all(struct vop2 *vop2)
{
	u32 pd;

	pd = vop2_readl(vop2, RK3588_SYS_PD_CTRL);
	pd &= ~(VOP2_PD_CLUSTER0 | VOP2_PD_CLUSTER1 | VOP2_PD_CLUSTER2 |
		VOP2_PD_CLUSTER3 | VOP2_PD_ESMART);

	vop2_writel(vop2, RK3588_SYS_PD_CTRL, pd);
}
```

同一文件 **`vop2_enable()`** 开头使用 **`pm_runtime_resume_and_get()`** 拉活设备；**`vop2_disable()`** 里 **`pm_runtime_put_sync()`** 并 **`regcache_drop_region()`** 丢弃 regmap 缓存：

```818:884:drivers/gpu/drm/rockchip/rockchip_drm_vop2.c
static void vop2_enable(struct vop2 *vop2)
{
	int ret;
	u32 version;

	ret = pm_runtime_resume_and_get(vop2->dev);
	if (ret < 0) {
		drm_err(vop2->drm, "failed to get pm runtime: %d\n", ret);
		return;
	}
...
	if (vop2->version == VOP_VERSION_RK3588)
		rk3588_vop2_power_domain_enable_all(vop2);
...
}

static void vop2_disable(struct vop2 *vop2)
{
	rockchip_drm_dma_detach_device(vop2->drm, vop2->dev);

	pm_runtime_put_sync(vop2->dev);

	regcache_drop_region(vop2->map, 0, vop2_regmap_config.max_register);
```

**原因**：这正是 **LKML 上讨论 regcache_sync vs 上电顺序** 的硬件背景：**Cluster/Esmart 寄存器在内部 PD 未开前不可假定可写**；排障时要同时看 **genpd 是否 on** 与 **`RK3588_SYS_PD_CTRL`** 相关路径是否执行。

---

## 2. 软件栈（Linux）

- **DRM/KMS**：`rockchipdrm` + **VOP** 驱动。  
- **Bridge / Panel**：DSI、eDP、HDMI 转接芯片、面板驱动。  
- **Atomic commit**：模式设置与 **power** 状态切换交错时需保证 **状态一致**。

---

## 3. 电源域与 PD 映射（回顾）

- `RK3588_PD_VOP`、`RK3588_PD_VO0`、`RK3588_PD_VO1` 等属于 **VD_LOGIC**（见 `01`）。  
- **原因**：显示 idle 时应释放 **runtime PM**，避免长期撑住 **VOP 域** 增耗。

---

## 4. Suspend / Resume 关注点

1. **模式保存**：分辨率、色彩格式、DSC 是否启用。  
2. **链路 training**：eDP/DP **LT**、HDMI **TMDS/FRL** 是否在 resume 重跑。  
3. **Panel 电源时序**：`reset-gpios`、`enable-gpios`、上电延时 **T1/T2**。  
4. **PSR（Panel Self Refresh）**：省电特性有时与 **suspend** 组合出 bug，**A/B 关闭 PSR** 是有效诊断手段。

**原因**：面板 spec 若要求 **硬复位** 才能从 deep sleep 恢复，软件未拉 **reset** → 黑屏。

---

## 5. DPMS vs System Suspend

- **关屏（DPMS off）** 不一定等价于 **system suspend**；前者可能仅关 **背光/时序**，后者还走 **全局 PM**。  
- **排查**：若仅 suspend 出问题而 DPMS 正常，怀疑 **noirq 阶段** 或 **共享时钟/电源** 被其他驱动影响。

---

## 6. 调试手段

- `dmesg` 中 **drm/bridge/panel** 错误行。  
- **强制 modeset**：用户态工具或 `chvt` 切换 VT 是否恢复。  
- **对比** `video=` 内核参数、禁用 **splash**。  
- **多显**：逐个断开 **副屏** 复现。

详见案例库 [10](10_故障案例库_RK3588_zh.md) **案例 D**（VOP2/regcache）及 **附录 B**（黑屏类）。

---

## 7. 功耗优化（运行态）

- **空闲降帧**、**内容自适应亮度** 属产品策略。  
- **硬件**：背光效率、屏自刷新。  
- **驱动**：无显示内容时 **关闭不必要 pipeline**。

---

## 8. 常见坑

- **resume 顺序**：panel 早于 bridge 上电。  
- **DSC/高带宽** 未在 resume **重新配置** 寄存器。  
- **共享 1V8/3V3** 被 Wi‑Fi 等拉死，显示芯片未真正断电。

---

## 9. 负责人交付物

- 显示驱动 **suspend/resume review** 必查项（时序图）。  
- 认证 **面板列表** + 每款的 **reset 序列**。  
- 显示专项 **suspend 循环** 自动化用例。
