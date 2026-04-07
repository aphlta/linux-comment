# RK3588：高速外设（PCIe / USB / GMAC）

## 1. 文档目的

说明 **PCIe、USB、以太网（GMAC）** 在 **runtime PM**、**系统休眠** 与 **唤醒** 中的常见机制，以及 **阻止 suspend、秒醒、resume 超时** 的排查思路。RK3588 上对应电源域见 `RK3588_PD_PCIE`、`RK3588_PD_USB`、`RK3588_PD_GMAC`（`01`）。

**原因**：外设 **IRQ 频繁**、**远程唤醒**、**ASPM 兼容性** 是低功耗 bug 高发区。

---

## 1.5 本仓库：DTS 中的 PCIe / USB3 与 genpd 标记

### 电源域驱动：`RK3588_PD_PCIE` / `RK3588_PD_USB` 为 **active_wakeup**

在 **`drivers/pmdomain/rockchip/pm-domains.c`** 的 **`rk3588_pm_domains[]`** 中，**`pcie`** 与 **`usb`** 条目的 **`active_wakeup` 为 `true`**（宏 `DOMAIN_RK3588` 最后一参）。含义：**这些域上的设备更常作为唤醒源**，genpd 框架会设置相应标志，避免 **误关断导致无法唤醒**（细节见 `struct rockchip_domain_info` 与 `rockchip_pm_add_one_domain()` 内对 `active_wakeup` 的处理）。

```1257:1262:drivers/pmdomain/rockchip/pm-domains.c
	[RK3588_PD_GMAC]	= DOMAIN_RK3588("gmac",    0x4, BIT(6),  0,       0x0, BIT(30), BIT(21), 0x0, 0,       0,       false, false),
	[RK3588_PD_PCIE]	= DOMAIN_RK3588("pcie",    0x4, BIT(7),  0,       0x0, BIT(31), BIT(22), 0x0, 0,       0,       true, false),
	[RK3588_PD_NVM]		= DOMAIN_RK3588("nvm",     0x4, BIT(8),  BIT(24), 0x4, 0,       0,       0x4, BIT(2),  BIT(18), false, false),
...
	[RK3588_PD_USB]		= DOMAIN_RK3588("usb",     0x4, BIT(11), 0,       0x4, BIT(3),  BIT(25), 0x4, BIT(4),  BIT(20), true, false),
```

### 设备树：USB3 DWC3 与 PCIe 控制器

**`rk3588-base.dtsi`** 中 **`usb_host0_xhci`**：`compatible = "rockchip,rk3588-dwc3", "snps,dwc3"`，**`power-domains = <&power RK3588_PD_USB>`**，并带大量 **`snps,*-quirk`** 属性（与 PHY/链路兼容性相关，间接影响 **suspend/Ux**）：

```472:484:arch/arm64/boot/dts/rockchip/rk3588-base.dtsi
	usb_host0_xhci: usb@fc000000 {
		compatible = "rockchip,rk3588-dwc3", "snps,dwc3";
		reg = <0x0 0xfc000000 0x0 0x400000>;
		interrupts = <GIC_SPI 220 IRQ_TYPE_LEVEL_HIGH 0>;
		clocks = <&cru REF_CLK_USB3OTG0>, <&cru SUSPEND_CLK_USB3OTG0>,
			 <&cru ACLK_USB3OTG0>;
		clock-names = "ref_clk", "suspend_clk", "bus_clk";
		dr_mode = "otg";
		phys = <&u2phy0_otg>, <&usbdp_phy0 PHY_TYPE_USB3>;
		phy-names = "usb2-phy", "usb3-phy";
		phy_type = "utmi_wide";
		power-domains = <&power RK3588_PD_USB>;
```

**PCIe**：例如 **`pcie2x1l1@fe180000`**：`compatible = "rockchip,rk3588-pcie", "rockchip,rk3568-pcie"`，**`power-domains = <&power RK3588_PD_PCIE>`**，**`interrupt-names = "sys", "pmc", "msg", "legacy", "err"`**（**`pmc`** 与电源管理事件相关）：

```1706:1736:arch/arm64/boot/dts/rockchip/rk3588-base.dtsi
	pcie2x1l1: pcie@fe180000 {
		compatible = "rockchip,rk3588-pcie", "rockchip,rk3568-pcie";
...
		interrupt-names = "sys", "pmc", "msg", "legacy", "err";
...
		power-domains = <&power RK3588_PD_PCIE>;
```

**GMAC**：同文件中有 **`gmac*`** 节点（具体寄存器地址因实例而异），**`power-domains = <&power RK3588_PD_GMAC>`**（见 `01` 中外设示例）；以太网 **WoL** 由 **`stmmac`/`dwmac-rockchip`** 与 **PHY** 驱动配合，需结合 **板级 DTS** 的 **`phy-handle`、`reset-gpios`** 等。

---

## 2. PCIe

### 2.1 机制

- **ASPM（Active State Power Management）**：链路 **L0s/L1** 省电；部分设备 **固件有 bug**，需关闭做 A/B。  
- **D-states**：设备 **D0/D3hot/D3cold**；根复杂体与 **电源时序** 依赖板级设计（`vpcie3v3`、`PERST#`、`CLKREQ#`）。

### 2.2 常见问题

- **NVMe / 扩展卡** resume 慢或超时。  
- **suspend abort**：驱动拒绝进入 D3。

**排查**：`lspci -vv`、内核参数 `pcie_aspm=off`（仅诊断）、`dmesg` 中 **pci pm** 日志。详见 [10](10_故障案例库_RK3588_zh.md) **附录 B**（PCIe/NVMe）。

---

## 3. USB

### 3.1 机制

- **autosuspend**：`power/autosuspend_delay_ms`、`power/control`。  
- **remote wakeup**：主机/设备能力 + DTS **wakeup-source**。

### 3.2 常见问题

- **VBUS / charger** 导致 **无法深睡或秒醒**。  
- **Hub 下设备** 持续中断。

**排查**：拔外设、`usbcore.autosuspend` 参数、禁用 **remote wakeup** 做对比。

---

## 4. GMAC（以太网）

### 4.1 机制

- **PHY 电源**：常独立 regulator。  
- **Wake-on-LAN**：`ethtool` 配置 **magic packet** 等；需 **PHY + 主板** 支持。

### 4.2 常见问题

- **WoL 误配** → 链路抖动唤醒。  
- **suspend 时 PHY 未关** → 待机电流高。

**排查**：`ethtool -s eth0 wol d`、拔网线对比电流。

---

## 5. 与唤醒源、电源域的交叉

- 外设 **IRQ** 可能在 `wakeup_sources` 中显示高 **active_count**。  
- **PD_PCIE** 长期 active 可能表示 **驱动或用户态** 持有引用。

---

## 6. 验证建议

- **无外设 baseline** → **单接 NVMe** → **单接 USB3 盘** 阶梯测试。  
- **suspend 循环** × 每种拓扑。  
- **长时间 idle** 下 **链路状态**（PCIe `LnkSta`）。

---

## 7. 常见坑

- DTS **缺少 PCIe 供电/复位** 导致 PM 状态机错乱。  
- **USB Type-C PD** 芯片 **不断协商** 打中断。  
- **千兆 PHY** 错误 `phy-mode` 导致 **链路 flap**。

---

## 8. 负责人交付物

- 《外设认证列表》：每设备的 **ASPM / suspend** 结论。  
- ODM **USB/PCIe 走线** 与 **唤醒** 设计规范。  
- 已知 **问题固件** 的黑名单与 **内核 workaround** 开关说明。
