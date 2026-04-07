# RK3588：多媒体（GPU / NPU / 编解码）

## 1. 文档目的

说明 **GPU、NPU、视频编解码** 相关 **电源域**、**runtime PM** 与 **系统休眠** 的协同要点，以及 **任务未完成、固件状态机错误** 导致的 **suspend 失败或僵死** 的处理思路。

**原因**：RK3588 多媒体算力强，**软件队列 + 硬件 fence** 若未 flush，极易 **撑住 PD** 或 **abort suspend**；加速器常带 **微码**，PM 失败后需 **复位+重载**。

---

## 1.5 本仓库：GPU / 视频 IP 在 DTS 里如何挂 PD 与 OPP

### GPU（Mali Valhall + `RK3588_PD_GPU`）

```454:469:arch/arm64/boot/dts/rockchip/rk3588-base.dtsi
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

**`rk3588-opp.dtsi`** 末尾 **`&gpu { operating-points-v2 = <&gpu_opp_table>; }`** 绑定 **GPU OPP**（与 **`pm-domains.c` 中 GPU 需 `regulator`** 一起看 `05`）。

### AV1 解码（`RK3588_PD_AV1`）

```1250:1261:arch/arm64/boot/dts/rockchip/rk3588-base.dtsi
	av1d: video-codec@fdc70000 {
		compatible = "rockchip,rk3588-av1-vpu";
		reg = <0x0 0xfdc70000 0x0 0x800>;
		interrupts = <GIC_SPI 108 IRQ_TYPE_LEVEL_HIGH 0>;
		interrupt-names = "vdpu";
		assigned-clocks = <&cru ACLK_AV1>, <&cru PCLK_AV1>;
		assigned-clock-rates = <400000000>, <400000000>;
		clocks = <&cru ACLK_AV1>, <&cru PCLK_AV1>;
		clock-names = "aclk", "hclk";
		power-domains = <&power RK3588_PD_AV1>;
		resets = <&cru SRST_A_AV1>, <&cru SRST_P_AV1>, <&cru SRST_A_AV1_BIU>, <&cru SRST_P_AV1_BIU>;
	};
```

### NPU

**NPU 控制器节点** 在本仓库 **公开 `rk3588*.dtsi` 中可能未展开**（常由厂商模块或 overlay 添加）；**电源树**已在 **`rk3588-base.dtsi`** 的 **`power-controller`** 下定义 **`RK3588_PD_NPU` / `NPUTOP` / `NPU1` / `NPU2`** 嵌套域（见 `01`）。驱动 probe 后通过 **`pm_runtime` + `dev_pm_domain_attach`** 与 **`rk3588_pm_domains[]`** 中 **`npu`/`npu1`/`npu2`/`nputop`** 条目对应。

---

## 2. 电源域回顾（`01`）

| 子系统 | 相关 PD 宏 |
|--------|------------|
| NPU | `RK3588_PD_NPU`, `NPUTOP`, `NPU1`, `NPU2` |
| GPU | `RK3588_PD_GPU` |
| 编解码 | `RK3588_PD_VCODEC`, `RKVDEC*`, `VENC*`, 及 `VDPU`、`AV1` 等 |

**原因**：多子域要求驱动 **成组** 管理 power，避免只关一半。

---

## 3. GPU

- **用户态**：OpenGL/Vulkan 提交 **command buffer**；内核 **DRM scheduler** 与 **GPU IRQ** 完成同步。  
- **runtime PM**：空闲时关时钟/电；**busy** 时拒绝或延迟 suspend。  
- **失败恢复**：上游 Mali **Panthor** 等讨论过 **system/runtime PM 失败后需 reset 并重新加载固件** 才能恢复一致状态——RK3588 负责人应要求 BSP **具备同等 fail-safe**（见 `10` 案例 E）。

**排查**：`dmesg`、DRM `debugfs`（若启用）、用户态是否 **僵尸进程占 GPU**。

---

## 4. NPU

- 推理框架 **runtime** 可能 **长占设备**。  
- **驱动** 需在 suspend 前 **drain queue** 或明确 **-EBUSY**（并记录日志）。  
- **原因**：强制 suspend 可能导致 **固件 hang**，后续 **任何推理失败**。

**建议**：产品定义 **休眠前保存会话** 或 **杀后台推理**（策略由 PM 与架构定）。

---

## 5. 视频编解码（VPU）

- **fence**：缓冲区在 **display / codec** 间传递；未 signal 的 fence 会 **阻塞 idle**。  
- **原因**：播放中途按电源键休眠，若未 **正确 tear down**，下一周期 **resume 花屏或卡死**。

**排查**：关闭播放后等待数秒再 suspend；用 **最小播放器** 复现。

---

## 6. RGA / ISP / 相机路径

- **相机预览** 常 **持续 DMA**；需 **关流** 后再测 suspend。  
- **ISP、VI、VO** 等 PD 与显示、传感器耦合，见 `01`、`06`。

---

## 7. 验证与压测

- **GPU bench** → 立即 suspend → resume。  
- **NPU 推理循环** 同步压测。  
- **4K 解码 + 输出** 场景休眠。  
- 记录 **PD 超时**、**PM 错误** 次数。

---

## 8. 常见坑

- 只处理 **system suspend**，忽略 **runtime PM** 长时间 **active**。  
- **用户态服务** 后台持有 `/dev/dri` 或 NPU 设备不释放。  
- **固件版本** 与 **内核 IOCTL** 不匹配 → PM 回调 **silent fail**。

---

## 9. 负责人交付物

- 多媒体驱动 **suspend 前置条件** 文档（必须 flush 的资源列表）。  
- **GPU/NPU FW** 版本与内核 **兼容性矩阵**。  
- **失败恢复路径**（reset+reload）代码 review **强制项**。
