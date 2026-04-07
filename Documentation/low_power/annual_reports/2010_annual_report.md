# 2010 年度工作报告：SoC 低功耗优化（初级工程师）

| 项目 | 信息 |
|------|------|
| 年份 | 2010 |
| 角色 | 初级低功耗优化工程师 |
| 所属部门 | SoC 原厂 BSP 部门 |
| SoC 平台 | ARM11 / Cortex-A8 单核 |
| 制程工艺 | 65nm → 45nm 过渡 |
| 内核版本 | Linux 2.6.32 — 2.6.35 |
| Android 版本 | Android 2.1 (Éclair) — 2.2 (Froyo) |
| 产品形态 | 功能机向智能机过渡的参考设计、ODM 平板 |

---

## 一、行业背景与技术环境

2010 年前后是智能手机从「能上网」走向「能玩应用」的关键一年：Android 2.2 引入 JIT，
应用生态爆发，但 SoC 侧仍大量沿用功能机时代的时钟与电源思路——**没有统一的 Common Clock
Framework（CCF）**，各 IP 时钟门控散落在平台代码里，suspend 路径与 DVFS 路径经常「各写各的」。

**行业侧要点：**

- **工艺**：65nm 仍占主流出货，45nm 开始用于旗舰参考设计；漏电与动态功耗比例开始倒挂，idle 优化重要性上升。
- **软件栈**：Linux 2.6.3x 仍是手机 BSP 标配；Android 2.x 对 wakelock、early suspend 等机制依赖度高，与内核标准 suspend 并存，调试复杂。
- **竞争焦点**：待机时间、发热、「能不能睡下去」成为客户验收硬指标；底电流（suspend 电流）往往写在合同附件里。

```
2010 年典型手机功耗关注点（示意）

  用户感知                    BSP 侧对应工作
  ─────────────────────────────────────────────
  待机掉电快          →    时钟泄漏、IO 漏电、USB PHY 未关
  游戏发热            →    OPP 表、PMIC 效率、散热模型（本年次要）
  睡下去醒不来        →    resume 顺序、DMA 未完成、LCD 复位时序
```

---

## 二、核心工作内容

### 2.1 私有时钟框架与时钟树梳理（无 CCF 时代）

**背景：** 平台使用自研 `clk_enable`/`clk_disable` 封装，无全局拓扑视图。部分外设驱动在
probe 时永久 `clk_enable`，导致 SoC idle 时仍有「幽灵时钟」在跑。

**本年度完成：**

1. **绘制 SoC 时钟树**（PLL → 分频 → 门控 → 外设），输出内部文档与 Excel 依赖表。
2. **审计 22 个已合入驱动的时钟使用**，归类为：必须常开、可 runtime 关断、错误常开。
3. **修复 12 处时钟泄漏**：典型模式为 `probe` 成功路径 `enable` 了时钟，但 `remove`/错误路径未对称 `disable`，或 suspend 中忘记关断子时钟。

**伪代码示例（当年私有框架风格，说明「对称」原则）：**

```c
/*
 * 原因：probe 多路径返回时若未统一 clk_disable，会在用户无感知情况下
 * 抬高 chip idle 功耗；2010 年尚无 devm_clk 惯例，全靠人工审计。
 */
static int foo_probe(struct platform_device *pdev)
{
	struct clk *clk = clk_get(&pdev->dev, "bus");
	int ret;

	if (IS_ERR(clk))
		return PTR_ERR(clk);

	ret = clk_enable(clk);
	if (ret)
		goto err_clk_put;

	ret = register_irq();
	if (ret)
		goto err_clk_disable;

	return 0;

err_clk_disable:
	clk_disable(clk);
err_clk_put:
	clk_put(clk);
	return ret;
}
```

**效果量化：**

| 指标 | 优化前 | 优化后 | 说明 |
|------|--------|--------|------|
| SoC 侧 idle 额外功耗（估算） | 基准 | **-15 mW** | 12 处泄漏修复叠加效应 |
| 时钟树文档页数 | 0 | 1 本内部 spec | 便于后续 DVFS/suspend 联调 |

---

### 2.2 DVFS 基础实现：OPP、cpufreq、PMIC I2C 调压

**背景：** 客户要求支持多档频率与电压，以平衡 Antutu 跑分与续航；PMIC 通过 I2C 改 BUCK 输出。

**交付物：**

1. **5 个 OPP（Operating Performance Point）**：从启动安全档到最高性能档，每档对应 `(freq_kHz, uV)`。
2. **cpufreq 平台驱动**：`target`/`setpolicy` 与硬件分频器、电压表联动。
3. **ondemand governor 调优**：采样率、`up_threshold`/`down_threshold`、ignore_nice 等与 UI 卡顿/续航折中。

**OPP 表示例（示意）：**

| OPP | 频率 (MHz) | 电压 (mV) | 典型场景 |
|-----|------------|-----------|----------|
| 0 | 200 | 900 | 深度轻载、音频后台 |
| 1 | 400 | 950 | 一般交互 |
| 2 | 600 | 1000 | 列表滑动 |
| 3 | 800 | 1100 | 浏览器/地图 |
| 4 | 1000 | 1200 | 基准测试 / 峰值 |

**调压路径示意：**

```
cpufreq_target()
    → 计算目标 OPP
    → 若升频：先升压再升频（避免 undervolt）
    → 若降频：先降频再降压
    → i2c_smbus_write_byte_data(pm_i2c_client, REG_VARM, code)
```

**踩坑记录（与本节强相关）：** 见第四节「调压竞态、I2C 延迟」。

---

### 2.3 System Suspend / Resume 全路径调通

**背景：** 参考设计底电流不达标（客户目标 < 3mA），需从「能 suspend」升级到「可量产级底电流」。

**工作拆分：**

1. **编写并验证 18 个驱动的 `.suspend`/`.resume`（或 early suspend 钩子）**，覆盖 LCD、触摸、传感器、SD/MMC、USB、音频 codec 等。
2. **底电流分解**：用切断法拉电容、分段跳线、示波器看电源轨等方式，定位 **SDRAM 自刷新配置、USB PHY 挂起、GPIO 浮空/上拉漏电** 等问题。
3. **与 Android early suspend / late resume 协同**：避免与内核 `suspend_devices_and_enter` 双路径打架。

**电流优化结果：**

| 阶段 | 底电流 (mA) | 主要动作 |
|------|-------------|----------|
| 初版 SDK | 12.0 | 大量驱动未 sleep，USB 未 phy_suspend |
| SDRAM CKE/自刷新修正 | 6.5 | 与 memory controller 同事联调 |
| USB PHY + IO 漏电治理 | 4.1 | PHY 寄存器序列 + pad 配置 |
| 全驱动 suspend 闭环 | **2.8** | 18 个回调 + 漏电流抽检 |

**Suspend 软件栈 ASCII 示意：**

```
用户按电源键 / Alarm 到期
        │
        ▼
Android: wake_lock 释放路径
        │
        ▼
kernel: pm_suspend(PM_SUSPEND_MEM)
        │
        ├── devices suspend (18 drivers)
        ├── syscore suspend
        ├── CPU 最后 WFI / 平台 sleep 汇编
        │
        ▼
硬件: DRAM self-refresh, 大部分 rail 由 PMIC 策略下电
```

---

### 2.4 功耗测量环境与自动化脚本

**背景：** 研发与客户的「mA 口径」必须一致，否则争议不断。

**搭建内容：**

1. **硬件**：主电源轨串联精密采样电阻（如 0.1Ω）+ 台式万用表电压档测电阻压降，换算电流；关键轨另接电流探头抽查。
2. **软件**：shell 脚本循环 `echo mem > /sys/power/state` 与 rtc/alarm 唤醒，统计成功率与平均底电流读数窗口。

**脚本片段（概念示例）：**

```bash
#!/bin/sh
# 原因：suspend/resume 偶发失败需大量循环暴露；人工按键不可复现统计。
LOG=./suspend_cycle.log
for i in $(seq 1 500); do
	echo "=== cycle $i $(date) ===" >> "$LOG"
	echo mem > /sys/power/state || echo "FAIL $i" >> "$LOG"
	sleep 2
done
```

---

## 三、技术成长与能力沉淀

| 维度 | 年初 | 年末 |
|------|------|------|
| 内核电源管理概念 | 零散 | 建立 cpufreq / suspend / 时钟 整体图景 |
| 调试手段 |  printk 为主 | 电流分解 + 循环压测 + 寄存器对照表 |
| 跨部门协作 | 较少 | 与 PMIC FAE、DRAM AE、LCD 厂联合攻关 |
| 文档输出 | 无体系 | 时钟树 + suspend checklist 初版 |

**本年度最大认知升级：** 低功耗不是「调一个 governor」，而是 **时钟、电压、设备电源状态、测量方法** 四条线的闭环。

---

## 四、踩坑与根因摘要

| 现象 | 根因（简述） | 教训 |
|------|----------------|------|
| 随机死机/花屏 | **调压竞态**：降频与降压顺序或锁外并发 | 统一在 cpufreq 驱动内序列化，PMIC 写前关抢占 |
| UI 卡顿 spikes | **I2C 延迟**：PMIC 写慢，ondemand 采样内完不成 | 预升降压、减少跨档次数；与硬件商量 faster mode |
| resume 黑屏 | **LCD 复位/resume 时序** 与 DSI 时钟恢复顺序 | 固化 resume 顺序文档；加延时与 retry（临时） |
| 文件损坏/ DMA 错 | **DMA 传输未完成就 suspend** | suspend_noirq 阶段停 DMA；驱动增加 `pm_runtime` 前置习惯（次年延续） |

---

## 五、关键数字（年度 KPI 对齐）

| 指标 | 数值 |
|------|------|
| 维护/新编写涉及功耗相关驱动数 | **22** |
| 关闭的功耗/休眠相关 Bug | **35** |
| 底电流（参考设计典型配置） | **12 mA → 2.8 mA** |
| 时钟泄漏修复点数 | **12** |
| OPP 档位数 | **5** |
| 实现 suspend/resume 回调的驱动数 | **18** |
| SoC idle 功耗（时钟泄漏修复） | **约 -15 mW** |

---

## 六、遗留问题与下一年展望

1. **DVFS 与 suspend 的统一策略**：部分驱动仍假设「频率不变」，唤醒后需全路径校验。
2. **I2C PMIC 的带宽与实时性**：随着 OPP 增多，需考虑独立 SPMI 或硬件 sequencer（当年方案未定型）。
3. **Android wakelock 与内核 PM 的统计可视化**：仍依赖手工 log，尚未建立统一功耗 dashboard。
4. **双核平台已在路线图**：2011 年需提前学习 CPU hotplug、SMP 下的 idle 竞争。

---

## 附录 A：术语与缩写（便于新人阅读）

| 缩写 | 含义 |
|------|------|
| OPP | Operating Performance Point，频率-电压对 |
| DVFS | Dynamic Voltage and Frequency Scaling |
| BSP | Board Support Package |
| PHY | 物理层接口电路（如 USB PHY） |
| PMIC | Power Management IC |
| WFI | Wait For Interrupt，ARM idle 指令 |

## 附录 B：2010 年个人技术时间线（摘要）

```
Q1   时钟树文档 v0.1 + 首批 4 个泄漏修复
Q2   cpufreq + 5 OPP 合入参考内核；ondemand 首轮参数扫描
Q3   suspend 主路径打通；底电流从 12mA 拉到 ~5mA 区间
Q4   USB/SDRAM/IO 漏电专项；底电流达标 2.8mA；测量脚本交付测试部
```

---

*文档说明：本年度报告中的寄存器名、OPP 数值、脚本路径均为典型化示例，用于还原当时技术语境；与具体客户项目 NDA 细节已脱敏。*
