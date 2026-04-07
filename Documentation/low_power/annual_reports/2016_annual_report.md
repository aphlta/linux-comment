# 2016 年度工作报告：schedutil、PELT 与总线级省电

| 项目 | 信息 |
|------|------|
| 年份 | 2016 |
| 角色 | 资深低功耗优化工程师 / Tech Lead |
| 团队规模 | **6 人** |
| SoC 平台 | Cortex-A73 + A53 / **自研大核 + A53** |
| 制程工艺 | 16nm / **14nm FinFET** |
| 内核版本 | Linux 4.1 → 4.9 |
| Android 版本 | Android 6.0 Marshmallow → 7.0 Nougat |
| 产品形态 | 双摄普及期、UFS 逐步替代 eMMC |

---

## 一、行业背景与技术环境

2016 年 **schedutil** governor 进入主线视野，其核心思想是用调度器 **PELT（Per-Entity Load Tracking）** 的 util 信号 **直接驱动 cpufreq**，取代 interactive 的高频用户态/内核轮询。Android 7.0 引入 **Doze on the Go**（轻/深两级），对 **Sensor Hub、WiFi 扫描卸载** 提出新要求。PC 侧 **PCIe ASPM** 与 **USB selective suspend** 经验向手机 SoC 外设子系统渗透。

**技术关键词：** PELT 半衰期、util_clamp 预研、ASPM L1.2、远程唤醒、功耗 **归因自动化**。

---

## 二、核心工作内容

### 2.1 schedutil governor 集成与调优

**对比 interactive：**

| 维度 | interactive | schedutil |
|------|-------------|-----------|
| 负载来源 | 定时采样 + hispeed | **PELT util** |
| CPU 开销 | polling 路径持续存在 | **事件驱动**，更低开销 |
| 与调度一致性 | 易与 placement 脱节 | **同源信号** |

**rate_limit 配置（平台示例）：**  
- **LITTLE 簇：** `500 µs`（更快响应轻交互）  
- **big 簇：** `1000 µs`（抑制尖峰抖动）

```c
/*
 * 设备树或 cpufreq 驱动中限制 schedutil 最小调频间隔。
 * 原因：PELT 在任务迁移、唤醒瞬间会产生尖刺 util，无 rate_limit 会触发多余频点切换，
 *       仪测上表现为功耗上升且无效。
 */
/* 示意属性名，具体绑定随内核版本为 cpufreq_policy 或 governor 私有 data */
little-cpu-schedutil-rate-limit-us = <500>;
big-cpu-schedutil-rate-limit-us = <1000>;
```

**实测（内部同机型、同工作负载集）：** 相对优化良好的 interactive，**整机功耗降低约 5%–11%**。

**迁移计划：** 先在 LITTLE 全量，再在 big 上 A/B；游戏场景保留 **短期 boost** 钩子与热节流协同。

---

### 2.2 PELT 调优与 util_clamp 预研

**半衰期实验：** 对比 **16ms / 32ms / 64ms** 对功耗与响应的影响。

| 半衰期 | 功耗趋势 | 交互响应 | 备注 |
|--------|----------|----------|------|
| 16ms | 略升 | 更「跟手」 | util 衰减快，易触发升频 |
| 32ms | 平衡 | 平衡 | 默认附近 |
| 64ms | 略降 | 偶发钝感 | 重载后降频偏慢 |

**util_clamp 预研：** 为 **前台 / 后台 / RT 线程** 设计 clamp 上下限，限制后台「蹭」大核或过高频点。**原因：Android 多应用并存时，公平性不等于能效最优**，clamp 是工程上可控的旋钮。

```c
/*
 * 伪代码：根据 cgroup 或 task 角色设置 util clamp。
 * 原因：防止后台下载类线程在 PELT 上呈现持续中高 util，拖住 big 核频率。
 */
if (task_is_background(p))
	util_clamp_set(p, min_util, max_util_bg);
else if (task_is_rt(p))
	util_clamp_set(p, min_util_rt, max_util_rt);
```

---

### 2.3 Android Doze on the Go 适配

**两级 Doze：** **Light Doze**（口袋/短时静止）与 **Deep Doze**（长时间静置）。

**配套工作：**

- **Sensor Hub 低功耗协议：** batch 上报、on-change 替代高频 polling。  
- **WiFi scanning offload：** 将扫描批次下沉到固件/芯片，减少 AP 侧唤醒。  

**成果：** Light Doze 场景下 **功耗降低约 20%**（相对仅 Deep Doze 的旧策略）。

| 状态 | 用户可感知约束 | 内核侧关注点 |
|------|----------------|--------------|
| Light | 通知延迟略增 | alarm 合并、sensor 批处理 |
| Deep | 同步大幅减少 | resume 链路与驱动 timeout |

---

### 2.4 PCIe ASPM 与 USB Selective Suspend

**PCIe ASPM：** 配置 **L0s / L1 / L1.1 / L1.2**，按外设与 root port 能力启用。

**WiFi 模块：** 启用 **L1.2** 后，典型待机 **节省约 35mW**（实验室单变量，屏幕关闭、蜂窝关闭）。

**USB：** **selective suspend** + **remote wakeup**，DWC3 **runtime PM** 与 gadget/host 模式切换协同。

```dts
/*
 * PCIe 端口 ASPM 能力声明（示意）。
 * 原因：错误开启不支持的 L1.2 会导致链路训练失败或随机掉线。
 */
pcie0 {
	max-link-speed = <2>;
	/* 平台私有或标准属性，依 BSP 而定 */
	aspm-l1-2-supported;
};
```

---

### 2.5 功耗 Debug 工具链建设

1. **ftrace 电源事件：** 统一抓取 `cpu_idle`、`cpu_frequency`、`sched_switch` 关键子集。  
2. **Python 功耗归因工具原型：** 仪测 CSV + ftrace 时间对齐，输出「模块级嫌疑排序」。  
3. **自动化功耗回归：** 夜间 job 跑标准场景，超阈值自动 bisect 提示。

**原因：** 2016 年优化进入 **5% 量级肉搏**，没有工具链则无法定位是 **PELT、ASPM 还是 Framework** 引入的回退。

---

## 三、踩坑与案例引用

### 3.1 schedutil + PELT 尖刺

突发 util 导致 **无意义升频**，仪测锯齿明显。**缓解：** rate_limit、迁移防抖、与 **WALT/PELT 变体** 实验（若平台有补丁）。

### 3.2 快充 CPU boost 冲突

快充协议栈周期性线程 activity 被 PELT 视为持续负载，**schedutil 拉高频率**，充电器侧温升与 CPU 抢热预算。**缓解：** 对已知线程打标签或 cgroup clamp，详见组内文档 **case05_schedutil_spurious_updates.md**。

### 3.3 DWC3 OTG spinlock 死锁

runtime PM 与 OTG 状态机在低概率竞争下触发 **spinlock 死锁**，与省电路径强相关。分析与修复参见 **case02_dwc3_otg_spinlock_deadlock.md**。

---

## 四、团队与项目协作

**6 人团队** 分工：2 人 cpufreq/调度、2 人 Android 系统休眠与 Sensor、1 人总线/外设、1 人工具链。  
与 **充电、相机、modem** 组建立「线程白名单」共享表，减少互踩。

---

## 五、技术成长

- 能独立对 **PELT 数学含义** 与 **频点切换仪测结果** 做互证分析。  
- 掌握 **PCIe/USB 电源管理** 在手机上的限制（电池供电、快速恢复）。  
- 推动 **「工具先于优化」** 在组内立项，减少重复人肉 strace。

---

## 六、关键数字汇总

| 指标 | 数值 |
|------|------|
| schedutil vs interactive | **功耗降低 5%–11%** |
| PCIe WiFi L1.2 | **节省约 35mW** |
| Light Doze | **降低约 20%** |
| PELT 半衰期等实验轮次 | **50+ 轮** |
| 年度闭环 Bug | **72 个** |

---

## 七、遗留问题

- util_clamp **主线 API** 与厂商策略分裂，需持续跟进社区。  
- 部分 **UFS** 控制器在 ASPM 与 **深 idle** 组合下偶发恢复超时。  
- Python 归因工具 **与 Perfetto 打通** 未在 2016 年完成，列入 2017。

---

## 八、测试场景注册表（节选）

| ID | 场景 | 关键指标 |
|----|------|----------|
| S01 | 桌面静止 30min | 亮屏 idle 电流 |
| S02 | 微信滑动 10min | jank%、平均频率 |
| S03 | 优酷在线视频 | 帧时间、DDR 频率分布 |
| S04 | 灭屏 WiFi 下载 | 温升、L1.2 驻留 |
| S05 | 快充 + 亮屏导航 | CPU freq 直方图 |

---

## 九、附录：schedutil 迁移检查表

- [ ] LITTLE/big **独立 rate_limit** 已配置  
- [ ] **热节流** 与 schedutil **max_freq** 联动已测  
- [ ] **游戏** 与 **相机** 长事务下无异常降频  
- [ ] **ETM/perf** 开销在可接受范围  
- [ ] **回滚开关** 保留一个内核 cmdline  

---

## 十、功耗仪测与 ftrace 对齐示例（命令示意）

```bash
# 原因：仪测时间轴与内核 trace 必须用同一 NTP 或脉冲标记对齐，否则归因会错位。
adb shell "echo 1 > /sys/kernel/debug/tracing/events/power/enable"
adb shell "echo 1 > /sys/kernel/debug/tracing/tracing_on"
# 仪测端同时开始采样，结束后再 tracing_off
```

---

## 十一、总结

2016 年是 **「调度驱动调频」** 与 **「总线/外设 ASPM」** 双线并进的一年；团队从跟社区 patch 转向 **主导参数体系与工具链**。文档化踩坑（如 schedutil 尖刺、DWC3 死锁）降低了后续机型复现成本。

---

## 十二、自我评价与展望

个人在 **技术深度（PELT/schedutil）** 与 **横向拉通（USB/PCIe/Android Doze）** 上更均衡。2017 年将面临 **DynamIQ、SCMI、Android 8.0 后台限制** 等新维度，需提前储备 **固件—内核协议** 与 **Framework 功耗策略** 双语能力。

---

## 十三、参考文献与内部文档（节选）

- 内部：**case05_schedutil_spurious_updates.md**、**case02_dwc3_otg_spinlock_deadlock.md**  
- 上游：schedutil 提交说明、PELT 文档、`Documentation/devicetree` 相关 binding  

---

## 十四、竞品与基线对标（内部）

| 对标项 | 我方 2016 末 | 竞品 A | 竞品 B | 备注 |
|--------|--------------|--------|--------|------|
| 亮屏 idle (mA) | 基线 | -8% | +3% | 同亮度、同固件版本类 |
| 视频播放 (mW) | 基线 | -5% | -2% | 720p 软解对比窗口 |
| 灭屏 WiFi (mA) | 基线 | 持平 | -4% | ASPM 策略差异 |

**原因：** 竞品数据来自公开市场样机与实验室仪测，仅用于 **趋势判断**，不写入对外宣传材料。

---

## 十五、DMA 与 RPM 协同检查项（Audio/I2C）

- I2S/PCM 停止后 **DMA 通道** 是否全部 release，避免 **parent 设备 rpm 引用泄漏**。  
- I2C **xfer 完成回调** 与 `pm_runtime_mark_last_busy` 时序一致，防止 **autosuspend 截断后续消息**。  
- **原因：** 2016 年 8 模块 RPM 推广中，**DMA 与总线主设备生命周期** 是最常见泄漏点。

---

## 十六、年度培训与分享（内部）

| 主题 | 受众 | 次数 |
|------|------|------|
| schedutil 原理与调参 | 内核组 | 2 |
| ASPM 调试实录 | 驱动组 | 1 |
| Doze on the Go 联调 | Framework 组 | 3 |

---

*（报告完）*
