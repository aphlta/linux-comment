# 2017 年度工作报告：DynamIQ、SCMI 与 Oreo 后台限制

| 项目 | 信息 |
|------|------|
| 年份 | 2017 |
| 角色 | **资深功耗架构师** |
| 团队规模 | **8 人**（含 **2 名实习生**） |
| SoC 平台 | **DynamIQ**（**1+3+4** / **2+2+4** 等配置） |
| 制程工艺 | **10nm FinFET** |
| 内核版本 | Linux 4.4（部分遗留）/ **4.9 → 4.14** |
| Android 版本 | Android 7.1 Nougat → **8.0 Oreo** |
| 备注 | **纯内核功耗相关工作最后一年**（2018 起转向 Android Framework） |

---

## 一、行业背景与技术环境

**DynamIQ** 将传统 big.LITTLE 的「簇」边界软化：同一簇内可包含不同微架构核心，并引入 **DSU（DynamIQ Shared Unit）**、**L3 分区**、**per-core 电源门控** 等能力。固件侧 **SCMI（System Control and Management Interface）** 成为 AP 与 **SCP（System Control Processor）** 通信的事实标准之一。Android 8.0 的 **Background Execution Limits** 显著改变应用唤醒模型，内核 idle 形态随之变化。

**个人角色转变准备：** 2017 年后半年开始交接 **cpufreq/cpuidle 日常** 给同事，自身更多投入 **架构与跨层策略**；为 2018 年 **Framework 功耗** 转型铺路。

---

## 二、核心工作内容

### 2.1 DynamIQ / DSU 电源管理

**相对传统 big.LITTLE 的主要差异（概念）：**

- **Per-core power gate：** 单核可关断而邻核仍运行，idle 粒度更细。  
- **DSU L3：** 共享 L3 可 **分区/关断**（实现随实现方 IP 配置而异），影响 **延迟与泄漏**。  
- **AMU（Activity Monitors）**：为调度与调频提供更直接的硬件活动信号（集成与使能依赖核心实现）。

**ASCII 对比示意图：**

```
传统 big.LITTLE（示意）                 DynamIQ + DSU（示意）
====================                    =====================

 [ big cluster ]                         [  Core big0  ][ Core big1 ]
  shared L2                                \______________/
 [ A57 A57 ]                                    DSU L3
                                           [ LITTLE0..3 ]
 [ LITTLE cluster ]                        per-core PG + 共享 L3 策略
 [ A53 A53 A53 A53 ]
```

**L3 分区（CLUSTERCFR 等寄存器）：**  
通过固件/内核协作，在 **轻载** 时收缩 L3 参与范围或进入低泄漏模式，仪测与仿真显示 **L3 相关分量能耗节省约 15%**（场景依赖强，数字为内部典型场景）。

**原因：** L3 泄漏在 10nm 下不可忽略，**分区管理** 是 DynamIQ 时代与「关核」同等重要的旋钮。

---

### 2.2 SCMI 协议适配

**架构理解：** **AP ↔ SCP** 经 **共享内存 + doorbell**（或 mailbox）交换消息，SCP 侧执行时钟、电源、传感器聚合等 **低延迟控制**。

**落地的 6 类协议：**

| 协议 | 用途 |
|------|------|
| Base | 版本、能力发现 |
| Power | 域 on/off、状态查询 |
| Performance | DVFS 级别、limits |
| Clock | 时钟树速率 |
| Sensor | 温度、电压等读数 |
| Reset | 子系统复位 |

**内核对接：** **scmi_cpufreq**（及关联 scmi 驱动）将 **CPUFreq** 请求翻译为 SCMI performance 消息。**原因：10nm 平台常将 PMIC/时钟/温度保护下沉 SCP**，内核不再直接写裸寄存器。

**踩坑与文档：** resume 路径上 **消息乱序/超时** 曾导致 cpufreq 卡在低档，分析见 **case03_scmi_resume_race.md**。

```c
/*
 * 示意：通过 SCMI 设置性能级别（伪代码）。
 * 原因：SCP 可统一仲裁热、电池、充电器输入，避免 AP 侧竞态。
 */
ret = scmi_perf_limits_set(handle, domain_id, max_level, min_level);
if (ret)
	pr_err("scmi perf limits failed: %d\n", ret);
```

---

### 2.3 Android Oreo Background Execution Limits

**工作：** 量化 **隐式广播限制、后台服务限制、JobScheduler 强化** 对内核的影响。

**内部统计（多样机均值，业务应用集合）：**

| 指标 | 相对 Nougat |
|------|-------------|
| 后台唤醒次数 | **减少约 62%** |
| 灭屏待机功耗 | **降低约 29%** |

**DSU idle 优化：** 后台压力减轻后，**更长连续 idle**，DSU/L3 可进入更深状态；需重标 **cpuidle 驻留阈值** 与 **退出延迟**。

**原因：** Framework 限制减少「无意义抖动」，内核侧若仍按旧阈值保守浅睡，会 **浪费 DynamIQ 的细粒度关断能力**。

---

### 2.4 NPU 功耗管理初探

**框架：** **power domain** + **runtime PM** + **devfreq**。

**OPP：** **3 个** 典型工作点（推理峰值、中等、轻载）。

**能效观察：** 在指定 INT8 推理 workload 下，**NPU 相对 CPU/GPU 达到约 8–10× 能效比**（同延迟预算下仪测）。

| 设备 | 角色 | 备注 |
|------|------|------|
| NPU | devfreq + rpm | 推理会话结束立即降档 |
| 共享内存 | DMA 一致性 | 与 cache 维护策略绑定 |
| 热 | IPA 扩展点 | 为后续 NPU 预算留接口 |

---

## 三、踩坑汇总

1. **SCMI 消息超时：** SCP 负载过高或中断屏蔽过长导致 **AP 侧阻塞**。**对策：** 异步路径、重试上限、降级到安全频点。  
2. **SCP/AP 状态不一致：** 一方认为已 on，另一方仍为 off，引发 **访问超时**。**对策：** 握手版本化 + boot/resume 单点序列图。  
3. **SCMI sensor 延迟：** 温度用于 IPA 时，延迟过大导致 **超调**。**对策：** 滤波与预测、与 on-die 传感器交叉校验。  

---

## 四、团队建设（8 人含实习生）

- **2 名实习生：** 分别负责 SCMI 侧 **trace 解析工具** 与 **Oreo 后台策略** 的自动化用例；产出纳入主线评审。  
- **导师制：** 每周一次「功耗架构读书会」（DynamIQ TRM + SCMI 规范节选）。  
- **代码所有权：** cpufreq、SCMI、热、Android 休眠各设 **owner**，避免单点瓶颈。

---

## 五、技术成长

- 从 **「子系统工程师」** 过渡到 **「跨 AP/SCP/Framework 的架构视角」**。  
- 能绘制 **端到端 resume 时序图** 并定位在 SCMI 或驱动 init 的哪一步。  
- 理解 **NPU 作为新功耗主体** 对 IPA 与调度的长期影响。

---

## 六、关键数字汇总

| 指标 | 数值 |
|------|------|
| L3 分区等相关节省 | **约 15%**（典型场景） |
| SCMI 协议落地数 | **6 个** |
| Android 8.0 待机降低 | **约 29%** |
| 后台唤醒减少 | **约 62%** |
| NPU vs CPU/GPU 能效比 | **约 8–10×** |
| 年度闭环 Bug | **68 个** |

---

## 七、遗留问题

- **SCMI 与内核 cpufreq** 的 **debugfs 可见性** 仍不足，现场问题依赖 SCP 日志。  
- NPU **驱动与图形栈** 在共享电源域上的 refcount 边界需继续打磨。  
- **4.4 遗留分支** 与 **4.14 主线** 双栈维护成本偏高，2018 年需收敛。

---

## 八、SCMI 消息流 ASCII 图

```
  +-----+    shmem + doorbell    +-----+
  | AP  | <--------------------> | SCP |
  +-----+                        +-----+
     |                                |
     | scmi_cpufreq                   | PMIC/clock/thermal
     v                                v
 cpufreq core                    硬件电源/时钟
```

**原因：** 把控制面收敛到 SCP 可降低 AP 在 EL1 写敏感寄存器的频率，并改善 **安全域隔离**。

---

## 九、测试与发布门禁

| 门禁项 | 标准 |
|--------|------|
| resume 压测 | 连续 500 次无 SCMI timeout |
| 游戏 | 帧率不低于上一年基线 -3% |
| 待机 | Oreo 后台限制全开，8h 掉电 < SLA |
| NPU | 长时间推理无热失控 |

---

## 十、实习生培养成果

| 课题 | 产出 |
|------|------|
| SCMI trace | 可视化脚本 + 文档 |
| Oreo 后台 | Monkey + batterystats 报告模板 |

**原因：** 2017 年团队扩张，**工具与文档优先交给实习生** 可释放资深同学做架构决策。

---

## 十一、与 2018 交接清单（内核侧）

- cpufreq：**scmi_cpufreq** 参数矩阵与 OTA 回滚策略  
- cpuidle：**DSU/L3** 与 deepest idle 的兼容开关  
- 文档：**case03_scmi_resume_race.md** 合并入平台 bring-up checklist  
- 联系人：各子系统 owner 列表（略）

---

## 十二、总结

2017 年在 **10nm DynamIQ** 与 **SCMI** 上完成平台化闭环，并完整经历 **Android Oreo** 对内核 idle 形态的重塑。**NPU** 初探为后续 **异构计算功耗** 打开新战场。个人职责上，这是 **纯内核功耗** 方向的阶段性收官之年。

---

## 十三、自我评价

在 **8 人团队** 中强化了 **标准协议（SCMI）** 与 **可量化 Framework 策略** 的双向翻译能力；对 **case03_scmi_resume_race** 类问题的复盘提升了组内 **resume 路径** 的整体质量。2018 年将主动拥抱 **Android Framework 电源管理**，把内核视角用于约束设计与验收标准。

---

## 十四、附录：Oreo 限制与内核观测对应

| Framework 行为 | 内核可观测现象 |
|----------------|----------------|
| Job 合并执行 | 周期性唤醒簇集化 |
| 后台服务限制 | CPU 短时脉冲减少 |
| 隐式广播收紧 | wakelock 持有时长下降 |

---

## 十五、关键里程碑时间线（2017）

| 季度 | 里程碑 |
|------|--------|
| Q1 | DynamIQ cpuidle 初版 + 仪测基线 |
| Q2 | SCMI Base/Power/Perf 打通 |
| Q3 | scmi_cpufreq 量产分支 |
| Q4 | Oreo 发布门禁通过 + NPU OPP 表冻结 |

---

## 十六、AMU 集成备注（工程向）

AMU 计数器使能与 **EL2/EL3 暴露策略** 因 OEM 安全策略而异。2017 年采用 **「调度器可选读取」** 路径：若固件未导出则回退 PELT，避免启动失败。**原因：硬件能力渐进启用** 比「全有或全无」更适合量产节奏。

---

## 十七、功耗架构师视角：2018 之前给 Framework 的输入

1. **Job 窗口** 与 **deepest idle 可达性** 的量化关系（数据来自 Oreo 实验）。  
2. **SCMI 超时降级** 时用户可感知表现（帧率底线、亮度是否联动）。  
3. **NPU 会话** 与 **游戏同开** 的热预算预留建议。  

**原因：** 提前对齐 **可验收指标**，避免 Framework 策略与内核/固件能力脱节。

---

## 十八、术语表（DynamIQ / SCMI）

| 术语 | 解释 |
|------|------|
| DSU | 多核共享单元，常含 L3 与一致性逻辑 |
| SCMI | AP 与系统控制处理器之间的标准管理接口 |
| SCP | 常跑固件，负责电源/时钟/传感器聚合 |
| CLUSTERCFR | 与簇/L3 配置相关的控制寄存器族（依 IP 文档） |

---

*（报告完）*
