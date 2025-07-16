### ❶  整体架构——把 **一次 miss** 变成 **一条 megaflow**
eth.src hardcode 就可以（52:54:00:39:89:ff， eth.type 也是hard code 0x0800）
负责追踪一条 kernel flow 如何生成的，主要包括： 1）产生 匹配特定条件（eth.src && eth.type) 的upcall 的数据包信息（五元组，设备名称，inport 等）；2） 下发 kernel flow ovs_flow_cmd_new
需要与 upcall 一一对应，可以使用下述方法中的 使用 portid 即netlink msgid && 解析出的包头信息（仅下发 flow 包含的部分，仅有 eth.src && eth.type ) ,都对应则匹配，输出该包的信息。 

flow 如下：
recirc_id(0),in_port(19),skb_mark(0/0xffff),eth(src=52:54:00:39:89:ff),eth_type(0x0800),ipv4(frag=no), packets:6199153, bytes:132673711689, used:0.449s, flags:SFPR., actions:userspace(pid=2870210960,slow_path(match))

最开始 flags 为 R. , 后续才更新为 SFPR. 忽略这个字段先。

```
           kernel datapath
packet ──▶ ovs_dp_process_packet()
           ├─ table lookup → *miss*
           └─ ovs_dp_upcall()            (A)

         ▲              │  Netlink  OVS_PACKET_CMD_MISS
         │              ▼
  upcall‑handler thread (vswitchd/​pmd)
           ├─ translate()  → decide ACTIONS, MASK
           ├─ dpif_flow_put() ───────┐
           │   (B) OVS_FLOW_CMD_NEW  │ Netlink socket
           └─ dpif_execute()         │ OVS_PACKET_CMD_EXECUTE (首包直接转)
                                      ▼
                             ovs_flow_cmd_new() → ovs_flow_insert()
                             ovs_packet_cmd_execute()
```

* **(A) `ovs_dp_upcall()`** 只送出 **miss‑key + skb payload**。
* **(B) `ovs_flow_cmd_new()`** 只送回 **KEY / MASK / ACTIONS / FLAGS**；
  没有 skb，也不重复携带五元组里的 *dst MAC / src IP …* 如果被通配。
  之后包再来直接命中内核表。

---

### ❷  如何在 eBPF/BCC 里 **过滤并打印** 两端信息

| 探针                               | 过滤依据                                                                                                                     | 能拿到的字段                                       | 备注               |
| -------------------------------- | ------------------------------------------------------------------------------------------------------------------------ | -------------------------------------------- | ---------------- |
| **kprobe: ovs\_dp\_upcall**      | 从 `struct sw_flow_key` 里比对 `eth.src`, `eth.type==0x0800`                                                                 | 五元组、in\_port、recirc\_id、skb\_mark、tunnel key | skb 还在；可以把首部字段拨开 |
| **kretprobe: ovs\_flow\_insert** | 在返回值 `struct sw_flow *flow` 里，同样查 `key->eth.src`、mask 中哪些位不通配；再检查 `flow->actions` 首个 attr 是否 `OVS_ACTION_ATTR_USERSPACE` | key+mask、flags (`S F P R`)、actions           | 这是 “真正下发” 的确定点   |

---

### ❸  把 **一次 upcall** 和 **随后的 flow\_put** **对到一起** 的几种办法

| 对应方法                                    | 可行性    | 优缺点                                                               |
| --------------------------------------- | ------ | ----------------------------------------------------------------- |
| **① Netlink `portid` 相同**               | ✔      | *同一 upcall‑handler 线程* 发送所有包；一对多（同 handler 同时处理多 miss），需再加 key 比对 |
| **② `ufid`** (OVS ≥ 2.5 + 启用 UFID mode) | ✔ (推荐) | upcall msg 可携带 `OVS_PACKET_ATTR_UFID`，flow\_put 用同一值；唯一且无歧义       |
| **③ 完整 KEY/MASK 比较**                    | ✔      | 与 flow\_put 里的 key/mask 按位比较——最通用，但要自己算掩码                         |
| **④ vswitchd 日志中的 *UKID* 或 cookie**     | ✔      | 开 debug 日志；对生产侵入低，但粒度受日志级别限制                                      |

> 在默认发行版配置里 **方法①+③ 最容易落地**：
>
> * upcall & flow\_put 都通过 **同一个 Netlink socket**（`portid=handler->portid`），
> * 你再用 **eth.src + in\_port + recirc\_id + skb\_mark** 做键即可唯一匹配。

---

### ❹  举例：解析 `OVS_FLOW_CMD_NEW` 时关心的字段

```c
/* 伪码 – kernel side (flow_netlink.c) */
struct nlattr *attrs[OVS_FLOW_ATTR_MAX+1];
if (nla_parse_nested(attrs, OVS_FLOW_ATTR_MAX, nlattr, NULL))
    ...

key  = nla_data(attrs[OVS_FLOW_ATTR_KEY]);      // struct sw_flow_key
mask = nla_data(attrs[OVS_FLOW_ATTR_MASK]);     // 同长掩码
acts = nla_data(attrs[OVS_FLOW_ATTR_ACTIONS]);  // nlattr actions
flags= nla_get_u32(attrs[OVS_FLOW_ATTR_FLAGS]); // CREATE | PAUSED | ...
```

*只要你在 bpftrace/BCC 中把这四块结构解析出来，再做过滤 / 打印，就能知道：*

* **谁触发 miss、什么 key/mask**
* **下发的动作是不是 `OVS_ACTION_ATTR_USERSPACE`**
* **是否带 `OVS_FLOW_F_PAUSED` 导致 `P` flag**

---

### ❺  小结实现步骤

1. **bpftool prog load** 你的 `upcall_kp.o` → attach 到 `ovs_dp_upcall`.
2. 同理挂 `flow_insert_ret.o` 到 `ovs_flow_insert` 的 kretprobe。
3. 在 perf‑reader 里用 `(portid, key.hash)` 做二级索引，把 upcall 与 flow 对齐。
4. 打印 `flags` 的变化即可看到 `R.`→`S F P R.` 的全过程。

这样就能完整观测 “miss → upcall → flow\_put → megaflow 生效”。
