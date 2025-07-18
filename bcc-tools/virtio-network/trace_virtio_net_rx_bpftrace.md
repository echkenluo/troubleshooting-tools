

## 1. 需求：实现追踪 virtnet_poll 这个 probe 点的程序，支持通过队列与接口名称过滤（直接 hardcode 过滤条件即可）。

函数签名如下： 
static int virtnet_poll(struct napi_struct *napi, int budget)
{
	struct receive_queue *rq =
		container_of(napi, struct receive_queue, napi);
	struct virtnet_info *vi = rq->vq->vdev->priv;


## 2. 实现相关
从 napi_struct 获取其所子啊的 rq 数据结构的方法参考  container_of 的实现，计算偏移 即， napi 指针的位置减去 其相对所在的 receive_queue 开始位置的 offset，得到的指针，转换成 receive_queue 指针，就是指向对应 rq 对象。

1. cong napi 中拿 net_device ，然后拿 devname，这样应该拿到的事 vm 中看到的虚拟网卡名称，即我们的网卡名过滤条件；
2. 从 rq 获取 rx queue index （即第二个过滤条件）。


实现参考以下代码中的方式（有 rq 就可以直接获取 rx queue index）： 
static void virtnet_poll_cleantx(struct receive_queue *rq)
{
	struct virtnet_info *vi = rq->vq->vdev->priv;
	unsigned int index = vq2rxq(rq->vq);


static int vq2rxq(struct virtqueue *vq)
{
	return vq->index / 2;
}


## 注意事项

1. bpftrace 程序中需要包含使用的数据结构的头文件，具体可以查看 kernel-source/kernel 
2. 如果不方便/无法添加头文件，则需要在 代码显式定义所需的数据结构，并且一定要遵循：在结构体中代码中使用到的字段以及其以前的字段必须完整包含，其后的字段可以 padding 


    


## 3. 实现结果

已实现的 bpftrace 脚本文件：
- `trace_virtnet_poll.bt` - 基础工作版本，按队列过滤
- `trace_virtio_net_rx_complete.bt` - 完整版本，支持接口名和队列过滤

### 关键实现要点

1. **container_of 实现**：
   ```bpftrace
   $rq_ptr = $napi_ptr - 8;  // napi 在 receive_queue 中的偏移量为 8
   ```

2. **队列索引计算**：
   ```bpftrace
   $vq_index = *(uint32*)($vq_ptr + 40);  // vq->index 偏移量为 40
   $rx_queue = $vq_index / 2;             // vq2rxq 实现
   ```

3. **结构体偏移量**（基于 openEuler 4.19.90 内核）：
   - napi 在 receive_queue 中偏移：8 字节
   - vq 在 receive_queue 中偏移：0 字节  
   - index 在 virtqueue 中偏移：40 字节
   - dev 在 napi_struct 中偏移：56 字节

### 测试结果

在测试环境 root@192.168.29.151 上成功运行，能够：
- 正确追踪 virtnet_poll 函数调用
- 按队列索引过滤（hardcode 队列 0）
- 显示函数入口和出口
- 统计处理的数据包数量和效率

示例输出：
```
243341026825885: ENTRY q0 budget=64 vq_idx=0
243341026950107: EXIT processed=1
```

## 测试
在 root@192.168.29.151:/root/ 下进行测试，可以免密 ssh 登陆， scp 等。

测试命令：
```bash
sudo bpftrace /root/trace_virtnet_poll.bt
``` 