import yaml
import json
import urllib.request
import logging
from ipwhois import IPWhois
from socket import gethostbyname
from country_mappings import country_code_mapping
from flag_emojis import country_emoji_mapping
# 全局字典，用于记录每个国家出现的次数
country_count = {}

# ip归属
def get_country_for_ip(ip):
    try:
        # 尝试解析输入，判断是 IP 地址还是域名
        ip_address = gethostbyname(ip)
    except Exception:
        # 如果解析失败，说明输入可能是 IP 地址
        ip_address = ip
    # 使用 IP 地址调用 IPWhois 进行查询
    obj = IPWhois(ip_address)
    results = obj.lookup_rdap()

    # 提取国家信息
    country = results.get('asn_country_code', 'Unknown')

    # 使用映射字典获取中文国家名，如果没有对应的映射，则返回原始国家码
    country = country_code_mapping.get(country, country)
 
    return country

# ip归属emoji
def get_emoji_for_ip(ip):
    try:
        # 尝试解析输入，判断是 IP 地址还是域名
        ip_address = gethostbyname(ip)
    except Exception:
        # 如果解析失败，说明输入可能是 IP 地址
        ip_address = ip
    # 使用 IP 地址调用 IPWhois 进行查询
    obj = IPWhois(ip_address)
    results = obj.lookup_rdap()

    # 提取国家信息
    country_emoji = results.get('asn_country_code', 'Unknown')

    # 使用映射字典获取emoji，如果没有对应的映射，则返回原始国家码
    country_emoji = country_emoji_mapping.get(country_emoji, None)
 
    return country_emoji
# 提取节点
def process_urls(url_file, processor):
    try:
        with open(url_file, 'r') as file:
            urls = file.read().splitlines()

        for index, url in enumerate(urls):
            try:
                response = urllib.request.urlopen(url)
                data = response.read().decode('utf-8')
                processor(data, index)
            except Exception as e:
                logging.error(f"Error processing URL {url}: {e}")
    except Exception as e:
        logging.error(f"Error reading file {url_file}: {e}")
#提取clash节点
def process_clash(data, index):
    content = yaml.safe_load(data)
    proxies = content.get('proxies', [])
    
    for i, proxy in enumerate(proxies):
        ip = proxy.get('server', 'Unknown IP')
        country = get_country_for_ip(ip)
        country_emoji = get_emoji_for_ip(ip)
        
        # 生成节点名称，如果之前出现过相同类型和国家，就在国家后面加上出现的次数
        key = f"{proxy['type']} | {country_emoji}{country}"
        count = country_count.get(key, 0)

        # 生成节点名称
        proxy['name'] = f"{key}{count}"

        # 更新全局字典中该类型和国家出现的次数
        country_count[key] = count + 1

    merged_proxies.extend(proxies)

#提取clash_old节点-以后删除
def process_clash_old(data, index):
    content = yaml.safe_load(data)
    proxies = content.get('proxies', [])
    for i, proxy in enumerate(proxies):
        ip = proxy.get('server', 'Unknown IP')
        country = get_country_for_ip(ip)
        country_emoji = get_emoji_for_ip(ip)

        # 生成节点名称，如果之前出现过相同类型和国家，就在国家后面加上出现的次数
        key = f"{proxy['type']} | {country_emoji}{country}"
        count = country_count.get(key, 0)

        if proxy.get('type') != 'hysteria2':
            proxy['name'] = f"{key}{count}"
            merged_proxies.append(proxy)


# 处理sb，待办
def process_sb(data, index):
    try:
        json_data = json.loads(data)
        # 处理 shadowtls 数据

        # 提取所需字段
        method = json_data["outbounds"][0]["method"]
        password = json_data["outbounds"][0]["password"]
        server = json_data["outbounds"][1]["server"]
        server_port = json_data["outbounds"][1]["server_port"]
        server_name = json_data["outbounds"][1]["tls"]["server_name"]
        shadowtls_password = json_data["outbounds"][1]["password"]
        version = json_data["outbounds"][1]["version"]
        # 获取 IP 归属地
        country = get_country_for_ip(server)
        country_emoji = get_emoji_for_ip(server)
        name = f"shadowtls_{index}_{country_emoji}{country}"
        # 创建当前网址的proxy字典
        proxy = {
            "name": name,
            "type": "ss",
            "server": server,
            "port": server_port,
            "cipher": method,
            "password": password,
            "plugin": "shadow-tls",
            "client-fingerprint": "chrome",
            "plugin-opts": {
                "host": server_name,
                "password": shadowtls_password,
                "version": int(version)
            }
        }

        # 将当前proxy字典添加到所有proxies列表中
        merged_proxies.append(proxy)

    except Exception as e:
        logging.error(f"Error processing shadowtls data for index {index}: {e}")

def process_hysteria(data, index):
    try:
        json_data = json.loads(data)
        # 处理 hysteria 数据
        # 提取所需字段
        auth = json_data["auth_str"]
        server_ports = json_data["server"]
        server_ports_slt = server_ports.split(":")
        server = server_ports_slt[0]
        ports = server_ports_slt[1]
        ports_slt = ports.split(",")
        server_port = int(ports_slt[0])
        if len(ports_slt) > 1:
            mport = ports_slt[1]
        else:
            mport = server_port
        fast_open = json_data["fast_open"]
        insecure = json_data["insecure"]
        server_name = json_data["server_name"]
        alpn = json_data["alpn"]
        protocol = json_data["protocol"]
        
        # 获取 IP 归属地
        country = get_country_for_ip(server)
        country_emoji = get_emoji_for_ip(server)

        # 生成节点名称，如果之前出现过相同类型和国家，就在国家后面加上出现的次数
        key = f"hysteria | {country_emoji}{country}"
        count = country_count.get(key, 0)

        name = f"{key}{count}"

        # 更新全局字典中该类型和国家出现的次数
        country_count[key] = count + 1

        # 创建当前网址的proxy字典
        proxy = {
            "name": name,
            "type": "hysteria",
            "server": server,
            "port": server_port,
            "ports": mport,
            "auth_str": auth,
            "up": 80,
            "down": 100,
            "fast-open": fast_open,
            "protocol": protocol,
            "sni": server_name,
            "skip-cert-verify": insecure,
            "alpn": [alpn]
        }

        # 将当前proxy字典添加到所有proxies列表中
        merged_proxies.append(proxy)

    except Exception as e:
        logging.error(f"Error processing hysteria data for index {index}: {e}")
# 处理hysteria2
def process_hysteria2(data, index):
    try:
        json_data = json.loads(data)
        # 处理 hysteria2 数据
        # 提取所需字段
        auth = json_data["auth"]
        server_ports = json_data["server"]
        server_ports_slt = server_ports.split(":")
        server = server_ports_slt[0]
        ports = server_ports_slt[1]
        ports_slt = ports.split(",")
        server_port = int(ports_slt[0])
        fast_open = json_data["fastOpen"]
        insecure = json_data["tls"]["insecure"]
        sni = json_data["tls"]["sni"]
        # 获取 IP 归属地
        country = get_country_for_ip(server)
        country_emoji = get_emoji_for_ip(server)

        # 生成节点名称，如果之前出现过相同类型和国家，就在国家后面加上出现的次数
        key = f"hysteria2 | {country_emoji}{country}"
        count = country_count.get(key, 0)

        name = f"{key}{count}"

        # 更新全局字典中该类型和国家出现的次数
        country_count[key] = count + 1

        # 创建当前网址的proxy字典
        proxy = {
            "name": name,
            "type": "hysteria2",
            "server": server,
            "port": server_port,
            "password": auth,
            "fast-open": fast_open,
            "sni": sni,
            "skip-cert-verify": insecure
        }

        # 将当前proxy字典添加到所有proxies列表中
        merged_proxies.append(proxy)

    except Exception as e:
        logging.error(f"Error processing hysteria2 data for index {index}: {e}")

#处理xray
def process_xray(data, index):
    try:
        json_data = json.loads(data)
        # 处理 xray 数据
        protocol = json_data["outbounds"][0]["protocol"]
        #vless操作
        if protocol == "vless":
        # 提取所需字段
            server = json_data["outbounds"][0]["settings"]["vnext"][0]["address"]
            port = json_data["outbounds"][0]["settings"]["vnext"][0]["port"]
            uuid = json_data["outbounds"][0]["settings"]["vnext"][0]["users"][0]["id"]
            istls = True
            flow = json_data["outbounds"][0]["settings"]["vnext"][0]["users"][0]["flow"]
            # 传输方式
            network = json_data["outbounds"][0]["streamSettings"]["network"]
            publicKey = json_data["outbounds"][0]["streamSettings"]["realitySettings"]["publicKey"]
            shortId = json_data["outbounds"][0]["streamSettings"]["realitySettings"]["shortId"]
            serverName = json_data["outbounds"][0]["streamSettings"]["realitySettings"]["serverName"]
            fingerprint = json_data["outbounds"][0]["streamSettings"]["realitySettings"]["fingerprint"]
            # udp转发
            isudp = True
            # 获取 IP 归属地
            country = get_country_for_ip(server)
            country_emoji = get_emoji_for_ip(server)
            name = f"reality_{index}_{country_emoji}{country}"
            
            # 根据network判断tcp
            if network == "tcp":
                proxy = {
                    "name": name,
                    "type": protocol,
                    "server": server,
                    "port": port,
                    "uuid": uuid,
                    "network": network,
                    "tls": istls,
                    "udp": isudp,
                    "flow": flow,
                    "client-fingerprint": fingerprint,
                    "servername": serverName,                
                    "reality-opts":{
                        "public-key": publicKey,
                        "short-id": shortId}
                }
                
            # 根据network判断grpc
            elif network == "grpc":
                serviceName = json_data["outbounds"][0]["streamSettings"]["grpcSettings"]["serviceName"]
                
                # 创建当前网址的proxy字典
                proxy = {
                    "name": name,
                    "type": protocol,
                    "server": server,
                    "port": port,
                    "uuid": uuid,
                    "network": network,
                    "tls": istls,
                    "udp": isudp,
                    "flow": flow,
                    "client-fingerprint": fingerprint,
                    "servername": serverName,
                    "grpc-opts":{
                        "grpc-service-name": serviceName
                    },
                    "reality-opts":{
                        "public-key": publicKey,
                        "short-id": shortId}
                }

        # 将当前proxy字典添加到所有proxies列表中
        merged_proxies.append(proxy)
    except Exception as e:
        logging.error(f"Error processing xray data for index {index}: {e}")

def update_proxy_groups(config_data, merged_proxies):
    for group in config_data['proxy-groups']:
        if group['name'] in ['自动选择', '🚀 节点选择']:
            if 'proxies' not in group or not group['proxies']:
                group['proxies'] = [proxy['name'] for proxy in merged_proxies]
            else:
                group['proxies'].extend(proxy['name'] for proxy in merged_proxies)

def update_warp_proxy_groups(config_warp_data, merged_proxies):
    for group in config_warp_data['proxy-groups']:
        if group['name'] in ['自动选择', 'chromego']:
            if 'proxies' not in group or not group['proxies']:
                group['proxies'] = [proxy['name'] for proxy in merged_proxies]
            else:
                group['proxies'].extend(proxy['name'] for proxy in merged_proxies)

# 包含hysteria2
merged_proxies = []

# 处理 clash URLs
process_urls('./urls/clash_urls.txt', process_clash)

# 处理 shadowtls URLs
process_urls('./urls/sb_urls.txt', process_sb)

# 处理 hysteria URLs
process_urls('./urls/hysteria_urls.txt', process_hysteria)

# 处理 hysteria2 URLs
process_urls('./urls/hysteria2_urls.txt', process_hysteria2)

# 处理 xray URLs
process_urls('./urls/xray_urls.txt', process_xray)

# 读取普通的配置文件内容
with open('./templates/clash_template.yaml', 'r', encoding='utf-8') as file:
    config_data = yaml.safe_load(file)

# 读取warp配置文件内容
with open('./templates/clash_warp_template.yaml', 'r', encoding='utf-8') as file:
    config_warp_data = yaml.safe_load(file)

# 添加合并后的代理到proxies部分
if 'proxies' not in config_data or not config_data['proxies']:
    config_data['proxies'] = merged_proxies
else:
    config_data['proxies'].extend(merged_proxies)

if 'proxies' not in config_warp_data or not config_warp_data['proxies']:
    config_warp_data['proxies'] = merged_proxies
else:
    config_warp_data['proxies'].extend(merged_proxies)


# 更新♻️ 自动选择和节点选择的proxies的name部分
update_proxy_groups(config_data, merged_proxies)
update_warp_proxy_groups(config_warp_data, merged_proxies)

# 将更新后的数据写入到一个YAML文件中，并指定编码格式为UTF-8
with open('./sub/meta_new.yaml', 'w', encoding='utf-8') as file:
    yaml.dump(config_data, file, sort_keys=False, allow_unicode=True)

with open('./sub/meta_warp_new.yaml', 'w', encoding='utf-8') as file:
    yaml.dump(config_warp_data, file, sort_keys=False, allow_unicode=True)

print("聚合完成")




# 不包含hysteria2-以后删除
merged_proxies = []

# 处理 clash URLs
process_urls('./urls/clash_urls.txt', process_clash_old)

# 处理 shadowtls URLs
process_urls('./urls/sb_urls.txt', process_sb)

# 处理 hysteria URLs
process_urls('./urls/hysteria_urls.txt', process_hysteria)

# 处理 hysteria2 URLs
process_urls('./urls/hysteria2_urls.txt', process_hysteria2)

# 处理 xray URLs
process_urls('./urls/xray_urls.txt', process_xray)

# 读取普通的配置文件内容
with open('./templates/clash_template.yaml', 'r', encoding='utf-8') as file:
    config_data = yaml.safe_load(file)

# 读取warp配置文件内容
with open('./templates/clash_warp_template.yaml', 'r', encoding='utf-8') as file:
    config_warp_data = yaml.safe_load(file)

# 添加合并后的代理到proxies部分
# 添加合并后的代理到proxies部分
if 'proxies' not in config_data or not config_data['proxies']:
    config_data['proxies'] = merged_proxies
else:
    config_data['proxies'].extend(merged_proxies)

if 'proxies' not in config_warp_data or not config_warp_data['proxies']:
    config_warp_data['proxies'] = merged_proxies
else:
    config_warp_data['proxies'].extend(merged_proxies)

# 更新♻️ 自动选择和节点选择的proxies的name部分
update_proxy_groups(config_data, merged_proxies)
update_warp_proxy_groups(config_warp_data, merged_proxies)

# 将更新后的数据写入到一个YAML文件中，并指定编码格式为UTF-8
with open('./sub/meta.yaml', 'w', encoding='utf-8') as file:
    yaml.dump(config_data, file, sort_keys=False, allow_unicode=True)

with open('./sub/meta_warp_proxies.yaml', 'w', encoding='utf-8') as file:
    yaml.dump(config_warp_data, file, sort_keys=False, allow_unicode=True)

print("聚合完成")
