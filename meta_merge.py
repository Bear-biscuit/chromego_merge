import yaml
import json
import urllib.request
import logging
from ipwhois import IPWhois
from socket import gethostbyname

# 对应国家
country_code_mapping = {
    'AD': '安道尔',
    'AE': '阿联酋',
    'AF': '阿富汗',
    'AG': '安提瓜和巴布达',
    'AI': '安圭拉',
    'AL': '阿尔巴尼亚',
    'AM': '亚美尼亚',
    'AO': '安哥拉',
    'AQ': '南极洲',
    'AR': '阿根廷',
    'AS': '美属萨摩亚',
    'AT': '奥地利',
    'AU': '澳大利亚',
    'AW': '阿鲁巴',
    'AX': '奥兰群岛',
    'AZ': '阿塞拜疆',
    'BA': '波斯尼亚和黑塞哥维那',
    'BB': '巴巴多斯',
    'BD': '孟加拉国',
    'BE': '比利时',
    'BF': '布基纳法索',
    'BG': '保加利亚',
    'BH': '巴林',
    'BI': '布隆迪',
    'BJ': '贝宁',
    'BL': '圣巴泰勒米',
    'BM': '百慕大',
    'BN': '文莱',
    'BO': '玻利维亚',
    'BQ': '荷兰加勒比区',
    'BR': '巴西',
    'BS': '巴哈马',
    'BT': '不丹',
    'BV': '布维岛',
    'BW': '博茨瓦纳',
    'BY': '白俄罗斯',
    'BZ': '伯利兹',
    'CA': '加拿大',
    'CC': '科科斯（基林）群岛',
    'CD': '刚果（金）',
    'CF': '中非共和国',
    'CG': '刚果（布）',
    'CH': '瑞士',
    'CI': '科特迪瓦',
    'CK': '库克群岛',
    'CL': '智利',
    'CM': '喀麦隆',
    'CN': '中国',
    'CO': '哥伦比亚',
    'CR': '哥斯达黎加',
    'CU': '古巴',
    'CV': '佛得角',
    'CW': '库拉索',
    'CX': '圣诞岛',
    'CY': '塞浦路斯',
    'CZ': '捷克共和国',
    'DE': '德国',
    'DJ': '吉布提',
    'DK': '丹麦',
    'DM': '多米尼克',
    'DO': '多米尼加共和国',
    'DZ': '阿尔及利亚',
    'EC': '厄瓜多尔',
    'EE': '爱沙尼亚',
    'EG': '埃及',
    'EH': '西撒哈拉',
    'ER': '厄立特里亚',
    'ES': '西班牙',
    'ET': '埃塞俄比亚',
    'FI': '芬兰',
    'FJ': '斐济',
    'FK': '福克兰群岛',
    'FM': '密克罗尼西亚',
    'FO': '法罗群岛',
    'FR': '法国',
    'GA': '加蓬',
    'GB': '英国',
    'GD': '格林纳达',
    'GE': '格鲁吉亚',
    'GF': '法属圭亚那',
    'GG': '根西岛',
    'GH': '加纳',
    'GI': '直布罗陀',
    'GL': '格陵兰',
    'GM': '冈比亚',
    'GN': '几内亚',
    'GP': '瓜德罗普',
    'GQ': '赤道几内亚',
    'GR': '希腊',
    'GS': '南乔治亚岛和南桑威奇群岛',
    'GT': '危地马拉',
    'GU': '关岛',
    'GW': '几内亚比绍',
    'GY': '圭亚那',
    'HK': '香港',
    'HM': '赫德岛和麦克唐纳群岛',
    'HN': '洪都拉斯',
    'HR': '克罗地亚',
    'HT': '海地',
    'HU': '匈牙利',
    'ID': '印度尼西亚',
    'IE': '爱尔兰',
    'IL': '以色列',
    'IM': '曼岛',
    'IN': '印度',
    'IO': '英属印度洋领地',
    'IQ': '伊拉克',
    'IR': '伊朗',
    'IS': '冰岛',
    'IT': '意大利',
    'JE': '泽西岛',
    'JM': '牙买加',
    'JO': '约旦',
    'JP': '日本',
    'KE': '肯尼亚',
    'KG': '吉尔吉斯斯坦',
    'KH': '柬埔寨',
    'KI': '基里巴斯',
    'KM': '科摩罗',
    'KN': '圣基茨和尼维斯',
    'KP': '朝鲜',
    'KR': '韩国',
    'KW': '科威特',
    'KY': '开曼群岛',
    'KZ': '哈萨克斯坦',
    'LA': '老挝',
    'LB': '黎巴嫩',
    'LC': '圣卢西亚',
    'LI': '列支敦士登',
    'LK': '斯里兰卡',
    'LR': '利比里亚',
    'LS': '莱索托',
    'LT': '立陶宛',
    'LU': '卢森堡',
    'LV': '拉脱维亚',
    'LY': '利比亚',
    'MA': '摩洛哥',
    'MC': '摩纳哥',
    'MD': '摩尔多瓦',
    'ME': '黑山',
    'MF': '法属圣马丁',
    'MG': '马达加斯加',
    'MH': '马绍尔群岛',
    'MK': '北马其顿',
    'ML': '马里',
    'MM': '缅甸',
    'MN': '蒙古',
    'MO': '澳门',
    'MP': '北马里亚纳群岛',
    'MQ': '马提尼克',
    'MR': '毛里塔尼亚',
    'MS': '蒙特塞拉特',
    'MT': '马耳他',
    'MU': '毛里求斯',
    'MV': '马尔代夫',
    'MW': '马拉维',
    'MX': '墨西哥',
    'MY': '马来西亚',
    'MZ': '莫桑比克',
    'NA': '纳米比亚',
    'NC': '新喀里多尼亚',
    'NE': '尼日尔',
    'NF': '诺福克岛',
    'NG': '尼日利亚',
    'NI': '尼加拉瓜',
    'NL': '荷兰',
    'NO': '挪威',
    'NP': '尼泊尔',
    'NR': '瑙鲁',
    'NU': '纽埃',
    'NZ': '新西兰',
    'OM': '阿曼',
    'PA': '巴拿马',
    'PE': '秘鲁',
    'PF': '法属波利尼西亚',
    'PG': '巴布亚新几内亚',
    'PH': '菲律宾',
    'PK': '巴基斯坦',
    'PL': '波兰',
    'PM': '圣皮埃尔和密克隆',
    'PN': '皮特凯恩群岛',
    'PR': '波多黎各',
    'PS': '巴勒斯坦领土',
    'PT': '葡萄牙',
    'PW': '帕劳',
    'PY': '巴拉圭',
    'QA': '卡塔尔',
    'RE': '留尼汪',
    'RO': '罗马尼亚',
    'RS': '塞尔维亚',
    'RU': '俄罗斯',
    'RW': '卢旺达',
    'SA': '沙特阿拉伯',
    'SB': '所罗门群岛',
    'SC': '塞舌尔',
    'SD': '苏丹',
    'SE': '瑞典',
    'SG': '新加坡',
    'SH': '圣赫勒拿',
    'SI': '斯洛文尼亚',
    'SJ': '斯瓦尔巴和扬马延',
    'SK': '斯洛伐克',
    'SL': '塞拉利昂',
    'SM': '圣马力诺',
    'SN': '塞内加尔',
    'SO': '索马里',
    'SR': '苏里南',
    'SS': '南苏丹',
    'ST': '圣多美和普林西比',
    'SV': '萨尔瓦多',
    'SX': '荷属圣马丁',
    'SY': '叙利亚',
    'SZ': '斯威士兰',
    'TC': '特克斯和凯科斯群岛',
    'TD': '乍得',
    'TF': '法属南部领地',
    'TG': '多哥',
    'TH': '泰国',
    'TJ': '塔吉克斯坦',
    'TK': '托克劳',
    'TL': '东帝汶',
    'TM': '土库曼斯坦',
    'TN': '突尼斯',
    'TO': '汤加',
    'TR': '土耳其',
    'TT': '特立尼达和多巴哥',
    'TV': '图瓦卢',
    'TW': '台湾',
    'TZ': '坦桑尼亚',
    'UA': '乌克兰',
    'UG': '乌干达',
    'UM': '美国本土外小岛屿',
    'US': '美国',
    'UY': '乌拉圭',
    'UZ': '乌兹别克斯坦','VA': '梵蒂冈',
    'VC': '圣文森特和格林纳丁斯',
    'VE': '委内瑞拉',
    'VG': '英属维尔京群岛',
    'VI': '美属维尔京群岛',
    'VN': '越南',
    'VU': '瓦努阿图',
    'WF': '瓦利斯和富图纳',
    'WS': '萨摩亚',
    'YE': '也门',
    'YT': '马约特',
    'ZA': '南非',
    'ZM': '赞比亚',
    'ZW': '津巴布韦'
    # 在这里添加更多的映射
}
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
        
        # 生成节点名称
        proxy['name'] = f"{proxy['type']}_{index}{i+1}_{country}"

    merged_proxies.extend(proxies)

#提取clash_old节点-以后删除
def process_clash_old(data, index):
    content = yaml.safe_load(data)
    proxies = content.get('proxies', [])
    for i, proxy in enumerate(proxies):
        ip = proxy.get('server', 'Unknown IP')
        country = get_country_for_ip(ip)

        if proxy.get('type') != 'hysteria2':
            proxy['name'] = f"{proxy['type']}_{index}{i+1}_{country}"
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
        name = f"shadowtls_{index}_{country}"
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
        name = f"{index}_{country}"

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
        ip = proxy.get('server', 'Unknown IP')
        country = get_country_for_ip(ip)
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
        name = f"{index}_{country}"

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
            name = f"reality_{index}_{country}"
            
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
        if group['name'] in ['自动选择', '节点选择']:
            if 'proxies' not in group or not group['proxies']:
                group['proxies'] = [proxy['name'] for proxy in merged_proxies]
            else:
                group['proxies'].extend(proxy['name'] for proxy in merged_proxies)

def update_warp_proxy_groups(config_warp_data, merged_proxies):
    for group in config_warp_data['proxy-groups']:
        if group['name'] in ['自动选择', '手动选择', '负载均衡']:
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


# 更新自动选择和节点选择的proxies的name部分
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
#process_urls('./urls/hysteria2_urls.txt', process_hysteria2)

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

# 更新自动选择和节点选择的proxies的name部分
update_proxy_groups(config_data, merged_proxies)
update_warp_proxy_groups(config_warp_data, merged_proxies)

# 将更新后的数据写入到一个YAML文件中，并指定编码格式为UTF-8
with open('./sub/meta.yaml', 'w', encoding='utf-8') as file:
    yaml.dump(config_data, file, sort_keys=False, allow_unicode=True)

with open('./sub/meta_warp_proxies.yaml', 'w', encoding='utf-8') as file:
    yaml.dump(config_warp_data, file, sort_keys=False, allow_unicode=True)

print("聚合完成")
