import xml.etree.ElementTree as ET
import xml.dom.minidom
import json
import sys
import os

def convert_ppx_to_pbprofile(input_ppx, output_pbprofile):
    try:
        tree = ET.parse(input_ppx)
        root = tree.getroot()
    except Exception as e:
        print(f"Ошибка при чтении {input_ppx}: {e}")
        return

    proxy_configs = []
    proxy_id_map = {}
    
    proxy_list_node = root.find('ProxyList')
    if proxy_list_node is not None:
        for i, proxy_node in enumerate(proxy_list_node.findall('Proxy')):
            pid = proxy_node.get('id')
            pb_id = i + 1
            proxy_id_map[pid] = pb_id
            
            ptype = proxy_node.get('type', 'SOCKS5')
            address_node = proxy_node.find('Address')
            host = address_node.text.strip() if address_node is not None and address_node.text else ""
            
            port_node = proxy_node.find('Port')
            port = port_node.text.strip() if port_node is not None and port_node.text else ""
            
            username = ""
            password = ""
            auth_node = proxy_node.find('Authentication')
            if auth_node is not None and auth_node.get('enabled') == 'true':
                un_node = auth_node.find('Username')
                pw_node = auth_node.find('Password')
                if un_node is not None and un_node.text:
                    username = un_node.text.strip()
                if pw_node is not None and pw_node.text:
                    password = pw_node.text.strip()
            
            proxy_configs.append({
                "Id": pb_id,
                "Type": ptype,
                "Host": host,
                "Port": port,
                "Username": username,
                "Password": password
            })

    proxy_rules = []
    rule_list_node = root.find('RuleList')
    if rule_list_node is not None:
        for rule_node in rule_list_node.findall('Rule'):
            enabled = rule_node.get('enabled', 'true').lower() == 'true'
            
            action_node = rule_node.find('Action')
            action_type = action_node.get('type', 'Direct').upper()
            
            pb_action = action_type
            proxy_config_id = 0
            
            if action_type == 'PROXY':
                ppx_pid = action_node.text.strip() if action_node.text else ""
                if ppx_pid in proxy_id_map:
                    proxy_config_id = proxy_id_map[ppx_pid]
            
            def clean_text(node):
                if node is None or not node.text:
                    return "*"
                text = node.text
                return "".join([line.strip() for line in text.splitlines()])

            process_name = clean_text(rule_node.find('Applications'))
            target_hosts = clean_text(rule_node.find('Targets'))
            target_ports = clean_text(rule_node.find('Ports'))
            
            proxy_rules.append({
                "ProcessName": process_name,
                "TargetHosts": target_hosts,
                "TargetPorts": target_ports,
                "Protocol": "BOTH",
                "Action": pb_action,
                "IsEnabled": enabled,
                "ProxyConfigId": proxy_config_id
            })

    name = os.path.splitext(os.path.basename(output_pbprofile))[0]
    pb_profile = {
        "Version": "1.0",
        "Name": name,
        "LocalhostViaProxy": False,
        "IsTrafficLoggingEnabled": True,
        "AutoClearConnectionLogs": True,
        "Language": "en",
        "CloseToTray": True,
        "ProxyConfigs": proxy_configs,
        "ProxyRules": proxy_rules,
        "LogFilters": []
    }

    try:
        with open(output_pbprofile, 'w', encoding='utf-8') as f:
            json.dump(pb_profile, f, indent=2, ensure_ascii=False)
        print(f"Успешно конвертировано: {input_ppx} -> {output_pbprofile}")
    except Exception as e:
        print(f"Ошибка при записи в файл {output_pbprofile}: {e}")


def convert_pbprofile_to_ppx(input_pbprofile, output_ppx):
    try:
        with open(input_pbprofile, 'r', encoding='utf-8') as f:
            pb_profile = json.load(f)
    except Exception as e:
        print(f"Ошибка при чтении {input_pbprofile}: {e}")
        return

    root = ET.Element('ProxifierProfile', version="102", platform="Windows", product_id="0", product_minver="400")
    
    options = ET.SubElement(root, 'Options')
    resolve = ET.SubElement(options, 'Resolve')
    ET.SubElement(resolve, 'AutoModeDetection', enabled="true")
    ET.SubElement(resolve, 'ViaProxy', enabled="false")
    ET.SubElement(resolve, 'BlockNonATypes', enabled="false")
    excl = ET.SubElement(resolve, 'ExclusionList', OnlyFromListMode="false")
    excl.text = "localhost;127.*.*.*; %ComputerName%;"
    dns = ET.SubElement(resolve, 'DnsUdpMode')
    dns.text = "0"
    ET.SubElement(options, 'Encryption', mode="disabled")
    ET.SubElement(options, 'ConnectionLoopDetection', enabled="true", resolve="true")
    ET.SubElement(options, 'Udp', mode="mode_bypass")
    ET.SubElement(options, 'LeakPreventionMode', enabled="false")
    ET.SubElement(options, 'ProcessOtherUsers', enabled="false")
    ET.SubElement(options, 'ProcessServices', enabled="false")
    ET.SubElement(options, 'HandleDirectConnections', enabled="false")
    ET.SubElement(options, 'HttpProxiesSupport', enabled="false")
    
    proxy_list = ET.SubElement(root, 'ProxyList')
    
    proxy_id_map = {}
    base_id = 100
    
    for cfg in pb_profile.get('ProxyConfigs', []):
        pb_id = cfg.get('Id')
        ppx_id = str(base_id)
        base_id += 1
        proxy_id_map[pb_id] = ppx_id
        
        proxy = ET.SubElement(proxy_list, 'Proxy', id=ppx_id, type=cfg.get('Type', 'SOCKS5'))
        
        un = cfg.get('Username', '')
        pw = cfg.get('Password', '')
        if un or pw:
            auth = ET.SubElement(proxy, 'Authentication', enabled="true")
            if pw:
                ET.SubElement(auth, 'Password').text = pw
            if un:
                ET.SubElement(auth, 'Username').text = un
                
        opt = ET.SubElement(proxy, 'Options')
        opt.text = "48"
        
        port = ET.SubElement(proxy, 'Port')
        port.text = str(cfg.get('Port', ''))
        
        addr = ET.SubElement(proxy, 'Address')
        addr.text = cfg.get('Host', '')
        
        label = ET.SubElement(proxy, 'Label')
        label.text = f"Proxy {ppx_id}"

    ET.SubElement(root, 'ChainList')
    
    rule_list = ET.SubElement(root, 'RuleList')
    
    for i, rule in enumerate(pb_profile.get('ProxyRules', [])):
        r_node = ET.SubElement(rule_list, 'Rule', enabled="true" if rule.get('IsEnabled', True) else "false")
        
        action = rule.get('Action', 'DIRECT').upper()
        act_node = ET.SubElement(r_node, 'Action')
        if action == 'DIRECT':
            act_node.set('type', 'Direct')
        elif action == 'BLOCK':
            act_node.set('type', 'Block')
        elif action == 'PROXY':
            act_node.set('type', 'Proxy')
            pb_pid = rule.get('ProxyConfigId')
            if pb_pid in proxy_id_map:
                act_node.text = proxy_id_map[pb_pid]
            else:
                act_node.text = "100" 
                
        targets = rule.get('TargetHosts', '*')
        if targets != '*':
            ET.SubElement(r_node, 'Targets').text = targets
            
        ports = rule.get('TargetPorts', '*')
        if ports != '*':
            ET.SubElement(r_node, 'Ports').text = ports
            
        apps = rule.get('ProcessName', '*')
        if apps != '*':
            ET.SubElement(r_node, 'Applications').text = apps
            
        name_node = ET.SubElement(r_node, 'Name')
        name_node.text = f"Rule {i + 1}"

    try:
        xmlstr = ET.tostring(root, encoding='utf-8')
        dom = xml.dom.minidom.parseString(xmlstr)
        pretty_xml_as_string = dom.toprettyxml(indent="\t")
        
        lines = [line for line in pretty_xml_as_string.split('\n') if line.strip()]
        
        if lines and lines[0].startswith("<?xml"):
            lines[0] = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            
        with open(output_ppx, 'w', encoding='utf-8') as f:
            f.write('\n'.join(lines))
            
        print(f"Успешно конвертировано: {input_pbprofile} -> {output_ppx}")
    except Exception as e:
        print(f"Ошибка при записи в файл {output_ppx}: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Использование: ProfileConverter.exe <ВХОДНОЙ_ФАЙЛ> <ВЫХОДНОЙ_ФАЙЛ>")
        print("Пример (ppx -> pbprofile): ProfileConverter.exe input.ppx output.pbprofile")
        print("Пример (pbprofile -> ppx): ProfileConverter.exe input.pbprofile output.ppx")
        sys.exit(1)
        
    in_file = sys.argv[1]
    out_file = sys.argv[2]
    
    if in_file.lower().endswith('.ppx'):
        convert_ppx_to_pbprofile(in_file, out_file)
    elif in_file.lower().endswith('.pbprofile'):
        convert_pbprofile_to_ppx(in_file, out_file)
    else:
        print("Ошибка: Входной файл должен иметь расширение .ppx или .pbprofile")
