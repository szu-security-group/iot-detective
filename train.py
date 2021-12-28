import math
import scapy.all as sc
from scapy.utils import rdpcap

from data_collection import *

TRAIN_IPS = None
# if None, then use all devices in TRAIN_PCAP_FILE to generate data,
# or you should add your desired train devices ip in train_ips as a list
EXAMINED_DEVICES_IP = ["192.168.0.22", "192.168.0.33", "192.168.0.43"]


# 注： 对于get_domains_idf中的devices_fp，训练集和测试集采用的均是train_devices_fp
# （其实按道理应该是全球语料库，即对于全球的client该domain的特异性)


def update_great_domains():
    """
    这里从每个device的domain集M中挑出得分最高的2个domain，形成{"*domain": [device1, ...]}
    在测试ip的domain集N中每个domain，查询M中键为domain的设备，得到的设备集合记为D，
    将测试ip和D中每个设备d进行tfidf匹配，设定阈值为θ，得到满足相似度大于θ的猜测设备集G
    :return:
    """
    devices_knowledge_dict = get_jsonful_from_mongodb("devices_knowledge")
    devices_great_domains_to_devices = dict()
    # 各个IoT设备最显著的domain组成domain集
    for device, device_knowledge in devices_knowledge_dict.items():
        domains_tfidf = device_knowledge["domains_tfidf"]
        tfidf_vector_length = device_knowledge["tfidf_vector_length"]
        great_domains_tfidf_len_square = 0
        for domain, tfidf in domains_tfidf.items():
            great_domains_tfidf_len_square += tfidf * tfidf
            if domain not in devices_great_domains_to_devices.keys():
                devices_great_domains_to_devices[domain] = [device]
            else:
                devices_great_domains_to_devices[domain].append(device)
            if great_domains_tfidf_len_square >= 0.9 * 0.9 * tfidf_vector_length * tfidf_vector_length:
                break
    for domain, devices in devices_great_domains_to_devices.items():
        GREAT_DOMAINS_COL.update_one({"domain": domain}, {"$set": {"devices": devices}}, upsert=True)


@calc_method_time
def get_train_info(train_cap_file, excluded_domains, specify_train_ips, train_ips=None):
    """
    获取各个ip的窗口数（第一个到最后一个DNS包期间的窗口数）及各个训练ip各个域名的出现窗口数
    :param train_cap_file: 训练的pcap
    :param excluded_domains: 停止词，TOP100域名和其它需要排除的域名
    :param excluded_domains_suffix: 排除掉的域名后缀
    :param train_ips: 特指训练的ip
    :return: 各个ip的窗口数（第一个到最后一个DNS包期间的窗口数）及各个训练ip各个域名的出现窗口数
    """
    train_ips_info = dict()
    ips_domains_windows_num = dict()
    ips_first_window = dict()
    ips_last_window = dict()
    ips_domains_last_window = dict()
    pkts = rdpcap(train_cap_file)
    start_time = pkts[0].time
    for i, pkt in enumerate(pkts):
        # 需要是ipv4
        if sc.IP in pkt:
            ip = pkt[sc.IP].dst
        else:
            ip = pkt[sc.IPv6].dst
        domain = str(pkt[sc.DNS].qd.qname, encoding=ENCODING_METHOD)[:-1]  # -1是为了去除domain最后的.
        window_index = math.floor((pkt.time - start_time) / WINDOW_SECONDS) + 1
        if ip in BLACK_IPS:
            continue
        if specify_train_ips:
            if ip not in train_ips:
                continue
        if is_excluded_domain(domain, excluded_domains, EXCLUDED_DOMAINS_SUFFIX):
            continue
        domain = erase_protocol_prefix(domain)
        if ip not in ips_domains_windows_num.keys():
            ips_domains_windows_num[ip] = {
                domain: 1
            }
            ips_first_window[ip] = window_index
            ips_domains_last_window[ip] = dict()
        elif domain not in ips_domains_windows_num[ip].keys():
            ips_domains_windows_num[ip][domain] = 1
        elif window_index > ips_domains_last_window[ip][domain]:
            ips_domains_windows_num[ip][domain] += 1
        ips_last_window[ip] = window_index
        ips_domains_last_window[ip][domain] = window_index
    for ip in ips_first_window.keys():
        train_ips_info[ip] = dict()
        train_ips_info[ip]["windows_num"] = ips_last_window[ip] - ips_first_window[ip] + 1
        train_ips_info[ip]["domains_windows_num"] = ips_domains_windows_num[ip]
    return train_ips_info


def get_domains_devices_nums(devices_fp):
    """
    每个域名对应多少个iot设备
    :param devices_fp: 每个设备每个域名的查询频率
    :return:每个域名对应的iot设备数目
    """
    domains_devices_nums = dict()
    for device_fp in devices_fp.values():
        for domain in device_fp.keys():
            domains_devices_nums[domain] = domains_devices_nums.get(domain, 0) + 1
    return domains_devices_nums


def get_ips_domains_tfidf(ips_domains_windows_num, domains_idf):
    """
    获取每个ip下每个domain的tfidf
    :param ips_domains_windows_num: 每个ip每个域名的查询频率
    :param domains_idf: 每个域名的idf信息
    :return:
    """
    ips_tfidf = dict()
    for ip, ip_fp in ips_domains_windows_num.items():
        ips_tfidf[ip] = dict()
        for domain in ip_fp.keys():
            ips_tfidf[ip][domain] = ip_fp[domain] * domains_idf[domain]
    return ips_tfidf


def train_devices(train_pcap_file, train_ips_device_info_file):
    """
    训练设备
    :param train_pcap_file: 训练的pcap文件
    :param train_ips_device_info_file: 对各个ip对应的设备的描述
    :return:
    """
    top_domains = load_json(TOP_DOMAINS_FILE)
    other_excluded_domains = load_json(OTHER_EXCLUDED_DOMAINS_FILE)
    excluded_domains = list()
    excluded_domains.extend(top_domains)
    excluded_domains.extend(other_excluded_domains)
    train_ips_device_info = load_json(train_ips_device_info_file)

    # 获取训练ip的信息
    train_ips_info = get_train_info(train_pcap_file, excluded_domains, specify_train_ips=False)
    logger.info("读取{pcap}完成".format(pcap=train_pcap_file))

    # 更新mix中的训练客户端数train_clients_num
    mix = MIX_COL.find_one({"info": "train"})
    if mix is None:
        mix = {"info": "train", "train_clients_num": 0, "train_file": list()}
        MIX_COL.insert_one(mix)
    mix["train_clients_num"] += len(train_ips_info)
    mix["train_file"].append(TRAIN_PCAP_FILE)
    MIX_COL.update_one({"info": "train"},
                       {"$set": {"train_clients_num": mix["train_clients_num"], "train_file": mix["train_file"]}},
                       upsert=True)
    logger.info("mix 更新完毕")

    # 预处理一下，得到每个域名对应的设备列表domains_devices，可能重复
    domains_devices = dict()
    for ip, ip_info in train_ips_info.items():
        domains_windows_num = ip_info["domains_windows_num"]
        device = train_ips_device_info[ip]["device"]
        for domain in domains_windows_num.keys():
            if domain not in domains_devices.keys():
                domains_devices[domain] = list()
            domains_devices[domain].append(device)

    # 每个域名的知识库保存在MongoDB中，包括域名domain, 在对应的设备的出现次数devices_num，总的出现次数total_num以及idf值idf
    for domain, devices in domains_devices.items():
        domain_knowledge = DOMAINS_KNOWLEDGE_COL.find_one({"domain": domain})
        if domain_knowledge is None:
            domain_knowledge = {"domain": domain, "devices_num": dict(), "total_num": 0, "idf": 0}
        for device in devices:
            domain_knowledge["devices_num"][device] = domain_knowledge["devices_num"].get(device, 0) + 1
        domain_knowledge["devices_num"] = get_sorted_dict(domain_knowledge["devices_num"], compared_target="value")
        domain_knowledge["total_num"] += len(devices)
        domain_knowledge["idf"] = math.log((1 + (mix["train_clients_num"] / (1 + domain_knowledge["total_num"]))), 2)
        # 更新domain_knowledge
        DOMAINS_KNOWLEDGE_COL.update_one({"domain": domain}, {"$set": domain_knowledge}, upsert=True)
    logger.info("插入domains_knowledge完毕")

    # 每种设备的训练数据保存在MongoDB中，包括设备名device, 设备的类型type，设备的产商vendor，该类设备的训练次数train_num, 设备总出现窗口数windows_num，
    # 每个域名的出现窗口数domains_windows_num, 每个域名的tfidf值domains_tfidf以及总的tfidf的向量长度tfidf_vector_length
    for ip, ip_info in train_ips_info.items():
        # 找到这个ip对应的设备
        device = train_ips_device_info[ip]["device"]
        type = train_ips_device_info[ip]["type"]
        vendor = train_ips_device_info[ip]["vendor"]

        # 找到MongoDB中该设备的数据，若无，则初始化
        device_knowledge = DEVICES_KNOWLEDGE_COL.find_one({"device": device})
        if device_knowledge is None:
            device_knowledge = {"device": device, "type": type, "vendor": vendor, "train_num": 0, "windows_num": 0,
                                "domains_windows_num": dict(), "domains_tfidf": dict(), "tfidf_vector_length": 0}

        # 如果type和vendor有变动，也要更新
        device_knowledge["type"] = type
        device_knowledge["vendor"] = vendor
        device_knowledge["train_num"] += 1
        device_knowledge["windows_num"] += ip_info["windows_num"]

        domains_windows_num = ip_info["domains_windows_num"]
        for domain, windows_num in domains_windows_num.items():
            domain_knowledge = DOMAINS_KNOWLEDGE_COL.find_one({"domain": domain})
            device_knowledge["domains_windows_num"][domain] = device_knowledge["domains_windows_num"].get(domain,
                                                                                                          0) + windows_num
            domain_tf = device_knowledge["domains_windows_num"][domain] / device_knowledge["windows_num"]
            device_knowledge["domains_tfidf"][domain] = domain_tf * domain_knowledge["idf"]
        device_knowledge["domains_windows_num"] = get_sorted_dict(device_knowledge["domains_windows_num"],
                                                                  compared_target="value")
        device_knowledge["domains_tfidf"] = get_sorted_dict(device_knowledge["domains_tfidf"], compared_target="value")
        device_knowledge["tfidf_vector_length"] = cal_tfidf_vectors_length(device_knowledge["domains_tfidf"])
        # 更新device_knowledge
        DEVICES_KNOWLEDGE_COL.update_one({"device": device}, {"$set": device_knowledge}, upsert=True)
    logger.info("插入devices_knowledge完毕")

    # -----------------------------------------------------------------------------
    # 训练了新数据，需要对一些数据进行更新
    # 更新domains_knowledge中所有domain的idf
    domains_knowledge_dict = get_jsonful_from_mongodb("domains_knowledge")
    for domain, domain_knowledge in domains_knowledge_dict.items():
        domain_knowledge["idf"] = math.log((1 + (mix["train_clients_num"] / (1 + domain_knowledge["total_num"]))), 2)
        DOMAINS_KNOWLEDGE_COL.update_one({"domain": domain},
                                         {"$set": {"idf": domain_knowledge["idf"]}}, upsert=False)
    logger.info("更新domains_knowledge完毕")

    # 更新devices_knowledge中所有device的domains_tfidf以及tfidf_vector_length
    devices_knowledge_dict = get_jsonful_from_mongodb("devices_knowledge")
    for device, device_knowledge in devices_knowledge_dict.items():
        domains_tfidf = device_knowledge["domains_tfidf"]
        for domain, tfidf in domains_tfidf.items():
            domain_tf = device_knowledge["domains_windows_num"][domain] / device_knowledge["windows_num"]
            device_knowledge["domains_tfidf"][domain] = domain_tf * domains_knowledge_dict[domain]["idf"]
        device_knowledge["tfidf_vector_length"] = cal_tfidf_vectors_length(device_knowledge["domains_tfidf"])
        DEVICES_KNOWLEDGE_COL.update_one({"device": device}, {
            "$set": {"domains_tfidf": device_knowledge["domains_tfidf"],
                     "tfidf_vector_length": device_knowledge["tfidf_vector_length"]}}, upsert=False)
    logger.info("更新devices_knowledge完毕")

    # 更新great_domains
    update_great_domains()
    logger.info("更新great_domains完毕")



@calc_method_time
def main():
    train_devices(TRAIN_PCAP_FILE, TRAIN_IPS_DEVICE_INFO_FILE)


if __name__ == '__main__':
    main()
