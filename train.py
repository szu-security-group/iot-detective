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
    devices_knowledge_dict = get_jsonful_from_mongodb("new_devices_knowledge")
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
            if great_domains_tfidf_len_square >= 0.8 * 0.8 * tfidf_vector_length * tfidf_vector_length:
                break
    for domain, devices in devices_great_domains_to_devices.items():
        GREAT_DOMAINS_COL.update_one({"domain": domain}, {"$set": {"devices": devices}}, upsert=True)


@calc_method_time
def get_ips_domains_windows(train_pcap_file, excluded_domains, specify_train_ips, train_ips=None):
    """
    获取各个ip的窗口数（第一个到最后一个DNS包期间的窗口数）及各个训练ip各个域名的出现窗口数
    :param train_pcap_file: 训练的pcap
    :param excluded_domains: 停止词，TOP100域名和其它需要排除的域名
    :param excluded_domains_suffix: 排除掉的域名后缀
    :param train_ips: 特指训练的ip
    :return: 各个ip的窗口数（第一个到最后一个DNS包期间的窗口数）及各个训练ip各个域名的出现窗口数
    """
    ips_domains_windows = dict()
    pkts = rdpcap(os.path.join(TRAIN_DATA_FOLDER_NAME, train_pcap_file))
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
        if is_excluded_domain(domain, excluded_domains, EXCLUDED_DOMAINS_SUFFIX):  # 过滤特定域名
            continue
        domain = erase_protocol_prefix(domain).lower()  # 统一域名格式
        if ip not in ips_domains_windows.keys():
            ips_domains_windows[ip] = dict()
        if domain not in ips_domains_windows[ip]:
            ips_domains_windows[ip][domain] = set()
        ips_domains_windows[ip][domain].add(window_index)
    result_ips_domains_windows = dict()
    for ip, domains_windows in ips_domains_windows.items():
        result_ips_domains_windows[ip] = dict()
        for domain, windows in domains_windows.items():
            result_ips_domains_windows[ip][domain] = list(ips_domains_windows[ip][domain])
    store_json(result_ips_domains_windows, os.path.join(TRAIN_RESULT_FOLDER_NAME, train_pcap_file[:-len(".pcap")], "ips_domains_windows.json"))
    return ips_domains_windows


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


def train_devices(train_pcap_file, train_ips_device_info_file, day):
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
    file_name = train_pcap_file[:-len(".pcap")]
    if os.path.exists(os.path.join(TRAIN_RESULT_FOLDER_NAME, file_name, "ips_domains_windows.json")):
        logger.info("train: {file_name} has been existed".format(file_name=file_name))
        ips_domains_windows = load_json(os.path.join(TRAIN_RESULT_FOLDER_NAME, file_name, "ips_domains_windows.json"))
    else:
        mkdir_if_not_exist(os.path.join(TRAIN_RESULT_FOLDER_NAME, file_name))
        logger.info("train: read pacap:{file_name}".format(file_name=file_name))
        ips_domains_windows = get_ips_domains_windows(train_pcap_file, excluded_domains, specify_train_ips=False)
    # logger.info("读取{pcap}完成".format(pcap=train_pcap_file))

    # 每种设备的训练数据保存在MongoDB中，包括设备名device, 设备的类型type，设备的产商vendor，该类设备的训练次数train_num, 设备总出现窗口数windows_num，
    # 每个域名的出现窗口数domains_windows_num, 每个域名的tfidf值domains_tfidf以及总的tfidf的向量长度tfidf_vector_length
    for ip, domains_windows in ips_domains_windows.items():
        # 找到这个ip对应的设备
        device = train_ips_device_info[ip]["device"] + "_" + str(day)
        type = train_ips_device_info[ip]["type"]
        vendor = train_ips_device_info[ip]["vendor"]

        # 找到MongoDB中该设备的数据，若无，则初始化
        device_knowledge = {"device": device, "type": type, "vendor": vendor, "domains_windows_num": dict(),
                            "domains_tfidf": dict(), "tfidf_vector_length": 0}

        for domain, windows in domains_windows.items():
            domain_knowledge = DOMAINS_KNOWLEDGE_COL.find_one({"domain": domain})
            device_knowledge["domains_windows_num"][domain] = len(windows)
            device_knowledge["domains_tfidf"][domain] = len(windows) / TRAIN_WINDOWS_NUM * domain_knowledge["idf"]

        device_knowledge["tfidf_vector_length"] = cal_tfidf_vectors_length(device_knowledge["domains_tfidf"])

        device_knowledge["domains_tfidf"] = get_sorted_dict(device_knowledge["domains_tfidf"], compared_target="value")
        device_knowledge["tfidf_vector_length"] = cal_tfidf_vectors_length(device_knowledge["domains_tfidf"])
        # 更新device_knowledge
        DEVICES_KNOWLEDGE_COL.update_one({"device": device}, {"$set": device_knowledge}, upsert=True)
    logger.info("插入devices_knowledge完毕")

    # 更新devices_knowledge中所有device的domains_tfidf以及tfidf_vector_length
    devices_knowledge_dict = get_jsonful_from_mongodb("new_devices_knowledge")
    for device, device_knowledge in devices_knowledge_dict.items():
        domains_tfidf = device_knowledge["domains_tfidf"]
        for domain, tfidf in domains_tfidf.items():
            domain_tf = device_knowledge["domains_windows_num"][domain] / TRAIN_WINDOWS_NUM
            domain_knowledge = DOMAINS_KNOWLEDGE_COL.find_one({"domain": domain})
            device_knowledge["domains_tfidf"][domain] = domain_tf * domain_knowledge["idf"]
        device_knowledge["tfidf_vector_length"] = cal_tfidf_vectors_length(device_knowledge["domains_tfidf"])
        DEVICES_KNOWLEDGE_COL.update_one({"device": device}, {
            "$set": {"domains_tfidf": device_knowledge["domains_tfidf"],
                     "tfidf_vector_length": device_knowledge["tfidf_vector_length"]}}, upsert=False)
    logger.info("更新devices_knowledge完毕")


def get_domains_idf(pcap_file):
    top_domains = load_json(TOP_DOMAINS_FILE)
    other_excluded_domains = load_json(OTHER_EXCLUDED_DOMAINS_FILE)
    excluded_domains = list()
    excluded_domains.extend(top_domains)
    excluded_domains.extend(other_excluded_domains)

    total_ip_set = set()
    domain_ip = dict()
    pkts = rdpcap(pcap_file)
    for i, pkt in enumerate(pkts):
        # 需要是ipv4
        if sc.IP in pkt:
            ip = pkt[sc.IP].dst
        else:
            ip = pkt[sc.IPv6].dst
        if ip in BLACK_IPS:
            continue
        domain = str(pkt[sc.DNS].qd.qname, encoding=ENCODING_METHOD)[:-1]  # -1是为了去除domain最后的.
        total_ip_set.add(ip)
        if is_excluded_domain(domain, excluded_domains, EXCLUDED_DOMAINS_SUFFIX):  # 过滤特定域名
            continue
        domain = erase_protocol_prefix(domain).lower()  # 统一域名格式
        if domain not in domain_ip.keys():
            domain_ip[domain] = set()
        domain_ip[domain].add(ip)
    domains_idf = dict()
    for domain, ip_set in domain_ip.items():
        domains_idf[domain] = math.log((1 + (len(total_ip_set) / (1 + len(ip_set)))), 2)
        val = {"idf": domains_idf[domain], "devices_num": len(ip_set)}
        DOMAINS_KNOWLEDGE_COL.update_one({"domain": domain}, {"$set": val}, upsert=True)

    # 更新great_domains
    update_great_domains()
    logger.info("更新great_domains完毕")


@calc_method_time
def main():
    # get_domains_idf(os.path.join("train_data", "finder", "finder_2019_08.pcap"))
    # 删除集合new_devices_knowledge和new_great_domains
    deleted_collections = [DEVICES_KNOWLEDGE_COL, GREAT_DOMAINS_COL]
    for collection in deleted_collections:
        collection_name = collection.name
        if collection.drop():
            print("删除集合：{collection}  成功".format(collection=collection_name))
        else:
            print("删除集合：{collection}  失败".format(collection=collection_name))

    for day in TRAIN_DAYS:
        train_pcap_file = "finder_2019_08_"+str(day)+".pcap"
        train_devices(train_pcap_file, TRAIN_IPS_DEVICE_INFO_FILE, day)

    # 更新great_domains
    update_great_domains()
    logger.info("更新great_domains完毕")


if __name__ == '__main__':
    main()
