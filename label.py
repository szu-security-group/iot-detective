#!/usr/bin/env python
# -*- coding:utf-8 -*-
# @Time    : 2021/05/13 16:48
# @Author  : Zixing Xiao

import math
import scapy.all as sc
from scapy.utils import rdpcap
import matplotlib.pyplot as plt

from star_query import *
from my_tools import *

LABEL_TARGET_NAME, LABEL_PCAP_FILE, LABEL_IPS_DEVICES_INFO_FILE, LABEL_RESULT_FOLDER_NAME, ALL_THETAS_PERFORMANCE_FILE, LABEL_IPS_DOMAINS_REGULARITY_SCORE_FILE, LABEL_IPS_DOMAINS_PKTS_TIME_FILE, LABEL_IPS_OTHER_DOMAINS_FILE, LABEL_IPS_PERFORMANCE_FILE, LABEL_IPS_POSSIBLE_DEVICES_FILE, LABEL_IPS_POSSIBLE_DEVICES_SIMILARITY_FILE, LABEL_IPS_REPORT_FILE, LABEL_IPS_INFO_FILE = [
    None for i in range(13)]


def measure_performance(test_ips_possible_devices_similarity, test_ips_devices_info, theta):
    ips_tp = 0
    ips_fp = 0
    ips_fn = 0
    for test_ip, possible_devices_info in test_ips_possible_devices_similarity.items():
        tp = 0
        fp = 0
        test_ip_devices = [test_ips_devices_info[test_ip][i]["device"] for i in
                           range(len(test_ips_devices_info[test_ip]))]
        test_ip_devices_info_num = len(test_ip_devices)
        for possible_device, similarity in possible_devices_info.items():
            if similarity >= (theta - 0.0000000000000010):
                if possible_device in test_ip_devices:
                    tp += 1
                else:
                    fp += 1
        fn = test_ip_devices_info_num - tp
        ips_tp += tp
        ips_fp += fp
        ips_fn += fn

    if ips_tp == 0:
        precision = 0
        recall = 0
        f_05, f_1, f_2 = 0, 0, 0
    else:
        precision = ips_tp / (ips_tp + ips_fp)
        recall = ips_tp / (ips_tp + ips_fn)
        f_05 = (1.25 * precision * recall) / (0.25 * precision + recall)  # F0.5
        f_1 = (2 * precision * recall) / (precision + recall)  # F1
        f_2 = (5 * precision * recall) / (4 * precision + recall)  # F2
    return precision, recall, f_05, f_1, f_2


# def measure_performance(test_ips_possible_devices_similarity, test_ips_devices_info, theta):
#     test_ips_nums = len(test_ips_possible_devices_similarity)
#     ips_precision = 0
#     ips_recall = 0
#     for test_ip, possible_devices_info in test_ips_possible_devices_similarity.items():
#         test_ip_devices_info_num = len(test_ips_devices_info[test_ip])
#         tp = 0
#         fp = 0
#         for possible_device, similarity in possible_devices_info.items():
#             if similarity >= theta:
#                 tp_flag = False
#                 for device_info in test_ips_devices_info[test_ip]:
#                     if possible_device == device_info["device"]:
#                         tp += 1
#                         tp_flag = True
#                         break
#                 if not tp_flag:
#                     fp += 1
#         fn = test_ip_devices_info_num - tp
#         if tp + fp == 0:  # 推测该ip没有iot设备
#             if test_ip_devices_info_num == 0:  # 该ip实际上没有任何iot设备
#                 ip_precision = 1
#             else:  # 该ip实际上有iot设备
#                 ip_precision = 0
#         else:  # 推测该ip有iot设备
#             ip_precision = tp / (tp + fp)  # 在预测为真的样例中，实际为真的概率
#         if tp + fn == 0:  # 表示该ip实际上没有任何iot设备，则默认召回率为1
#             ip_recall = 1
#         else:
#             ip_recall = tp / (tp + fn)  # 在实际为真的样例中，预测为真的概率
#         ips_precision += ip_precision
#         ips_recall += ip_recall
#     precision_average = ips_precision / test_ips_nums
#     recall = ips_recall / test_ips_nums
#     if precision_average + recall == 0:
#         score = 0
#     else:
#         score = (2 * precision_average * recall) / (precision_average + recall)
#     return precision_average, recall, score


def try_theta_for_possible_devices():
    """
    尝试判别的theta，若ip和某设备的tfidf相似度大于该阈值，视为ip存在该设备
    :return:
    """
    test_ips_possible_devices_similarity = load_json(LABEL_IPS_POSSIBLE_DEVICES_SIMILARITY_FILE)
    test_ips_devices_info = load_json(LABEL_IPS_DEVICES_INFO_FILE)
    all_thetas_performance = dict()
    for theta in np.arange(THETA_LOW, THETA_HIGH + THETA_STEP, THETA_STEP):
        precision, recall, f_05, f_1, f_2 = measure_performance(test_ips_possible_devices_similarity,
                                                                test_ips_devices_info, theta)
        all_thetas_performance[theta] = {
            "theta": theta,
            "precision": precision,
            "recall": recall,
            "F0.5": f_05,
            "F1": f_1,
            "F2": f_2,
        }
    store_json(all_thetas_performance, ALL_THETAS_PERFORMANCE_FILE)


def get_test_ips_performance():
    """
    从all_thetas_performance中挑选score最大对应的theta，作为判别阈值，并得到所有ip的性能
    :return:
    """
    all_thetas_performance = load_json(ALL_THETAS_PERFORMANCE_FILE)
    test_ips_possible_devices_similarity = load_json(LABEL_IPS_POSSIBLE_DEVICES_SIMILARITY_FILE)
    test_ips_devices_info = load_json(LABEL_IPS_DEVICES_INFO_FILE)
    theta = float(get_key_by_max_value(all_thetas_performance, "F2"))
    precision, recall, f_05, f_1, f_2 = measure_performance(test_ips_possible_devices_similarity,
                                                            test_ips_devices_info, theta)
    test_ips_performance = {
        "theta": theta,
        "precision": precision,
        "recall": recall,
        "F0.5": f_05,
        "F1": f_1,
        "F2": f_2,
    }
    store_json(test_ips_performance, LABEL_IPS_PERFORMANCE_FILE)


def get_filtered_domains_tfidf(domains_tfidf_1, domains_tfidf_2):
    """
    以domains_tfidf_1为基准，生成domains_tfidf_2过滤后的tfidf字典。
    对于domains_tfidf_1中的domain，若domains_tfidf_2有，则填充，没有则设置为0
    :param domains_tfidf_1:  IoT设备的真实domain tfidf数据
    :param domains_tfidf_2:  测试ip的domain tfidf数据
    :return:
    """
    filtered_domains_tfidf_2 = dict()
    for domain, domain_tfidf in domains_tfidf_1.items():
        filtered_domains_tfidf_2[domain] = domains_tfidf_2.get(domain, 0)
    return filtered_domains_tfidf_2


def get_test_ips_possible_devices():
    """
    对测试集中每个ip查询的domain，去最佳域名集寻找到可能匹配的设备，得到每个ip可能匹配的设备
    :return:
    """
    ips_domains_tfidf = load_json(LABEL_IPS_INFO_FILE, "ips_domains_tfidf")
    devices_great_domains_to_devices = get_jsonful_from_mongodb("great_domains", sub_key="devices")
    test_ips_possible_devices = dict()
    for ip, domains_tfidf in ips_domains_tfidf.items():
        ip_possible_devices_set = set()
        ip_domains = domains_tfidf.keys()
        for domain in ip_domains:
            if domain in devices_great_domains_to_devices.keys():
                ip_possible_devices_set.update(devices_great_domains_to_devices[domain])
        test_ips_possible_devices[ip] = list(ip_possible_devices_set)
    store_json(test_ips_possible_devices, LABEL_IPS_POSSIBLE_DEVICES_FILE)


def get_test_ips_possible_devices_similarity():
    """
    得到测试集中每个ip和其可能匹配的设备间的tf-idf相似度
    :return:
    """
    devices_domains_tfidf = get_jsonful_from_mongodb("devices_knowledge", "domains_tfidf")
    devices_domains_tfidf_vector_length = get_jsonful_from_mongodb("devices_knowledge", "tfidf_vector_length")
    ips_domains_tfidf = load_json(LABEL_IPS_INFO_FILE, "ips_domains_tfidf")
    test_ips_possible_devices = load_json(LABEL_IPS_POSSIBLE_DEVICES_FILE)
    test_ips_possible_devices_similarity = dict()
    for ip, possible_devices in test_ips_possible_devices.items():
        test_ips_possible_devices_similarity[ip] = dict()
        for possible_device in possible_devices:
            possible_device_domains_tfidf = devices_domains_tfidf[possible_device]
            filtered_test_ip_domains_tfidf = get_filtered_domains_tfidf(possible_device_domains_tfidf,
                                                                        ips_domains_tfidf[ip])
            similarity = get_domains_dot_product(possible_device_domains_tfidf, filtered_test_ip_domains_tfidf) / (
                    devices_domains_tfidf_vector_length[possible_device] *
                    cal_tfidf_vectors_length(filtered_test_ip_domains_tfidf))
            test_ips_possible_devices_similarity[ip][possible_device] = similarity
    for ip, possible_devices in test_ips_possible_devices_similarity.items():
        # 按各个匹配设备的tfidf大小进行排序
        test_ips_possible_devices_similarity[ip] = get_sorted_dict(possible_devices, compared_target="value")
    store_json(test_ips_possible_devices_similarity, LABEL_IPS_POSSIBLE_DEVICES_SIMILARITY_FILE)


def get_keywords_count_in_text(keyword_list, text):
    text = " ".join(re.split(SPECIAL_SPLIT_SYMBOL, text.lower()))
    keywords_count = dict()
    for keyword in keyword_list:
        if " " in keyword:
            keyword_count = text.count(keyword)
            if keyword_count != 0:
                keywords_count[keyword] = keyword_count
        else:
            for word in text.split(" "):
                if keyword == word:
                    keywords_count[keyword] = keywords_count.get(keyword, 0) + 1
    if len(keywords_count) == 0:
        return None
    else:
        return get_sorted_dict(keywords_count, "value")


# def get_keywords_count_in_text(keyword_list, text):
#     keywords_count = dict()
#     for keyword in keyword_list:
#         keyword_count = text.count(keyword)
#         if keyword_count != 0:
#             keywords_count[keyword] = keyword_count
#     if len(keywords_count) == 0:
#         return None
#     else:
#         return get_sorted_dict(keywords_count, "value")


def guess_target_by_visit(knowledge_list, target_dict):
    """
    通过website搜索猜测domain可能的知识库词汇
    :param knowledge_list: 知识库词汇列表
    :param target_dict: 要猜测的target_dict
    :return: 各个知识库词汇的计数值
    """
    text_list = list()
    if target_dict["exception"] is None and target_dict["tags_data"]:
        for tag_name, text_list in target_dict["tags_data"].items():
            text_list.extend(text_list)
    return get_keywords_count_in_text(knowledge_list, " ".join(text_list))


# def guess_target_by_visit(knowledge_list, target_dict):
#     """
#     通过website搜索猜测domain可能的知识库词汇
#     :param knowledge_list: 知识库词汇列表
#     :param target_dict: 要猜测的target_dict
#     :return: 各个知识库词汇的计数值
#     """
#     knowledge_words_count = dict()
#     if target_dict["exception"] is None and target_dict["tags_data"]:
#         for tag_name, text_list in target_dict["tags_data"].items():
#             for tag_text in text_list:
#                 for knowledge_word in knowledge_list:
#                     for word in re.split(SPECIAL_SPLIT_SYMBOL, tag_text.lower()):
#                         if knowledge_word == word:
#                             knowledge_words_count[knowledge_word] = knowledge_words_count.get(knowledge_word, 0) + 1
#         if len(knowledge_words_count) != 0:
#             # knowledge_words_count = get_key_by_max_value(knowledge_words_count)
#             knowledge_words_count = get_sorted_dict(knowledge_words_count, compared_target="value")
#         else:
#             knowledge_words_count = None
#         return knowledge_words_count
#     else:
#         return None


def guess_query_info_by_google(knowledge_list, query_info):
    """
    通过google搜索猜测query_info可能的知识库词汇
    :param knowledge_list: 知识库词汇列表
    :param query_info: 要猜测的query_info
    :return: 各个知识库词汇的计数值
    """
    text_list = list()
    google_dict = get_query_info_google_result(query_info)
    if FIND_WORD_USE_STRUCTURE and google_dict["page_info"]["is_structured"]:
        for row in google_dict["page_info"]["structured_data"]:
            for key, value in row.items():
                text_list.extend(value)
    else:
        for tag_name, text in google_dict["page_info"]["tags_data"].items():
            text_list.extend(text)
    return get_keywords_count_in_text(knowledge_list, " ".join(text_list))


# def guess_query_info_by_google(knowledge_list, query_info):
#     """
#     通过google搜索猜测query_info可能的知识库词汇
#     :param knowledge_list: 知识库词汇列表
#     :param query_info: 要猜测的query_info
#     :return: 各个知识库词汇的计数值
#     """
#     knowledge_words_count = dict()
#     google_dict = get_query_info_google_result(query_info)
#     if FIND_WORD_USE_STRUCTURE and google_dict["page_info"]["is_structured"]:
#         for row in google_dict["page_info"]["structured_data"]:
#             for key, value in row.items():
#                 for knowledge_word in knowledge_list:
#                     for word in re.split(SPECIAL_SPLIT_SYMBOL, value.lower()):
#                         if knowledge_word == word:
#                             knowledge_words_count[knowledge_word] = knowledge_words_count.get(knowledge_word, 0) + 1
#     else:
#         for tag_name, text_list in google_dict["page_info"]["tags_data"].items():
#             for tag_text in text_list:
#                 for knowledge_word in knowledge_list:
#                     for word in re.split(SPECIAL_SPLIT_SYMBOL, tag_text.lower()):
#                         if knowledge_word == word:
#                             knowledge_words_count[knowledge_word] = knowledge_words_count.get(knowledge_word, 0) + 1
#     if len(knowledge_words_count) != 0:
#         # knowledge_words_count = get_key_by_max_value(knowledge_words_count)
#         knowledge_words_count = get_sorted_dict(knowledge_words_count, compared_target="value")
#     else:
#         knowledge_words_count = None
#     return knowledge_words_count


def guess_type(common_types, domain):
    """
    对于某domain，返回可能的type，或者common_type中各个type在网址或谷歌搜索结果或谷歌搜索结果链接中出现的次数（去重后）
    :param domain:
    :return:
    """
    logger.info("guess_type for {domain}".format(domain=domain))
    guess_method = None
    types_count = None

    # 1. 域名判存法
    # for common_type in common_types:
    #     if common_type in re.split(SPECIAL_SPLIT_SYMBOL, domain.lower()):
    #         if types_count is None:
    #             types_count = dict()
    #         guess_method = "1. domain_existence_method"
    #         types_count[common_type] = types_count.get("types_count", 0) + 1
    domain_split_list = domain.lower().split(".")
    for common_type in common_types:
        for word in domain_split_list:
            if common_type == word:
                if types_count is None:
                    types_count = dict()
                guess_method = "1. domain_existence_method"
                types_count[common_type] = types_count.get("types_count", 0) + 1

    # 2. 响应判存法
    if types_count is None:
        target_dict = visit_domain(domain)
        types_count = guess_target_by_visit(common_types, target_dict)
        if types_count is not None:
            guess_method = "2. domain_response_existence_method"

    # 3. google直接判存法
    if types_count is None:
        types_count = guess_query_info_by_google(common_types, domain)
        if types_count is not None:
            # 需要将一些可能重复多次的词汇进行删重，如bell出现在doorbell中，bell会多计算了
            # google_existence_types_count = eliminate_redundancy(redundant_type_dict, types_count)
            # if len(types_count) != 0:
            #     return google_existence_types_count
            guess_method = "3. google_only_domain_existence_method"

    # 4. google 添加关键词法
    keyword = "device"
    if types_count is None:
        types_count = guess_query_info_by_google(common_types, domain + " " + keyword)
        if types_count is not None:
            guess_method = "4. google_plus_keyword_existence_method"

    # 5. 访问3和4页面URL法
    if types_count is None:
        total_types_count = dict()
        urls = list()
        for url in GOOGLE_COL.find_one({"query_info": domain})["page_info"]["tags_data"]["url"]:
            urls.append(url)
        for url in GOOGLE_COL.find_one({"query_info": domain + " " + keyword})["page_info"]["tags_data"]["url"]:
            urls.append(url)
        for url in urls:
            target_dict = visit_google_url(url)
            one_target_types_count = guess_target_by_visit(common_types, target_dict)
            if one_target_types_count is not None:
                for type, count in one_target_types_count.items():
                    total_types_count[type] = total_types_count.get(type, 0) + count
        if len(total_types_count) != 0:
            total_types_count = get_sorted_dict(total_types_count, "value")
            guess_method = "5. visit_url_method"
            types_count = total_types_count

    return {"guess_method": guess_method, "types_count": types_count}


def guess_vendor(global_vendors, domain):
    """
    对于某domain，返回可能的vendor，或者global_vendors中各个vendor在网址或谷歌搜索结果或谷歌搜索结果链接中出现的次数
    :param domain:
    :return:
    """
    logger.info("guess_vendor for {domain}".format(domain=domain))
    guess_method = None
    guessed_vendor = None
    guessed_vendors_count = None
    sub_domain, second_domain, suffix = tldextract.extract(domain)

    # 1. 域名判存法
    if second_domain in global_vendors:
        guess_method = "1. domain_existence_method"
        guessed_vendor = second_domain

    # 2. whois查找
    if guessed_vendor is None:
        guessed_vendor = guess_domain_vendor_by_whois(second_domain + '.' + suffix)
        if guessed_vendor:
            guess_method = "2. whois_method"

    # 3. 响应判存法
    if guessed_vendors_count is None:
        target_dict = visit_domain(domain)
        guessed_vendors_count = guess_target_by_visit(global_vendors, target_dict)
        if guessed_vendors_count is not None:
            guess_method = "3. domain_response_existence_method"

    # 4. google直接判存法
    if guessed_vendor is None:
        guessed_vendors_count = guess_query_info_by_google(global_vendors, domain)
        if guessed_vendors_count is not None:
            guess_method = "4. google_only_domain_existence_method"

    # 5. google 添加关键词法
    keyword = "vendor"
    if guessed_vendor is None and guessed_vendors_count is None:
        guessed_vendors_count = guess_query_info_by_google(global_vendors, domain + " " + keyword)
        if guessed_vendors_count is not None:
            guess_method = "5. google_plus_keyword_existence_method"

    # 6. 访问4和5页面URL法
    if guessed_vendor is None and guessed_vendors_count is None:
        total_vendors_count = dict()
        urls = list()
        for url in GOOGLE_COL.find_one({"query_info": domain})["page_info"]["tags_data"]["url"]:
            urls.append(url)
        for url in GOOGLE_COL.find_one({"query_info": domain + " " + keyword})["page_info"]["tags_data"]["url"]:
            urls.append(url)
        for url in urls:
            target_dict = visit_google_url(url)
            one_target_vendors_count = guess_target_by_visit(global_vendors, target_dict)
            if one_target_vendors_count is not None:
                for vendor, count in one_target_vendors_count.items():
                    total_vendors_count[vendor] = total_vendors_count.get(vendor, 0) + count
        if len(total_vendors_count) != 0:
            total_vendors_count = get_sorted_dict(total_vendors_count, "value")
            guess_method = "6. visit_url_method"
            guessed_vendors_count = total_vendors_count

    if guessed_vendor:
        return {"guess_method": guess_method, "vendor": guessed_vendor}
    else:
        return {"guess_method": guess_method, "vendors_count": guessed_vendors_count}


def get_test_ips_info(test_pcap_file, is_nat=False):
    """
    将多个ip融合到一个新的ip"192.168.0.255"中。获取测试集中每个ip的domain tf-idf 以及每个ip每个domain的出现时间(以s为单位)
    :return:
    """
    all_iot_domains_idf = get_jsonful_from_mongodb("domains_knowledge", sub_key="idf")
    top_domains = load_json(TOP_DOMAINS_FILE)
    other_excluded_domains = load_json(OTHER_EXCLUDED_DOMAINS_FILE)
    excluded_domains = list()
    excluded_domains.extend(top_domains)
    excluded_domains.extend(other_excluded_domains)
    train_clients_num = get_val_from_mongodb("mix", val_name="train_clients_num")
    test_ips_info = dict()
    test_ips_domains_pkts_time = dict()  # 另外存储了文件名
    ips_domains_pkts_time = dict()  # 每个ip每个domain的出现时间(以s为单位)
    ips_domains_tfidf = dict()
    ips_first_window = dict()
    ips_last_window = dict()
    ips_domains_last_window = dict()
    pkts = rdpcap(test_pcap_file)
    start_time = pkts[0].time
    window_index = 0
    for i, pkt in enumerate(pkts):
        if sc.IP in pkt:
            ip = pkt[sc.IP].dst
        else:
            ip = pkt[sc.IPv6].dst
        if is_nat:
            ip = NAT_IP  # 融合的ip，视为NAT
        domain = str(pkt[sc.DNS].qd.qname, encoding=ENCODING_METHOD)[:-1]
        window_index = math.floor((pkt.time - start_time) / WINDOW_SECONDS) + 1
        if ip in BLACK_IPS:
            continue
        if is_excluded_domain(domain, excluded_domains, EXCLUDED_DOMAINS_SUFFIX):
            continue
        domain = erase_protocol_prefix(domain)
        if ip not in ips_domains_tfidf.keys():
            ips_domains_tfidf[ip] = {
                domain: 1
            }
            ips_first_window[ip] = window_index
            ips_domains_last_window[ip] = dict()
        elif domain not in ips_domains_tfidf[ip].keys():
            ips_domains_tfidf[ip][domain] = 1
        elif window_index > ips_domains_last_window[ip][domain]:
            ips_domains_tfidf[ip][domain] += 1
        if ip not in ips_domains_pkts_time.keys():
            ips_domains_pkts_time[ip] = {
                domain: [int(pkt.time - start_time)]
            }
        elif domain not in ips_domains_pkts_time[ip].keys():
            ips_domains_pkts_time[ip][domain] = [int(pkt.time - start_time)]
        else:
            ips_domains_pkts_time[ip][domain].append(int(pkt.time - start_time))
        ips_last_window[ip] = window_index
        ips_domains_last_window[ip][domain] = window_index
    for ip, device_fp in ips_domains_tfidf.items():
        for domain, counts in device_fp.items():
            ips_domains_tfidf[ip][domain] = counts / (
                    ips_last_window[ip] - ips_first_window[ip] + 1) * all_iot_domains_idf.get(domain, math.log(
                (1 + train_clients_num / (1 + 0)), 2))
            # 若测试ip中某domain在domain库里不存在，则idf仍应按照标准的算法进行计算
    for ip in ips_domains_tfidf.keys():
        ips_domains_tfidf[ip] = get_sorted_dict(ips_domains_tfidf[ip], compared_target="value")
    test_ips_info["pcap"] = test_pcap_file
    test_ips_info["window_seconds"] = WINDOW_SECONDS
    test_ips_info["nt"] = window_index
    test_ips_info["ips_domains_tfidf"] = get_sorted_dict_by_ip(ips_domains_tfidf)

    test_ips_domains_pkts_time["pcap"] = test_pcap_file
    test_ips_domains_pkts_time["ips_domains_pkts_time"] = get_sorted_dict_by_ip(ips_domains_pkts_time)

    store_json(test_ips_info, LABEL_IPS_INFO_FILE)
    store_json(test_ips_domains_pkts_time, LABEL_IPS_DOMAINS_PKTS_TIME_FILE)


def get_all_google(domains, vendors):
    """
    获取domain和vendor组合的google搜索结果
    :param domains:
    :param vendors:
    :return:
    """
    for domain in domains:
        get_word_google_search_num(domain)
        for vendor in vendors:
            get_word_google_search_num(domain + " " + vendor)


def get_word_google_search_num(word):
    """
    获取word的google搜索结果，返回搜索结果数目，即search_result["search_information"]["total_results"]
    :param word:
    :return:
    """
    google_info = OLD_GOOGLE_COL.find_one({"search_word": word})
    logger.info("google mongodb: {}".format(word))
    if google_info is None:
        logger.info("google api for: {}".format(word))
        url = GOOGLE_RAW_URL.format(word, GOOGLE_API_KEY)
        search_result = json.loads(requests.get(url).text)
        google_info = {"search_word": word}
        google_info.update({"search_result": search_result})
        OLD_GOOGLE_COL.insert_one(google_info)  # 将获取的信息写入到MongoDB中
    search_num = search_result["search_information"]["total_results"]
    return search_num


def get_test_ips_devices_info(old_train_ips_device_info_file):
    """
    修正测试设备信息，实际上，测试ip可以有多个设备，因此这里是列表形式
    :param train_ips_device_info_file: 训练设备信息
    :return:
    """
    test_ips_devices_info = dict()
    train_ips_device_info = load_json(old_train_ips_device_info_file)
    for ip, device_info in train_ips_device_info.items():
        test_ips_devices_info[ip] = [device_info]
    store_json(test_ips_devices_info, LABEL_IPS_DEVICES_INFO_FILE)


def mix_test_ips_devices_info():
    """
    将对ip的设备描述信息融合到"192.168.0.255"中去
    :return:
    """
    test_ips_devices_info = load_json(LABEL_IPS_DEVICES_INFO_FILE)
    test_nat_ip_devices_info = {NAT_IP: list()}
    for ip, devices_info in test_ips_devices_info.items():
        for device_info in devices_info:
            test_nat_ip_devices_info[NAT_IP].append(device_info)
    store_json(test_nat_ip_devices_info, os.path.join(LABEL_DATA_FOLDER_NAME, "finder_09_NAT" + ".json"))


def get_devices_thetas_performance():
    """
    获取每个设备在各个阈值下的表现，从而挑选最好的阈值
    :return:
    """
    devices_list = get_devices_list(TOTAL_IPS_DEVICES_INFO_FILE)
    devices_thetas_performance = dict()
    for device in devices_list:
        devices_thetas_performance[device] = dict()
        for theta in np.arange(THETA_LOW, THETA_HIGH + THETA_STEP, THETA_STEP):
            theta_str = str(theta)[:THETA_STR_LENGTH]
            devices_thetas_performance[device][theta_str] = {
                "tp": 0,
                "fp": 0,
                "fn": 0
            }
    # 先得到某device在所有的测试样本中出现的ip数
    devices_appearance_num = dict()
    for file_index in range(LABEL_FILE_LOW, LABEL_FILE_HIGH + 1):
        test_ips_devices_info_file = os.path.join(LABEL_DATA_FOLDER_NAME, "finder_08_" + str(file_index) + ".json")
        test_ips_devices_info = load_json(test_ips_devices_info_file)
        for ip, devices_info in test_ips_devices_info.items():
            for device_info in devices_info:
                devices_appearance_num[device_info["device"]] = devices_appearance_num.get(device_info["device"], 0) + 1
    # pprint(devices_appearance_num)

    # 得出结果
    for theta in np.arange(THETA_LOW, THETA_HIGH + THETA_STEP, THETA_STEP):
        theta_str = str(theta)[:THETA_STR_LENGTH]
        for file_index in range(LABEL_FILE_LOW, LABEL_FILE_HIGH + 1):
            test_ips_devices_info_file = os.path.join(LABEL_DATA_FOLDER_NAME, "finder_08_" + str(file_index) + ".json")
            test_ips_devices_info = load_json(test_ips_devices_info_file)
            file_name = os.path.join(LABEL_RESULT_FOLDER_NAME, "finder_08_" + str(file_index),
                                     "test_ips_possible_devices_similarity.json")
            test_ips_possible_devices_similarity = load_json(file_name)
            for test_ip, possible_devices_similarity in test_ips_possible_devices_similarity.items():
                test_ip_devices = [test_ips_devices_info[test_ip][i]["device"] for i in
                                   range(len(test_ips_devices_info[test_ip]))]
                for possible_device, similarity in possible_devices_similarity.items():
                    if similarity >= (theta - 0.0000000000000010):
                        if possible_device in test_ip_devices:
                            devices_thetas_performance[possible_device][theta_str]["tp"] += 1
                        else:
                            devices_thetas_performance[possible_device][theta_str]["fp"] += 1
        for device in devices_appearance_num.keys():
            devices_thetas_performance[device][theta_str]["fn"] = \
                devices_appearance_num[device] - devices_thetas_performance[device][theta_str]["tp"]

    # 计算precision, recall, F0.5, F1, F2
    for device, thetas_performance in devices_thetas_performance.items():
        for theta, performance in thetas_performance.items():
            theta_str = str(theta)[:THETA_STR_LENGTH]
            tp = performance["tp"]
            fp = performance["fp"]
            fn = performance["fn"]
            if tp == 0:
                devices_thetas_performance[device][theta_str]["precision"] = 0
                devices_thetas_performance[device][theta_str]["recall"] = 0
                devices_thetas_performance[device][theta_str]["F0.5"] = 0
                devices_thetas_performance[device][theta_str]["F1"] = 0
                devices_thetas_performance[device][theta_str]["F2"] = 0
            else:
                precision = tp / (tp + fp)
                recall = tp / (tp + fn)
                devices_thetas_performance[device][theta_str]["precision"] = precision
                devices_thetas_performance[device][theta_str]["recall"] = recall
                devices_thetas_performance[device][theta_str]["F0.5"] = (1.25 * precision * recall) / (
                        0.25 * precision + recall)  # F0.5
                devices_thetas_performance[device][theta_str]["F1"] = (2 * precision * recall) / (
                        precision + recall)  # F1
                devices_thetas_performance[device][theta_str]["F2"] = (5 * precision * recall) / (
                        4 * precision + recall)  # F2

    # 存储各个device中各个theta对应的precision, recall, F0.5, F1, F2
    for device in devices_list:
        device_thetas_performance_filename = os.path.join(DEVICES_PERFORMANCE_FOLDER_NAME, device + ".json")
        store_json(devices_thetas_performance[device], device_thetas_performance_filename)


def draw_devices_performance():
    """
    根据各个阈值对应的分数，画出曲线
    :return:
    """
    targets = ["precision", "recall", "F2"]
    line_patterns = ['r-', 'g--', 'b:']
    # target = "precision"
    # target = "recall"
    # target = "F0.5"
    # target = "F1"
    # target = "F2"
    devices_list = get_devices_list(TOTAL_IPS_DEVICES_INFO_FILE)
    # devices_list = ["Apple HomePod"]
    # devices_list = ["Belkin WeMo Crockpot"]
    for device in devices_list:
        for i, target in enumerate(targets):
            device_thetas_performance_filename = os.path.join(DEVICES_PERFORMANCE_FOLDER_NAME, device + ".json")
            device_thetas_performance = load_json(device_thetas_performance_filename)
            thetas = list()
            scores = list()
            for theta_index, theta_str in enumerate(device_thetas_performance.keys()):
                if float(theta_str[:THETA_STR_LENGTH]) >= 0.6:
                    thetas.append(float(theta_str[:THETA_STR_LENGTH]))
                    scores.append(device_thetas_performance[theta_str][target])
            plt.title(device)
            plt.xlabel("threshold")
            # plt.ylabel(target)
            max_score = max(scores)
            max_index = scores.index(max_score)
            max_theta = thetas[max_index]
            show_max = "(" + str(max_theta) + ", " + str(max_score)[:5] + ")"
            plt.annotate(show_max, xytext=(max_theta, max_score), xy=(max_theta, max_score), )
            plt.plot(thetas, scores, line_patterns[i], label=target)
        # fig_path = os.path.join(DEVICES_PERFORMANCE_FOLDER_NAME, device + "_" + target + ".svg")
        plt.legend()
        plt.tight_layout()
        # fig_path = os.path.join(DEVICES_PERFORMANCE_FOLDER_NAME, device + ".png")
        # plt.savefig(fig_path)
        fig_path = os.path.join(DEVICES_PERFORMANCE_FOLDER_NAME, device + ".svg")
        plt.savefig(fig_path, format='svg')
        plt.show()


def get_devices_best_theta_performance():
    """
    获取设备最优阈值下的表现，其实只有阈值会用到在之后的识别中，而其它表现只是辅助看而已
    :return:
    """
    devices_best_theta_performance = dict()
    devices_list = get_devices_list(TOTAL_IPS_DEVICES_INFO_FILE)
    # devices_list = ["Google OnHub", "Nest Camera", "Belkin WeMo Motion Sensor", "LIFX Virtual Bulb", "Roku TV", "Roku4",
    #            "Amazon Fire TV", "Apple HomePod", "Google Home Hub", "Sonos Beam"]
    for device in devices_list:
        if os.path.exists(os.path.join(DEVICES_PERFORMANCE_FOLDER_NAME, device + ".json")):
            device_performance = load_json(os.path.join(DEVICES_PERFORMANCE_FOLDER_NAME, device + ".json"))
            # theta = get_key_by_max_value(device_performance, "F1")  # 找到字典中F1值最大所对应的阈值
            theta = get_key_by_max_value(device_performance, "F2")  # 找到字典中F2值最大所对应的阈值
            devices_best_theta_performance[device] = {
                "theta": theta,
                "precision": device_performance[theta]["precision"],
                "recall": device_performance[theta]["recall"],
                "F0.5": device_performance[theta]["F0.5"],
                "F1": device_performance[theta]["F1"],
                "F2": device_performance[theta]["F2"]
            }
    # store_json(devices_best_theta_performance, DEVICES_BEST_THETA_PERFORMANCE_FILE)
    # 将最优阈值写入到MongoDB中的DEVICES_KNOWLEDGE_COL中的阈值中去
    for device in devices_list:
        DEVICES_KNOWLEDGE_COL.update_one({"device": device}, {"$set": {"threshold": devices_best_theta_performance[device]["theta"]}}, upsert=True)
    return devices_best_theta_performance


@calc_method_time
def main():
    global LABEL_TARGET_NAME, LABEL_PCAP_FILE, LABEL_IPS_DEVICES_INFO_FILE, LABEL_RESULT_FOLDER_NAME, ALL_THETAS_PERFORMANCE_FILE, LABEL_IPS_DOMAINS_REGULARITY_SCORE_FILE, LABEL_IPS_DOMAINS_PKTS_TIME_FILE, LABEL_IPS_OTHER_DOMAINS_FILE, LABEL_IPS_PERFORMANCE_FILE, LABEL_IPS_POSSIBLE_DEVICES_FILE, LABEL_IPS_POSSIBLE_DEVICES_SIMILARITY_FILE, LABEL_IPS_REPORT_FILE, LABEL_IPS_INFO_FILE
    for i in range(LABEL_FILE_LOW, LABEL_FILE_HIGH + 1):
        # 0. 修正常量
        # LABEL_TARGET_NAME = "finder_08_" + str(i)
        LABEL_TARGET_NAME = "finder_08_" + str(i) + "_NAT"
        LABEL_PCAP_FILE = os.path.join(LABEL_DATA_FOLDER_NAME, LABEL_TARGET_NAME.replace("_NAT", "") + ".pcap")
        LABEL_IPS_DEVICES_INFO_FILE = os.path.join(LABEL_DATA_FOLDER_NAME, LABEL_TARGET_NAME + ".json")
        # res文件夹中的文件，存放程序处理后的结果
        LABEL_RESULT_FOLDER_NAME = os.path.join("label_result", LABEL_TARGET_NAME)
        ALL_THETAS_PERFORMANCE_FILE = os.path.join(LABEL_RESULT_FOLDER_NAME, "all_thetas_performance.json")
        LABEL_IPS_DOMAINS_REGULARITY_SCORE_FILE = os.path.join(LABEL_RESULT_FOLDER_NAME,
                                                              "test_ips_domains_regularity_score.json")
        LABEL_IPS_DOMAINS_PKTS_TIME_FILE = os.path.join(LABEL_RESULT_FOLDER_NAME, "test_ips_domains_pkts_time.json")
        LABEL_IPS_OTHER_DOMAINS_FILE = os.path.join(LABEL_RESULT_FOLDER_NAME, "test_ips_other_domains.json")
        LABEL_IPS_PERFORMANCE_FILE = os.path.join(LABEL_RESULT_FOLDER_NAME, "test_ips_performance.json")
        LABEL_IPS_POSSIBLE_DEVICES_FILE = os.path.join(LABEL_RESULT_FOLDER_NAME, "test_ips_possible_devices.json")
        LABEL_IPS_POSSIBLE_DEVICES_SIMILARITY_FILE = os.path.join(LABEL_RESULT_FOLDER_NAME,
                                                                 "test_ips_possible_devices_similarity.json")
        LABEL_IPS_REPORT_FILE = os.path.join(LABEL_RESULT_FOLDER_NAME, "test_ips_report.json")
        LABEL_IPS_INFO_FILE = os.path.join(LABEL_RESULT_FOLDER_NAME, "test_ips_info.json")

        # 1. 测试设备信息test_ips_devices_info的准备
        # get_test_ips_devices_info(LABEL_IPS_DEVICES_INFO_FILE)  # 修正测试设备信息

        # 2. 创建好测试结果文件的文件夹
        mkdir_if_not_exist(LABEL_RESULT_FOLDER_NAME)

        # 3. 分析测试pcap
        # get_test_ips_info(LABEL_PCAP_FILE, is_nat=False)  # 获取测试集中每个ip的domain tf-idf，这里是每个ip对应一个设备
        get_test_ips_info(LABEL_PCAP_FILE, is_nat=True)  # 获取测试集中每个ip的domain tf-idf，这里弄成NAT模式
        get_test_ips_possible_devices()  # 对测试集中每个ip查询的domain，去最佳域名集寻找到可能匹配的设备，得到每个ip可能匹配的设备
        get_test_ips_possible_devices_similarity()  # 得到测试集中每个ip和其可能匹配的设备间的tf-idf相似度

    # get_devices_thetas_performance()
    # draw_devices_performance()  # 每个设备一张图

    # get_devices_best_theta_performance()


if __name__ == '__main__':
    main()
