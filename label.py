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
#         if tp + fp == 0:  # ?????????ip??????iot??????
#             if test_ip_devices_info_num == 0:  # ???ip?????????????????????iot??????
#                 ip_precision = 1
#             else:  # ???ip????????????iot??????
#                 ip_precision = 0
#         else:  # ?????????ip???iot??????
#             ip_precision = tp / (tp + fp)  # ???????????????????????????????????????????????????
#         if tp + fn == 0:  # ?????????ip?????????????????????iot??????????????????????????????1
#             ip_recall = 1
#         else:
#             ip_recall = tp / (tp + fn)  # ???????????????????????????????????????????????????
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
    ???????????????theta??????ip???????????????tfidf?????????????????????????????????ip???????????????
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
    ???all_thetas_performance?????????score???????????????theta???????????????????????????????????????ip?????????
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
    ???domains_tfidf_1??????????????????domains_tfidf_2????????????tfidf?????????
    ??????domains_tfidf_1??????domain??????domains_tfidf_2????????????????????????????????????0
    :param domains_tfidf_1:  IoT???????????????domain tfidf??????
    :param domains_tfidf_2:  ??????ip???domain tfidf??????
    :return:
    """
    filtered_domains_tfidf_2 = dict()
    for domain, domain_tfidf in domains_tfidf_1.items():
        filtered_domains_tfidf_2[domain] = domains_tfidf_2.get(domain, 0)
    return filtered_domains_tfidf_2


def get_test_ips_possible_devices():
    """
    ?????????????????????ip?????????domain??????????????????????????????????????????????????????????????????ip?????????????????????
    :return:
    """
    ips_domains_tfidf = load_json(LABEL_IPS_INFO_FILE, "ips_domains_tfidf")
    devices_great_domains_to_devices = get_jsonful_from_mongodb("new_great_domains", sub_key="devices")
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
    ????????????????????????ip?????????????????????????????????tf-idf?????????
    :return:
    """
    devices_domains_tfidf = get_jsonful_from_mongodb(DEVICES_KNOWLEDGE_COL_NAME, "domains_tfidf")
    devices_domains_tfidf_vector_length = get_jsonful_from_mongodb(DEVICES_KNOWLEDGE_COL_NAME, "tfidf_vector_length")
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
        # ????????????????????????tfidf??????????????????
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
    ??????website????????????domain????????????????????????
    :param knowledge_list: ?????????????????????
    :param target_dict: ????????????target_dict
    :return: ?????????????????????????????????
    """
    text_list = list()
    if target_dict["exception"] is None and target_dict["tags_data"]:
        for tag_name, text_list in target_dict["tags_data"].items():
            text_list.extend(text_list)
    return get_keywords_count_in_text(knowledge_list, " ".join(text_list))


# def guess_target_by_visit(knowledge_list, target_dict):
#     """
#     ??????website????????????domain????????????????????????
#     :param knowledge_list: ?????????????????????
#     :param target_dict: ????????????target_dict
#     :return: ?????????????????????????????????
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
    ??????google????????????query_info????????????????????????
    :param knowledge_list: ?????????????????????
    :param query_info: ????????????query_info
    :return: ?????????????????????????????????
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
#     ??????google????????????query_info????????????????????????
#     :param knowledge_list: ?????????????????????
#     :param query_info: ????????????query_info
#     :return: ?????????????????????????????????
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
    ?????????domain??????????????????type?????????common_type?????????type??????????????????????????????????????????????????????????????????????????????????????????
    :param domain:
    :return:
    """
    logger.info("guess_type for {domain}".format(domain=domain))
    guess_method = None
    types_count = None

    # 1. ???????????????
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

    # 2. ???????????????
    if types_count is None:
        target_dict = visit_domain(domain)
        types_count = guess_target_by_visit(common_types, target_dict)
        if types_count is not None:
            guess_method = "2. domain_response_existence_method"

    # 3. google???????????????
    if types_count is None:
        types_count = guess_query_info_by_google(common_types, domain)
        if types_count is not None:
            # ????????????????????????????????????????????????????????????bell?????????doorbell??????bell???????????????
            # google_existence_types_count = eliminate_redundancy(redundant_type_dict, types_count)
            # if len(types_count) != 0:
            #     return google_existence_types_count
            guess_method = "3. google_only_domain_existence_method"

    # 4. google ??????????????????
    keyword = "device"
    if types_count is None:
        types_count = guess_query_info_by_google(common_types, domain + " " + keyword)
        if types_count is not None:
            guess_method = "4. google_plus_keyword_existence_method"

    # 5. ??????3???4??????URL???
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
    ?????????domain??????????????????vendor?????????global_vendors?????????vendor???????????????????????????????????????????????????????????????????????????
    :param domain:
    :return:
    """
    logger.info("guess_vendor for {domain}".format(domain=domain))
    guess_method = None
    guessed_vendor = None
    guessed_vendors_count = None
    sub_domain, second_domain, suffix = tldextract.extract(domain)

    # 1. ???????????????
    if second_domain in global_vendors:
        guess_method = "1. domain_existence_method"
        guessed_vendor = second_domain

    # 2. whois??????
    if guessed_vendor is None:
        guessed_vendor = guess_domain_vendor_by_whois(second_domain + '.' + suffix)
        if guessed_vendor:
            guess_method = "2. whois_method"

    # 3. ???????????????
    if guessed_vendors_count is None:
        target_dict = visit_domain(domain)
        guessed_vendors_count = guess_target_by_visit(global_vendors, target_dict)
        if guessed_vendors_count is not None:
            guess_method = "3. domain_response_existence_method"

    # 4. google???????????????
    if guessed_vendor is None:
        guessed_vendors_count = guess_query_info_by_google(global_vendors, domain)
        if guessed_vendors_count is not None:
            guess_method = "4. google_only_domain_existence_method"

    # 5. google ??????????????????
    keyword = "vendor"
    if guessed_vendor is None and guessed_vendors_count is None:
        guessed_vendors_count = guess_query_info_by_google(global_vendors, domain + " " + keyword)
        if guessed_vendors_count is not None:
            guess_method = "5. google_plus_keyword_existence_method"

    # 6. ??????4???5??????URL???
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
    ?????????ip?????????????????????ip"192.168.0.255"??????????????????????????????ip???domain tf-idf ????????????ip??????domain???????????????(???s?????????)
    :return:
    """
    ips_domains_windows = dict()
    all_iot_domains_idf = get_jsonful_from_mongodb("new_domains_knowledge", sub_key="idf")
    top_domains = load_json(TOP_DOMAINS_FILE)
    other_excluded_domains = load_json(OTHER_EXCLUDED_DOMAINS_FILE)
    excluded_domains = list()
    excluded_domains.extend(top_domains)
    excluded_domains.extend(other_excluded_domains)
    train_clients_num = get_val_from_mongodb("mix", val_name="train_clients_num")
    test_ips_info = dict()
    # test_ips_domains_pkts_time = dict()  # ????????????????????????
    # ips_domains_pkts_time = dict()  # ??????ip??????domain???????????????(???s?????????)
    ips_domains_tfidf = dict()
    pkts = rdpcap(test_pcap_file)
    start_time = pkts[0].time
    for i, pkt in enumerate(pkts):
        if sc.IP in pkt:
            ip = pkt[sc.IP].dst
        else:
            ip = pkt[sc.IPv6].dst
        if ip in BLACK_IPS:
            continue
        if is_nat:
            ip = NAT_IP  # ?????????ip?????????NAT
        domain = str(pkt[sc.DNS].qd.qname, encoding=ENCODING_METHOD)[:-1]
        window_index = math.floor((pkt.time - start_time) / WINDOW_SECONDS) + 1
        if is_excluded_domain(domain, excluded_domains, CLEANING_EXCLUDED_DOMAINS_SUFFIX):
            continue
        domain = erase_protocol_prefix(domain).lower()  # ??????????????????
        if ip not in ips_domains_windows.keys():
            ips_domains_windows[ip] = dict()
        if domain not in ips_domains_windows[ip]:
            ips_domains_windows[ip][domain] = set()
        ips_domains_windows[ip][domain].add(window_index)
    for ip, domains_windows in ips_domains_windows.items():
        ips_domains_tfidf[ip] = dict()
        for domain, windows in domains_windows.items():
            ips_domains_tfidf[ip][domain] = len(windows) / LABEL_WINDOWS_NUM * all_iot_domains_idf.get(domain, math.log(
                (1 + train_clients_num / (1 + 0)), 2))
            # ?????????ip??????domain???domain?????????????????????idf???????????????????????????????????????
    for ip in ips_domains_tfidf.keys():
        ips_domains_tfidf[ip] = get_sorted_dict(ips_domains_tfidf[ip], compared_target="value")
    test_ips_info["pcap"] = test_pcap_file
    test_ips_info["ips_domains_tfidf"] = get_sorted_dict_by_ip(ips_domains_tfidf)

    # test_ips_domains_pkts_time["pcap"] = test_pcap_file
    # test_ips_domains_pkts_time["ips_domains_pkts_time"] = get_sorted_dict_by_ip(ips_domains_pkts_time)

    store_json(test_ips_info, LABEL_IPS_INFO_FILE)
    # store_json(test_ips_domains_pkts_time, LABEL_IPS_DOMAINS_PKTS_TIME_FILE)


def get_all_google(domains, vendors):
    """
    ??????domain???vendor?????????google????????????
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
    ??????word???google?????????????????????????????????????????????search_result["search_information"]["total_results"]
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
        OLD_GOOGLE_COL.insert_one(google_info)  # ???????????????????????????MongoDB???
    search_num = search_result["search_information"]["total_results"]
    return search_num


def get_test_ips_devices_info(old_train_ips_device_info_file):
    """
    ?????????????????????????????????????????????ip???????????????????????????????????????????????????
    :param train_ips_device_info_file: ??????????????????
    :return:
    """
    test_ips_devices_info = dict()
    train_ips_device_info = load_json(old_train_ips_device_info_file)
    for ip, device_info in train_ips_device_info.items():
        test_ips_devices_info[ip] = [device_info]
    store_json(test_ips_devices_info, LABEL_IPS_DEVICES_INFO_FILE)


def mix_test_ips_devices_info():
    """
    ??????ip??????????????????????????????"192.168.0.255"??????
    :return:
    """
    test_ips_devices_info = load_json(LABEL_IPS_DEVICES_INFO_FILE)
    test_nat_ip_devices_info = {NAT_IP: list()}
    for ip, devices_info in test_ips_devices_info.items():
        for device_info in devices_info:
            test_nat_ip_devices_info[NAT_IP].append(device_info)
    store_json(test_nat_ip_devices_info, os.path.join(LABEL_DATA_FOLDER_NAME, "finder_2019_09_NAT" + ".json"))


def get_devices_thetas_performance():
    """
    ???????????????????????????????????????????????????????????????????????????
    :return:
    """
    LABEL_RESULT_FOLDER_NAME = os.path.join("label_result", "finder")
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
    # ????????????device????????????????????????????????????ip???
    devices_appearance_num = dict()
    for file_index in LABEL_DAYS:
        test_ips_devices_info_file = os.path.join(LABEL_DATA_FOLDER_NAME, "finder_2019_08_" + str(file_index) + ".json")
        test_ips_devices_info = load_json(test_ips_devices_info_file)
        for ip, devices_info in test_ips_devices_info.items():
            for device_info in devices_info:
                devices_appearance_num[device_info["device"]] = devices_appearance_num.get(device_info["device"], 0) + 1
    # pprint(devices_appearance_num)

    # ????????????
    for theta in np.arange(THETA_LOW, THETA_HIGH + THETA_STEP, THETA_STEP):
        theta_str = str(theta)[:THETA_STR_LENGTH]
        for file_index in LABEL_DAYS:
            test_ips_devices_info_file = os.path.join(LABEL_DATA_FOLDER_NAME,
                                                      "finder_2019_08_" + str(file_index) + ".json")
            test_ips_devices_info = load_json(test_ips_devices_info_file)
            file_name = os.path.join(LABEL_RESULT_FOLDER_NAME, "finder_2019_08_" + str(file_index),
                                     "test_ips_possible_devices_similarity.json")
            test_ips_possible_devices_similarity = load_json(file_name)
            for test_ip, possible_devices_similarity in test_ips_possible_devices_similarity.items():
                test_ip_devices = [test_ips_devices_info[test_ip][i]["device"] for i in
                                   range(len(test_ips_devices_info[test_ip]))]
                # ???possible_devices_similarity??????????????????????????????????????????????????????????????????
                # for possible_device, similarity in possible_devices_similarity.items():
                possible_devices_similarity = get_highest_val_from_instances(possible_devices_similarity)
                for possible_device, similarity in possible_devices_similarity.items():
                    if similarity >= (theta - 0.0000000000000010):
                        if possible_device in test_ip_devices:
                            devices_thetas_performance[possible_device][theta_str]["tp"] += 1
                        else:
                            devices_thetas_performance[possible_device][theta_str]["fp"] += 1
        for device in devices_appearance_num.keys():
            devices_thetas_performance[device][theta_str]["fn"] = \
                devices_appearance_num[device] - devices_thetas_performance[device][theta_str]["tp"]

    # ??????precision, recall, F0.5, F1, F2
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

    # ????????????device?????????theta?????????precision, recall, F0.5, F1, F2
    for device in devices_list:
        device_thetas_performance_filename = os.path.join(DEVICES_PERFORMANCE_FOLDER_NAME, device + ".json")
        store_json(devices_thetas_performance[device], device_thetas_performance_filename)


def get_devices_best_theta_performance():
    """
    ??????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????
    :return:
    """
    devices_best_theta_performance = dict()
    devices_list = get_devices_list(TOTAL_IPS_DEVICES_INFO_FILE)
    # devices_list = ["Google OnHub", "Nest Camera", "Belkin WeMo Motion Sensor", "LIFX Virtual Bulb", "Roku TV", "Roku4",
    #            "Amazon Fire TV", "Apple HomePod", "Google Home Hub", "Sonos Beam"]
    for device in devices_list:
        if os.path.exists(os.path.join(DEVICES_PERFORMANCE_FOLDER_NAME, device + ".json")):
            device_performance = load_json(os.path.join(DEVICES_PERFORMANCE_FOLDER_NAME, device + ".json"))
            # theta = get_key_by_max_value(device_performance, "F1")  # ???????????????F1???????????????????????????
            theta = get_key_by_max_value(device_performance, "F2")  # ???????????????F2???????????????????????????
            devices_best_theta_performance[device] = {
                "theta": theta,
                "precision": device_performance[theta]["precision"],
                "recall": device_performance[theta]["recall"],
                "F0.5": device_performance[theta]["F0.5"],
                "F1": device_performance[theta]["F1"],
                "F2": device_performance[theta]["F2"]
            }
    # store_json(devices_best_theta_performance, DEVICES_BEST_THETA_PERFORMANCE_FILE)
    # ????????????????????????MongoDB??????DEVICES_KNOWLEDGE_COL??????????????????
    for device in devices_list:
        for i in TRAIN_DAYS:
            DEVICES_KNOWLEDGE_COL.update_one({"device": device + "_" + str(i)},
                                             {"$set": {"threshold": devices_best_theta_performance[device]["theta"]}},
                                             upsert=False)
    logger.info("????????????????????????")
    return devices_best_theta_performance


@calc_method_time
def main():
    global LABEL_TARGET_NAME, LABEL_PCAP_FILE, LABEL_IPS_DEVICES_INFO_FILE, LABEL_RESULT_FOLDER_NAME, ALL_THETAS_PERFORMANCE_FILE, LABEL_IPS_DOMAINS_REGULARITY_SCORE_FILE, LABEL_IPS_DOMAINS_PKTS_TIME_FILE, LABEL_IPS_OTHER_DOMAINS_FILE, LABEL_IPS_PERFORMANCE_FILE, LABEL_IPS_POSSIBLE_DEVICES_FILE, LABEL_IPS_POSSIBLE_DEVICES_SIMILARITY_FILE, LABEL_IPS_REPORT_FILE, LABEL_IPS_INFO_FILE
    for file_index in LABEL_DAYS:
        # 0. ????????????
        LABEL_TARGET_NAME = "finder_2019_08_" + str(file_index)
        # LABEL_TARGET_NAME = "finder_2019_08_" + str(file_index) + "_NAT"
        LABEL_PCAP_FILE = os.path.join(LABEL_DATA_FOLDER_NAME, LABEL_TARGET_NAME + ".pcap")
        # LABEL_PCAP_FILE = os.path.join(LABEL_DATA_FOLDER_NAME, LABEL_TARGET_NAME.replace("_NAT", "") + ".pcap")
        LABEL_IPS_DEVICES_INFO_FILE = os.path.join(LABEL_DATA_FOLDER_NAME, LABEL_TARGET_NAME + ".json")
        # res??????????????????????????????????????????????????????
        LABEL_RESULT_FOLDER_NAME = os.path.join("label_result", "finder", LABEL_TARGET_NAME)
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

        # 1. ??????????????????test_ips_devices_info?????????
        # get_test_ips_devices_info(LABEL_IPS_DEVICES_INFO_FILE)  # ????????????????????????

    # 2. ???????????????????????????????????????
    #     mkdir_if_not_exist(LABEL_RESULT_FOLDER_NAME)
    #
        # 3. ????????????pcap
        # get_test_ips_info(LABEL_PCAP_FILE, is_nat=False)  # ????????????????????????ip???domain tf-idf??????????????????ip??????????????????
        # get_test_ips_info(LABEL_PCAP_FILE, is_nat=True)  # ????????????????????????ip???domain tf-idf???????????????NAT??????
        get_test_ips_possible_devices()  # ?????????????????????ip?????????domain??????????????????????????????????????????????????????????????????ip?????????????????????
        get_test_ips_possible_devices_similarity()  # ????????????????????????ip?????????????????????????????????tf-idf?????????

    get_devices_thetas_performance()

    get_devices_best_theta_performance()


if __name__ == '__main__':
    main()
