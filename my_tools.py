from utils import *

DOMAINS_WHOIS_INFO_FILE = "res/domains_whois_info.json"
DOMAINS_GOOGLE_FILE = "res/domains_google.json"
DOMAINS_VENDORS_GOOGLE_FILE = "res/domains_vendors_google.json"


def get_delta_list(input_list):
    return [input_list[i + 1] - input_list[i] for i in range(len(input_list) - 1)]


def get_time_list_regularity_score():
    """
    获取各个ip的域名的规律得分数据
    :return:
    """
    time_list = [0, 50, 300, 351, 601, 653, 903, 954]
    if len(time_list) < 3:  # 低于3就不能得到二次差值序列了
        return 0
    else:
        first_delta_time_list = get_delta_list(time_list)
        sorted_first_delta_time_list = sorted(first_delta_time_list)
        second_delta_time_list = get_delta_list(sorted_first_delta_time_list)
        print("time_list: ", time_list)
        print("first_delta_time_list: ", first_delta_time_list)
        print("sorted_first_delta_time_list: ", sorted_first_delta_time_list)
        print("second_delta_time_list: ", second_delta_time_list)
        near_count = 0
        for delta in second_delta_time_list:
            if delta <= REGULARITY_DELTA_TIME:
                near_count += 1
        print(len(second_delta_time_list))
        print(near_count)
        score = near_count / len(second_delta_time_list)
        print(score)
        return score


def get_test_ips_domains_regularity_score(test_ips_domains_pkts_time_file, test_ips_domains_regularity_score_file):
    """
    获取各个ip的域名的规律得分数据
    :return:
    """
    # ips_domains_time_list = load_json(TEST_IPS_DOMAINS_PKTS_TIME_FILE, "ips_domains_pkts_time")
    ips_domains_time_list = load_json(test_ips_domains_pkts_time_file, "ips_domains_pkts_time")
    test_ips_domains_regularity_score = dict()
    for ip, domains_time_list in ips_domains_time_list.items():
        test_ips_domains_regularity_score[ip] = dict()
        for domain, time_list in domains_time_list.items():
            time_list = list(set(time_list))  # 需要对时间进行去重
            if len(time_list) < 3:  # 低于3就不能得到二次差值序列了
                test_ips_domains_regularity_score[ip][domain] = 0
            else:
                first_delta_time_list = get_delta_list(time_list)
                second_delta_time_list = get_delta_list(sorted(first_delta_time_list))
                # print(time_list)
                # print(first_delta_time_list)
                # print(second_delta_time_list)
                near_count = 0
                for delta in second_delta_time_list:
                    if delta <= REGULARITY_DELTA_TIME:
                        near_count += 1
                # print(len(second_delta_time_list))
                # print(near_count)
                score = near_count / len(second_delta_time_list)
                # print(score)
                test_ips_domains_regularity_score[ip][domain] = score
        test_ips_domains_regularity_score[ip] = get_sorted_dict(test_ips_domains_regularity_score[ip],
                                                                compared_target="value")
    # pprint(test_ips_domains_regularity_score)
    # store_json(test_ips_domains_regularity_score, TEST_IPS_DOMAINS_REGULARITY_SCORE_FILE)
    store_json(test_ips_domains_regularity_score, test_ips_domains_regularity_score_file)
    return test_ips_domains_regularity_score


def main():
    get_time_list_regularity_score()
    # get_test_ips_domains_regularity_score()  # 获取各个ip的域名的规律得分数据
    # detect_domain()


if __name__ == '__main__':
    main()
