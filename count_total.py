import random
from pprint import pprint

from constants import *
from utils import *
import matplotlib.pyplot as plt
from star_query import *

TEST_IPS_REGULAR_DOMAINS_TFIDF_RATIO_FILE = os.path.join(ALL_RESULT_FOLDER_NAME,
                                                         "test_ips_regular_domains_tfidf_ratio.json")
DEVICES_REGULAR_DOMAINS_TFIDF_RATIO_FILE = os.path.join(ALL_RESULT_FOLDER_NAME,
                                                        "devices_regular_domains_tfidf_ratio.json")
DEVICES_REGULAR_DOMAINS_TFIDF_RATIO_PICTURE = os.path.join(ALL_RESULT_FOLDER_NAME,
                                                           "devices_regular_domains_tfidf_ratio")
DEVICES_SIMILARITY_FOR_PICTURE_FILE = os.path.join(ALL_RESULT_FOLDER_NAME,
                                                   "devices_similarity_for_picture.json")
DEVICES_SIMILARITY_FOR_PICTURE_PICTURE = os.path.join(ALL_RESULT_FOLDER_NAME,
                                                      "devices_similarity_for_picture")

THETA_COEFFICIENTS_PERFORMANCE_FILE = os.path.join(ALL_RESULT_FOLDER_NAME, "theta_coefficients_performance.json")


def get_test_ips_regular_domains_tfidf_ratio():
    test_ips_domains_regularity_score = load_json(TEST_IPS_DOMAINS_REGULARITY_SCORE_FILE)
    test_ips_domains_tfidf = load_json(TEST_IPS_INFO_FILE, "ips_domains_tfidf")
    test_ips_regular_domains_tfidf_ratio = dict()
    for ip, domains_regularity in test_ips_domains_regularity_score.items():
        tfidf_sum = 0
        for domain, tfidf in test_ips_domains_tfidf[ip].items():
            tfidf_sum += tfidf
        regular_tfidf_sum = 0
        for domain, regularity in domains_regularity.items():
            if regularity >= REGULARITY_THRESHOLD:
                regular_tfidf_sum += test_ips_domains_tfidf[ip][domain]
        test_ips_regular_domains_tfidf_ratio[ip] = regular_tfidf_sum / tfidf_sum

    store_json(test_ips_regular_domains_tfidf_ratio, TEST_IPS_REGULAR_DOMAINS_TFIDF_RATIO_FILE)


def get_devices_regular_domains_tfidf_ratio():
    """
    获取各个设备规律域名TF-IDF值所占比例
    :return:
    """
    test_ips_devices_info = load_json(TEST_IPS_DEVICES_INFO_FILE)
    test_ips_domains_regularity_score = load_json(TEST_IPS_DOMAINS_REGULARITY_SCORE_FILE)
    test_ips_domains_tfidf = load_json(TEST_IPS_INFO_FILE, "ips_domains_tfidf")
    devices_regular_domains_tfidf_ratio = dict()
    for ip, domains_regularity in test_ips_domains_regularity_score.items():
        tfidf_sum = 0
        for domain, tfidf in test_ips_domains_tfidf[ip].items():
            tfidf_sum += tfidf
        regular_tfidf_sum = 0
        for domain, regularity in domains_regularity.items():
            if regularity >= REGULARITY_THRESHOLD:
                regular_tfidf_sum += test_ips_domains_tfidf[ip][domain]
        devices_regular_domains_tfidf_ratio[test_ips_devices_info[ip][0]["device"]] = regular_tfidf_sum / tfidf_sum

    store_json(devices_regular_domains_tfidf_ratio, DEVICES_REGULAR_DOMAINS_TFIDF_RATIO_FILE)


def draw_dns_behaviors():
    """
    画出各个设备访问域名的散点图，即论文图1
    :return:
    """
    # ips_domains_pkts_time = load_json(TEST_IPS_DOMAINS_PKTS_TIME_FILE, "ips_domains_pkts_time")
    # train_ips_device_info = load_json(TRAIN_IPS_DEVICE_INFO_FILE)
    ips_domains_pkts_time = load_json(
        os.path.join(TEST_RESULT_FOLDER_NAME, "arunan_dns_1", "test_ips_domains_pkts_time.json"),
        "ips_domains_pkts_time")
    train_ips_device_info = load_json(os.path.join(TRAIN_DATA_FOLDER_NAME, "arunan_dns_23-30" + ".json"))
    description_list = list()
    i = 0
    for ip, domains_time in ips_domains_pkts_time.items():
        device = train_ips_device_info[ip]["device"]
        i += 1
        for domain, time_list in domains_time.items():
            hour_time_list = [time / 3600 for time in set(time_list)]
            dots_num = len(hour_time_list)
            plt.scatter(hour_time_list, [(str(i) + ":" + domain) for j in range(dots_num)])
        description_list.append(str(i) + ":" + device)
    print(", ".join(description_list))

    plt.rcParams['savefig.dpi'] = 500  # 图片像素
    plt.rcParams['figure.dpi'] = 500  # 分辨率
    plt.yticks(fontsize=8)
    # plt.title("DNS behavior of IoT devices")
    # plt.xlabel("hour of the day")
    # plt.ylabel("IoT domain name")
    plt.title("物联网设备的DNS查询行为")
    plt.xlabel("一天中的时间")
    plt.ylabel("查询域名")
    plt.tight_layout()
    x_major_locator = plt.MultipleLocator(2)
    ax = plt.gca()
    # ax为两条坐标轴的实例
    ax.xaxis.set_major_locator(x_major_locator)
    plt.savefig(os.path.join(ALL_RESULT_FOLDER_NAME, "dns_behavior.png"))
    plt.savefig(os.path.join(ALL_RESULT_FOLDER_NAME, "dns_behavior.svg"), format="svg")
    plt.show()


def draw_histogram(data_dict, fig_path):
    """
    根据传入字典来画水平的直方图
    :param data_dict: 传入字典
    :param fig_path: 保存的图片路径
    :return:
    """
    devices = list(data_dict.keys())
    scores = list(data_dict.values())
    plt.rcParams['savefig.dpi'] = 800  # 图片像素
    plt.rcParams['figure.dpi'] = 800  # 分辨率

    # plt.barh(devices, scores, color="green")
    # # plt.title("Matching Results")
    # plt.title("匹配结果")

    plt.barh(devices, scores, color="steelblue")

    plt.yticks(fontsize=4)
    plt.xticks()
    # plt.xlabel("similarity score")
    # plt.xlabel("相似度得分")
    # plt.xlabel("TF-IDF Ratio of Regular Domain Names")
    # plt.xlabel("规律域名TF-IDF值所占比例")
    plt.ylabel("device")
    # plt.ylabel("设备")
    plt.tight_layout()
    plt.savefig(fig_path + ".png")
    plt.savefig(fig_path + ".svg", format="svg")
    plt.show()


def get_devices_similarity_for_picture():
    devices_similarity_for_picture = dict()
    # test_ips_report = load_json(TEST_IPS_REPORT_FILE)
    test_ips_report = load_json(os.path.join("test_result", "finder_09_1", "test_ips_report.json"))
    i = 0
    devices_list = ["Amazon Echo Gen1", "Apple HomePod", "Apple TV (4thGen)", "Belkin WeMo Crockpot",
                    "Belkin WeMo Motion Sensor",
                    "Belkin WeMo Switch", "Google Home Mini", "Google Home", "Roku4", "Sonos Beam"]
    device_ip_map = dict()
    total_test_ips_devices_info = load_json(TOTAL_IPS_DEVICES_INFO_FILE)
    for device in devices_list:
        for ip, device_info in total_test_ips_devices_info.items():
            if device_info["device"] == device:
                device_ip_map[device] = ip
    for device, ip in device_ip_map.items():
        report = test_ips_report[ip]
        i += 1
        for possible_device, similarity in report["possible_devices_similarity"].items():
            devices_similarity_for_picture[str(i) + ":" + possible_device] = similarity
        devices_similarity_for_picture[device] = 0
        devices_similarity_for_picture[" " * i] = 0
    store_json(devices_similarity_for_picture, DEVICES_SIMILARITY_FOR_PICTURE_FILE)


def draw_devices_best_theta_performance():
    devices_performance = load_json(DEVICES_PERFORMANCE_FILE)
    # devices_list = ["Google OnHub", "Nest Camera", "Belkin WeMo Motion Sensor", "LIFX Virtual Bulb", "Roku TV", "Roku4",
    #                 "Amazon Fire TV", "Apple HomePod", "Google Home Hub", "Sonos Beam"]
    devices_list = ["Amazon Echo Gen1", "Apple HomePod", "Apple TV (4thGen)", "Belkin WeMo Crockpot",
                    "Belkin WeMo Motion Sensor",
                    "Belkin WeMo Switch", "Google Home Mini", "Google Home", "Roku4", "Sonos Beam"]
    devices = list()
    thetas = list()
    precisions = list()
    recalls = list()
    f2s = list()
    for device in devices_list:
        devices.append(device)
        performance = devices_performance[device]
        thetas.append(float(performance["theta"]))
        precisions.append(performance["precision"])
        recalls.append(performance["recall"])
        f2s.append(performance["F2"])

    device_width = 3
    bar_width = 0.5
    x_1 = list(range(0, device_width * len(devices), device_width))
    x_2 = [i + 1 * bar_width for i in x_1]
    x_3 = [i + 2 * bar_width for i in x_1]
    x_4 = [i + 3 * bar_width for i in x_1]

    # # 设置图形大小
    # plt.figure(figsize=(20, 8), dpi=20)
    # plt.title("Performance")

    # 设置x轴的刻度
    plt.xticks([i + bar_width * 1.5 for i in x_1], devices, rotation=45, fontsize=6)

    # plt.bar(x_1, thetas, width=bar_width, label="theta", color="sienna")
    # plt.bar(x_2, precisions, width=bar_width, label="precision", color="darkorange")
    # plt.bar(x_3, recalls, width=bar_width, label="recall", color="steelblue")
    # plt.bar(x_4, f2s, width=bar_width, label="F2", color="green")
    plt.bar(x_1, thetas, width=bar_width, label="识别阈值", color="sienna")
    plt.bar(x_2, precisions, width=bar_width, label="精确率", color="darkorange")
    plt.bar(x_3, recalls, width=bar_width, label="查全率", color="steelblue")
    plt.bar(x_4, f2s, width=bar_width, label="F2分数", color="green")

    plt.legend(bbox_to_anchor=(1, 1))
    # plt.legend()
    plt.tight_layout()
    fig_path = os.path.join(ALL_RESULT_FOLDER_NAME, "devices_best_theta_performance.png")
    fig_path = os.path.join(ALL_RESULT_FOLDER_NAME, "devices_best_theta_performance.svg")
    plt.savefig(fig_path, format='svg')

    # 展示
    plt.show()


def get_test_ips_devices_info_by_test_ips_info():
    """
    获取每个测试文件的描述文件，从all_ips_devices_info中获取该测试文件中出现的ip的设备信息
    :return:
    """
    all_ips_devices_info = load_json(os.path.join("train_data", "finder_08_500000.json"))
    for file_index in range(LABEL_FILE_LOW, LABEL_FILE_HIGH + 1):
        test_ips_devices_info = dict()
        # test_ips_devices_info = {NAT_IP: list()}
        test_ips_info_file = os.path.join("label_result", "finder_08_" + str(file_index), "test_ips_info.json")
        # test_ips_info_file = os.path.join("label_result", "finder_08_" + str(file_index) + "_NAT", "test_ips_info.json")
        test_ips = load_json(test_ips_info_file, "ips_domains_tfidf").keys()
        for ip in test_ips:
            test_ips_devices_info[ip] = [
                all_ips_devices_info[ip]
            ]
            # test_ips_devices_info[NAT_IP].append(all_ips_devices_info[ip])  # NAT下，让NAT_IP保存所有IP的设备信息
        store_json(test_ips_devices_info,
                   os.path.join(LABEL_DATA_FOLDER_NAME, "finder_08_" + str(file_index) + ".json"))
        # store_json(test_ips_devices_info,
        #            os.path.join(LABEL_DATA_FOLDER_NAME, "finder_08_" + str(file_index) + "_NAT" + ".json"))


def get_average_performance_nat():
    devices_performance = load_json(DEVICES_PERFORMANCE_FILE)
    theta_coefficients_performance = dict()
    theta_coefficient_low = 0.7
    theta_coefficient_high = 1
    theta_coefficient_step = 0.01
    for theta_coefficient in np.arange(theta_coefficient_low, theta_coefficient_high, theta_coefficient_step):
        fixed_devices_theta = dict()
        for device, theta_performance in devices_performance.items():
            fixed_devices_theta[device] = float(theta_performance["theta"]) * theta_coefficient

        ips_tp = 0
        ips_fp = 0
        ips_fn = 0

        for file_index in range(1, TEST_PCAPS_NUM + 1):
            # 对于每一个测试文件
            # 一些常量
            test_target_name = "finder_09_" + str(file_index) + "_NAT"
            test_ips_devices_info_file = os.path.join(TEST_DATA_FOLDER_NAME, test_target_name + ".json")
            test_ips_devices_info = load_json(test_ips_devices_info_file)
            test_result_folder_name = os.path.join("test_result", test_target_name)
            test_ips_possible_devices_similarity_file = os.path.join(test_result_folder_name,
                                                                     "test_ips_possible_devices_similarity.json")
            test_ips_possible_devices_similarity = load_json(test_ips_possible_devices_similarity_file)

            for test_ip, possbile_devices_similarity in test_ips_possible_devices_similarity.items():
                # 对于每一个测试ip
                tp = 0
                fp = 0
                test_ip_devices = [test_ips_devices_info[test_ip][i]["device"] for i in
                                   range(len(test_ips_devices_info[test_ip]))]
                test_ip_devices_info_num = len(test_ip_devices)
                for possible_device, similarity in possbile_devices_similarity.items():
                    if similarity >= fixed_devices_theta[possible_device]:
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
        theta_coefficients_performance[str(theta_coefficient)[:THETA_STR_LENGTH]] = {
            "precision": precision,
            "recall": recall,
            "F0.5": f_05,
            "F1": f_1,
            "F2": f_2
        }
    store_json(theta_coefficients_performance, THETA_COEFFICIENTS_PERFORMANCE_FILE)


def base_draw_lines(data_dict, y_string_length, x_label, fig_path, targets=None, title=None):
    """
    需要传入的是类似以下的结构
    "0.0": {
        "precision": 0.9398758727695888,
        "recall": 0.9901920719248059,
        "F0.5": 0.9495258249079082,
        "F1": 0.9643781094527363,
        "F2": 0.9797024098334142
    },
    :return:
    """
    line_patterns = ['r-', 'g--', 'b:', "c-.", "m."]

    if targets is None:
        for x, y_s in data_dict.items():
            targets = list(y_s.keys())
            break
    x_s = list()
    x_string_length = 0
    for x, y_s in data_dict.items():
        x_string_length = max(x_string_length, len(x))
    for x, y_s in data_dict.items():
        x_s.append(float(x[:x_string_length]))

    for i, target in enumerate(targets):
        y_s = list()
        for x in data_dict.keys():
            y_s.append(data_dict[x][target])
        if title:
            plt.title(title)
        plt.xlabel(x_label)
        max_y = max(y_s)
        max_index = y_s.index(max_y)
        max_x = x_s[max_index]
        show_max = "(" + str(max_x) + ", " + str(max_y)[:y_string_length] + ")"
        plt.annotate(show_max, xytext=(max_x, max_y), xy=(max_x, max_y), )
        # plt.plot(x_s, y_s, line_patterns[i], label=target)
        plt.plot(x_s, y_s, line_patterns[i], label=LANGUAGE_MAP[target])
    plt.legend()
    plt.tight_layout()
    if fig_path.endswith(".svg"):
        plt.savefig(fig_path, format='svg')
    else:
        plt.savefig(fig_path)
    plt.show()


def draw_theta_coefficients_performance():
    """
    画出在不同阈值系数下的NAT识别情况
    :return:
    """
    theta_coefficients_performance = load_json(THETA_COEFFICIENTS_PERFORMANCE_FILE)
    y_string_length = 6
    # title = "Performance Under Different Coefficients"
    # x_label = "coefficient"
    # title = "Performance Under Different Coefficients"
    x_label = "阈值系数"
    fig_path = os.path.join(ALL_RESULT_FOLDER_NAME, "theta_coefficients_performance.png")
    base_draw_lines(theta_coefficients_performance, y_string_length, x_label, fig_path,
                    targets=["precision", "recall", "F2"], title=None)
    fig_path = os.path.join(ALL_RESULT_FOLDER_NAME, "theta_coefficients_performance.svg")
    base_draw_lines(theta_coefficients_performance, y_string_length, x_label, fig_path,
                    targets=["precision", "recall", "F2"], title=None)


def get_average_performance():
    devices_performance = load_json(DEVICES_PERFORMANCE_FILE)
    precision_sum = 0
    recall_sum = 0
    f05_sum = 0
    f1_sum = 0
    f2_sum = 0
    device_count = 0
    for device, performance in devices_performance.items():
        if device not in ["Chinese Webcam", "Insteon Hub", "Koogeek Light bulb", "Piper NV", "Wink Hub"]:
            device_count += 1
            precision_sum += performance["precision"]
            recall_sum += performance["recall"]
            f05_sum += performance["F0.5"]
            f1_sum += performance["F1"]
            f2_sum += performance["F2"]
    return precision_sum / device_count, recall_sum / device_count, f05_sum / device_count, f1_sum / device_count, f2_sum / device_count


def get_devices_performance():
    """
    获取每个设备在最佳阈值下的表现
    :return:
    """
    devices_list = get_devices_list(TOTAL_IPS_DEVICES_INFO_FILE)
    devices_threshold = get_mongodb_devices_threshold()
    devices_performance = dict()
    for device in devices_list:
        devices_performance[device] = {
            "theta": devices_threshold[device],
            "tp": 0,
            "fp": 0,
            "fn": 0
        }
    # 先得到某device在所有的测试样本中出现的ip数
    devices_appearance_num = dict()
    for file_index in range(TEST_FILE_LOW, TEST_FILE_HIGH + 1):
        test_ips_devices_info_file = os.path.join(TEST_DATA_FOLDER_NAME, "finder_09_" + str(file_index) + ".json")
        test_ips_devices_info = load_json(test_ips_devices_info_file)
        for ip, devices_info in test_ips_devices_info.items():
            for device_info in devices_info:
                devices_appearance_num[device_info["device"]] = devices_appearance_num.get(device_info["device"], 0) + 1
    # pprint(devices_appearance_num)

    # 得出结果
    for file_index in range(TEST_FILE_LOW, TEST_FILE_HIGH + 1):
        test_ips_devices_info_file = os.path.join(TEST_DATA_FOLDER_NAME, "finder_09_" + str(file_index) + ".json")
        test_ips_devices_info = load_json(test_ips_devices_info_file)
        file_name = os.path.join(TEST_RESULT_FOLDER_NAME, "finder_09_" + str(file_index),
                                 "test_ips_possible_devices_similarity.json")
        test_ips_possible_devices_similarity = load_json(file_name)
        for test_ip, possible_devices_similarity in test_ips_possible_devices_similarity.items():
            test_ip_devices = [test_ips_devices_info[test_ip][i]["device"] for i in
                               range(len(test_ips_devices_info[test_ip]))]
            for possible_device, similarity in possible_devices_similarity.items():
                if similarity >= (devices_threshold[possible_device] - 0.0000000000000010):
                    if possible_device in test_ip_devices:
                        devices_performance[possible_device]["tp"] += 1
                    else:
                        devices_performance[possible_device]["fp"] += 1
    for device in devices_appearance_num.keys():
        devices_performance[device]["fn"] = \
            devices_appearance_num[device] - devices_performance[device]["tp"]

    # 计算precision, recall, F0.5, F1, F2
    for device, performance in devices_performance.items():
        tp = performance["tp"]
        fp = performance["fp"]
        fn = performance["fn"]
        if tp == 0:
            devices_performance[device]["precision"] = 0
            devices_performance[device]["recall"] = 0
            devices_performance[device]["F0.5"] = 0
            devices_performance[device]["F1"] = 0
            devices_performance[device]["F2"] = 0
        else:
            precision = tp / (tp + fp)
            recall = tp / (tp + fn)
            devices_performance[device]["precision"] = precision
            devices_performance[device]["recall"] = recall
            devices_performance[device]["F0.5"] = (1.25 * precision * recall) / (0.25 * precision + recall)  # F0.5
            devices_performance[device]["F1"] = (2 * precision * recall) / (precision + recall)  # F1
            devices_performance[device]["F2"] = (5 * precision * recall) / (4 * precision + recall)  # F2

    # 存储各个device中对应的precision, recall, F0.5, F1, F2
    store_json(devices_performance, DEVICES_PERFORMANCE_FILE)


def main():
    # 画出各个设备访问域名的散点图，即论文图1
    # draw_dns_behaviors()

    # 画出10个设备的相似情况
    # get_devices_similarity_for_picture()
    # devices_similarity_for_picture = load_json(DEVICES_SIMILARITY_FOR_PICTURE_FILE)
    # draw_histogram(devices_similarity_for_picture, DEVICES_SIMILARITY_FOR_PICTURE_PICTURE)

    # 10设备的一张图
    # draw_devices_best_theta_performance()

    # 画出在不同阈值系数下的NAT识别情况
    # draw_theta_coefficients_performance()

    # 获取各个设备规律域名TF-IDF值所占比例
    # get_test_ips_regular_domains_tfidf_ratio()
    # get_devices_regular_domains_tfidf_ratio()
    devices_regular_domains_tfidf_ratio = load_json(DEVICES_REGULAR_DOMAINS_TFIDF_RATIO_FILE)
    draw_histogram(devices_regular_domains_tfidf_ratio, DEVICES_REGULAR_DOMAINS_TFIDF_RATIO_PICTURE)

    # get_test_ips_devices_info_by_test_ips_info()

    # get_devices_performance()  # 获取每个设备在最佳阈值下的表现
    #
    # average_precision, average_recall, average_f05, average_f1, average_f2 = get_average_performance()
    # print(average_precision, average_recall, average_f05, average_f1, average_f2)

    # get_average_performance_nat()

    pass


if __name__ == '__main__':
    main()
