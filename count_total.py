import random

import matplotlib.pyplot as plt
from star_query import *
import matplotlib as mpl
from my_tools import *

FIGURE_LANGUAGE_CN = True
# FIGURE_LANGUAGE_CN = False

if FIGURE_LANGUAGE_CN:
    mpl.rcParams['font.sans-serif'] = ['SimHei', 'KaiTi', 'FangSong']
    mpl.rcParams['font.size'] = 12  # 字体大小
    mpl.rcParams['axes.unicode_minus'] = False  # 正常显示负号

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


def get_test_ips_regular_domains_tfidf_ratio(test_ips_domains_regularity_score_file,
                                             test_ips_regular_domains_tfidf_ratio_file):
    test_ips_domains_regularity_score = load_json(test_ips_domains_regularity_score_file)
    test_ips_domains_tfidf = load_json(
        os.path.join(os.path.dirname(test_ips_domains_regularity_score_file), "test_ips_info.json"),
        "ips_domains_tfidf")
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

    store_json(test_ips_regular_domains_tfidf_ratio, test_ips_regular_domains_tfidf_ratio_file)


def get_devices_regular_domains_tfidf_ratio(test_ips_domains_regularity_score_file,
                                            devices_regular_domains_tfidf_ratio_file):
    """
    获取各个设备规律域名TF-IDF值所占比例
    :return:
    """
    test_ips_devices_info = load_json(TOTAL_IPS_DEVICES_INFO_FILE)
    test_ips_domains_regularity_score = load_json(test_ips_domains_regularity_score_file)
    test_ips_domains_tfidf = load_json(
        os.path.join(os.path.dirname(test_ips_domains_regularity_score_file), "test_ips_info.json"),
        "ips_domains_tfidf")
    devices_regular_domains_tfidf_ratio = dict()
    for ip, domains_regularity in test_ips_domains_regularity_score.items():
        device = test_ips_devices_info[ip]["device"]
        tfidf_sum = 0
        for domain, tfidf in test_ips_domains_tfidf[ip].items():
            tfidf_sum += tfidf
        regular_tfidf_sum = 0
        for domain, regularity in domains_regularity.items():
            if regularity >= REGULARITY_THRESHOLD:
                regular_tfidf_sum += test_ips_domains_tfidf[ip][domain]
        ratio = regular_tfidf_sum / tfidf_sum
        if device in ["Apple HomePod", "Apple TV (4thGen)", "Belkin WeMo Crockpot", "Google Home Mini",
                      "Roku4"] or (random.randint(0, 10) > 8 and ratio >= 0):
            devices_regular_domains_tfidf_ratio[device] = ratio
        # devices_regular_domains_tfidf_ratio[device] = ratio
    store_json(devices_regular_domains_tfidf_ratio, devices_regular_domains_tfidf_ratio_file)


def draw_dns_behaviors():
    """
    画出各个设备访问域名的散点图，即论文图1
    :return:
    """
    figure_name = "dns_behavior"
    if FIGURE_LANGUAGE_CN:
        # plt.title("物联网设备的DNS查询行为")
        plt.xlabel("一天中的时间")
        plt.ylabel("查询域名")
        figure_name += "_cn"
    else:
        # plt.title("DNS behavior of IoT devices")
        plt.xlabel("hour of the day")
        plt.ylabel("IoT domain name")
    # ips_domains_pkts_time = load_json(TEST_IPS_DOMAINS_PKTS_TIME_FILE, "ips_domains_pkts_time")
    # train_ips_device_info = load_json(TRAIN_IPS_DEVICE_INFO_FILE)
    # showed_ip = ["192.168.1.163", "192.168.1.193", "192.168.1.223", "192.168.1.227", "192.168.1.240", "192.168.1.241",
    #              "192.168.1.249"]  # UNSW
    showed_devices_list = ["Securifi Almond", "LG WebOS TV", "PlayStation 4", "Ring Doorbell"]  # finder
    ips_domains_pkts_time = load_json(
        os.path.join("test_result", "finder", "finder_2019_09_1", "test_ips_domains_pkts_time.json"),
        "ips_domains_pkts_time")
    train_ips_device_info = load_json(TOTAL_IPS_DEVICES_INFO_FILE)
    description_list = list()
    i = 0
    for ip, domains_time in ips_domains_pkts_time.items():
        # if ip in showed_ip:
        if train_ips_device_info[ip]["device"] in showed_devices_list:
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
    plt.yticks(fontsize=9)
    plt.tight_layout()
    x_major_locator = plt.MultipleLocator(2)
    ax = plt.gca()
    # ax为两条坐标轴的实例
    ax.xaxis.set_major_locator(x_major_locator)
    plt.savefig(os.path.join(ALL_RESULT_FOLDER_NAME, figure_name + ".png"))
    plt.savefig(os.path.join(ALL_RESULT_FOLDER_NAME, figure_name + ".svg"), format="svg")
    plt.show()


def draw_histogram(data_dict, fig_path, pic):
    """
    根据传入字典来画水平的直方图
    :param data_dict: 传入字典
    :param fig_path: 保存的图片路径
    :param pic: 1为5个设备的相似情况，2为规律域名TF-IDF所占比例
    :return:
    """
    if FIGURE_LANGUAGE_CN:
        if pic == 1:
            plt.xlabel("相似度")
        elif pic == 2:
            plt.ylabel("设备")
            plt.xlabel("规律域名TF-IDF值所占比例")
        fig_path += "_cn"
    else:
        if pic == 1:
            plt.xlabel("similarity")
        elif pic == 2:
            plt.ylabel("device")
            plt.xlabel("TF-IDF Ratio of Regular Domain Names")

    if pic == 1:
        color = "green"
    elif pic == 2:
        color = "steelblue"
    devices = list(data_dict.keys())
    scores = list(data_dict.values())
    plt.rcParams['savefig.dpi'] = 800  # 图片像素
    plt.rcParams['figure.dpi'] = 800  # 分辨率

    plt.barh(devices, scores, color=color)

    plt.yticks(fontsize=10)
    plt.xticks()

    plt.tight_layout()
    plt.savefig(fig_path + ".png")
    plt.savefig(fig_path + ".svg", format="svg")
    plt.show()


def get_devices_similarity_for_picture():
    devices_similarity_for_picture = dict()

    # test_ips_possible_devices_similarity = load_json(TEST_IPS_REPORT_FILE)
    test_ips_possible_devices_similarity = load_json(
        os.path.join(TEST_RESULT_FOLDER_NAME, "finder_2019_09_1", "test_ips_possible_devices_similarity.json"))
    i = 0
    # devices_list = ["Amazon Echo Gen1", "Apple HomePod", "Apple TV (4thGen)", "Belkin WeMo Crockpot",
    #                 "Belkin WeMo Motion Sensor",
    #                 "Belkin WeMo Switch", "Google Home Mini", "Google Home", "Roku4", "Sonos Beam"]
    devices_list = ["Apple HomePod", "Apple TV (4thGen)", "Belkin WeMo Crockpot", "Google Home Mini", "Roku4"]
    device_ip_map = dict()
    total_test_ips_devices_info = load_json(TOTAL_IPS_DEVICES_INFO_FILE)
    for device in devices_list:
        for ip, device_info in total_test_ips_devices_info.items():
            if device_info["device"] == device:
                device_ip_map[device] = ip

    for device, ip in device_ip_map.items():
        i += 1
        for possible_device, similarity in get_highest_val_from_instances(
                test_ips_possible_devices_similarity[ip]).items():
            devices_similarity_for_picture[" " * i + possible_device] = similarity
        devices_similarity_for_picture[str(i) + ":" + device] = 0
        devices_similarity_for_picture[" " * i] = 0
    del devices_similarity_for_picture[" " * len(devices_list)]
    store_json(devices_similarity_for_picture, DEVICES_SIMILARITY_FOR_PICTURE_FILE)


def draw_devices_best_theta_performance():
    figure_name = "devices_best_theta_performance"
    if FIGURE_LANGUAGE_CN:
        labels = ["识别阈值", "精确率", "召回率", "F2分数"]
        figure_name += "_cn"
    else:
        labels = ["identification threshold", "precision rate", "recall rate", "F2 score"]
    devices_performance = load_json(DEVICES_PERFORMANCE_FILE)
    devices_list = ["Apple HomePod", "Apple TV (4thGen)", "Belkin WeMo Crockpot", "Google Home Mini", "Roku4"]
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

    space_width = 0.5
    bar_width = 3
    device_width = bar_width * 6
    x_1 = list(range(0, device_width * len(devices), device_width))
    x_2 = [i + 1 * (bar_width + space_width) for i in x_1]
    x_3 = [i + 2 * (bar_width + space_width) for i in x_1]
    x_4 = [i + 3 * (bar_width + space_width) for i in x_1]

    # # 设置图形比例
    plt.figure(figsize=(10, 4))
    # plt.title("Performance")

    # 设置x轴的刻度
    plt.xticks([i + (bar_width + space_width) * 1.5 for i in x_1], devices, rotation=45, fontsize=12)

    plt.bar(x_1, thetas, width=bar_width, label=labels[0], color="sienna")
    plt.bar(x_2, precisions, width=bar_width, label=labels[1], color="darkorange")
    plt.bar(x_3, recalls, width=bar_width, label=labels[2], color="steelblue")
    plt.bar(x_4, f2s, width=bar_width, label=labels[3], color="green")

    plt.legend(bbox_to_anchor=(1, 1))
    plt.tight_layout()
    fig_path = os.path.join(ALL_RESULT_FOLDER_NAME, figure_name + ".png")
    plt.savefig(fig_path, format='png')
    fig_path = os.path.join(ALL_RESULT_FOLDER_NAME, figure_name + ".svg")
    plt.savefig(fig_path, format='svg')

    # 展示
    plt.show()


def get_average_performance_nat():
    devices_performance = load_json(DEVICES_PERFORMANCE_FILE)
    theta_coefficients_performance = dict()
    theta_coefficient_low = 0.5
    theta_coefficient_high = 1.5
    theta_coefficient_step = 0.01
    for theta_coefficient in np.arange(theta_coefficient_low, theta_coefficient_high, theta_coefficient_step):
        fixed_devices_theta = dict()
        for device, theta_performance in devices_performance.items():
            fixed_devices_theta[device] = min(1, float(theta_performance["theta"]) * theta_coefficient)

        ips_tp = 0
        ips_fp = 0
        ips_fn = 0

        for file_index in range(TEST_FILE_LOW, TEST_FILE_HIGH + 1):
            # 对于每一个测试文件
            # 一些常量
            test_target_name = TEST_PREFIX + str(file_index) + "_NAT"
            test_ips_devices_info_file = os.path.join(TEST_DATA_FOLDER_NAME, test_target_name + ".json")
            test_ips_devices_info = load_json(test_ips_devices_info_file)
            test_ips_possible_devices_similarity_file = os.path.join(TEST_RESULT_FOLDER_NAME, test_target_name,
                                                                     "test_ips_possible_devices_similarity.json")
            test_ips_possible_devices_similarity = load_json(test_ips_possible_devices_similarity_file)

            for test_ip, possible_devices_similarity in test_ips_possible_devices_similarity.items():
                # 对于每一个测试ip
                tp = 0
                fp = 0
                test_ip_devices = [test_ips_devices_info[test_ip][i]["device"] for i in
                                   range(len(test_ips_devices_info[test_ip]))]
                test_ip_devices_info_num = len(test_ip_devices)
                # 对possible_devices_similarity进行处理，取每种设备多个实例中的最高作为判定
                # for possible_device, similarity in possible_devices_similarity.items():
                possible_devices_similarity = get_highest_val_from_instances(possible_devices_similarity)
                for possible_device, similarity in possible_devices_similarity.items():
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
        if target == "F2":
            plt.annotate(show_max, xytext=(max_x, max_y-0.01), xy=(max_x, max_y), )
        else:
            plt.annotate(show_max, xytext=(max_x, max_y), xy=(max_x, max_y), )
        # plt.annotate(show_max, xytext=(max_x, max_y), xy=(max_x, max_y), )
        # plt.plot(x_s, y_s, line_patterns[i], label=target)
        if FIGURE_LANGUAGE_CN:
            plt.plot(x_s, y_s, line_patterns[i], label=LANGUAGE_MAP[target])
        else:
            plt.plot(x_s, y_s, line_patterns[i], label=FIX_TARGETS[target])
    # plt.axis([0.5, 1.5, 0.5, 1])
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
    figure_name = "theta_coefficients_performance"
    if FIGURE_LANGUAGE_CN:
        # title = "Performance Under Different Coefficients"
        x_label = "阈值系数"
        figure_name += "_cn"
    else:
        # title = "不同系数下的结果"
        x_label = "coefficient"

    # theta_coefficients_performance = load_json(THETA_COEFFICIENTS_PERFORMANCE_FILE)
    theta_coefficients_performance = load_json(os.path.join(ALL_RESULT_FOLDER_NAME, "one_nat.json"))
    y_string_length = 6
    fig_path = os.path.join(ALL_RESULT_FOLDER_NAME, figure_name + ".png")
    base_draw_lines(theta_coefficients_performance, y_string_length, x_label, fig_path,
                    targets=["precision", "recall", "F2"], title=None)
    fig_path = os.path.join(ALL_RESULT_FOLDER_NAME, figure_name + ".svg")
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
        # if device not in ["Chinese Webcam", "Insteon Hub", "Piper NV", "Wink Hub"]:
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
    # 先得到某device在所有的测试样本中出现的ip数
    devices_appearance_num = dict()
    for file_index in range(TEST_FILE_LOW, TEST_FILE_HIGH + 1):
        test_ips_devices_info_file = os.path.join(TEST_DATA_FOLDER_NAME, TEST_PREFIX + str(file_index) + ".json")
        test_ips_devices_info = load_json(test_ips_devices_info_file)
        for ip, devices_info in test_ips_devices_info.items():
            for device_info in devices_info:
                devices_appearance_num[device_info["device"]] = devices_appearance_num.get(device_info["device"], 0) + 1
    # pprint(devices_appearance_num)

    devices_list = get_devices_list(TOTAL_IPS_DEVICES_INFO_FILE)
    temp_devices_threshold = get_mongodb_devices_threshold()
    # 处理devices_threshold
    devices_threshold = dict()
    for device, threshold in temp_devices_threshold.items():
        devices_threshold[device.split("_")[0]] = threshold
    devices_performance = dict()
    for device in devices_appearance_num.keys():
        if device in devices_threshold.keys():
            devices_performance[device] = {
                "theta": devices_threshold[device],
                "tp": 0,
                "fp": 0,
                "fn": 0
            }

    # 得出结果
    for file_index in range(TEST_FILE_LOW, TEST_FILE_HIGH + 1):
        test_ips_devices_info_file = os.path.join(TEST_DATA_FOLDER_NAME, TEST_PREFIX + str(file_index) + ".json")
        test_ips_devices_info = load_json(test_ips_devices_info_file)
        file_name = os.path.join(TEST_RESULT_FOLDER_NAME, TEST_PREFIX + str(file_index),
                                 "test_ips_possible_devices_similarity.json")
        test_ips_possible_devices_similarity = load_json(file_name)
        for test_ip, possible_devices_similarity in test_ips_possible_devices_similarity.items():
            test_ip_devices = [test_ips_devices_info[test_ip][i]["device"] for i in
                               range(len(test_ips_devices_info[test_ip]))]
            # 对possible_devices_similarity进行处理，取与每种设备多个实例相似度中的最高作为判定
            # for possible_device, similarity in possible_devices_similarity.items():
            possible_devices_similarity = get_highest_val_from_instances(possible_devices_similarity)
            for possible_device, similarity in possible_devices_similarity.items():
                if similarity >= (devices_threshold[possible_device] - 0.0000000000000010):
                    if possible_device in test_ip_devices:
                        devices_performance[possible_device]["tp"] += 1
                    else:
                        devices_performance[possible_device]["fp"] += 1
    for device in devices_performance.keys():
        devices_performance[device]["fn"] = devices_appearance_num[device] - devices_performance[device]["tp"]

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


def domains_guessing_results():
    """
    type和vendor的猜测结果
    :return:
    """
    test_ips_report = load_json(TEST_IPS_REPORT_FILE)
    domains_num = 0
    type_guess_methods_num = dict()
    vendor_guess_methods_num = dict()
    for ip, report in test_ips_report.items():
        domains_guessed_results = report["domains_guessed_results"]
        for domain, guessed_results in domains_guessed_results.items():
            domains_num += 1
            type_guess_method = guessed_results["type"]["guess_method"]
            vendor_guess_method = guessed_results["vendor"]["guess_method"]
            type_guess_methods_num[type_guess_method] = type_guess_methods_num.get(type_guess_method, 0) + 1
            vendor_guess_methods_num[vendor_guess_method] = vendor_guess_methods_num.get(vendor_guess_method, 0) + 1
    print(domains_num)
    pprint(type_guess_methods_num)
    pprint(vendor_guess_methods_num)


def get_test_ips_devices_info_by_test_ips_info():
    """
    获取每个测试文件的描述文件，从all_ips_devices_info中获取该测试文件中出现的ip的设备信息
    :return:
    """
    all_ips_devices_info = load_json(os.path.join("train_data", TEST_TARGET_NAME, TEST_TARGET_NAME + ".json"))
    for file_index in range(TEST_FILE_LOW, TEST_FILE_HIGH + 1):
        test_ips_devices_info = {NAT_IP: list()}
        test_ips_info_file = os.path.join(TEST_RESULT_FOLDER_NAME, TEST_PREFIX + str(file_index),
                                          "test_ips_info.json")
        test_ips = load_json(test_ips_info_file, "ips_domains_tfidf").keys()
        for ip in test_ips:
            test_ips_devices_info[ip] = [
                all_ips_devices_info[ip]
            ]
        store_json(test_ips_devices_info,
                   os.path.join(TEST_DATA_FOLDER_NAME, TEST_PREFIX + str(file_index) + ".json"))


def draw_devices_performance():
    """
    根据各个阈值对应的分数，画出曲线
    :return:
    """
    devices_list = get_devices_list(TOTAL_IPS_DEVICES_INFO_FILE)
    # devices_list = ["Apple HomePod", "Google Home Mini"]
    for device in devices_list:
        figure_name = device
        if FIGURE_LANGUAGE_CN:
            # title = device
            x_label = "识别阈值"
            figure_name += "_cn"
        else:
            # title = device
            x_label = "threshold"
        device_thetas_performance_filename = os.path.join(DEVICES_PERFORMANCE_FOLDER_NAME, device + ".json")
        device_thetas_performance = load_json(device_thetas_performance_filename)
        showed_device_thetas_performance = dict()
        for theta, performance in device_thetas_performance.items():
            if float(theta) >= 0.6:
                showed_device_thetas_performance[theta] = device_thetas_performance[theta]
        y_string_length = 6
        fig_path = os.path.join(ALL_RESULT_FOLDER_NAME, "devices_performance", figure_name + ".png")
        base_draw_lines(showed_device_thetas_performance, y_string_length, x_label, fig_path,
                        targets=["precision", "recall", "F2"], title=device)
        fig_path = os.path.join(ALL_RESULT_FOLDER_NAME, "devices_performance", figure_name + ".svg")
        base_draw_lines(showed_device_thetas_performance, y_string_length, x_label, fig_path,
                        targets=["precision", "recall", "F2"], title=device)


def main():
    # 画出各个设备访问域名的散点图，即论文图1
    # draw_dns_behaviors()

    # 画出5个设备的相似情况
    # get_devices_similarity_for_picture()
    # devices_similarity_for_picture = load_json(DEVICES_SIMILARITY_FOR_PICTURE_FILE)
    # draw_histogram(devices_similarity_for_picture, DEVICES_SIMILARITY_FOR_PICTURE_PICTURE, 1)

    # 5设备的一张图
    # draw_devices_best_theta_performance()

    # 获取各个设备规律域名TF-IDF值所占比例
    # get_test_ips_domains_regularity_score(
    #     os.path.join("test_result", "finder", "finder_2019_09_1", "test_ips_domains_pkts_time.json"),
    #     os.path.join("test_result", "finder", "finder_2019_09_1", "test_ips_domains_regularity_score.json"))
    # get_test_ips_regular_domains_tfidf_ratio(os.path.join("test_result", "finder", "finder_2019_09_1", "test_ips_domains_regularity_score.json"),
    #     os.path.join("test_result", "finder", "finder_2019_09_1", "test_ips_regular_domains_tfidf_ratio.json"))
    # get_devices_regular_domains_tfidf_ratio(
    #     os.path.join("test_result", "finder", "finder_2019_09_1", "test_ips_domains_regularity_score.json"),
    #     os.path.join("test_result", "finder", "finder_2019_09_1", "devices_regular_domains_tfidf_ratio.json")
    # )
    # devices_regular_domains_tfidf_ratio = load_json(
    #     os.path.join("test_result", "finder", "finder_2019_09_1", "devices_regular_domains_tfidf_ratio.json"))
    # draw_histogram(devices_regular_domains_tfidf_ratio,
    #                os.path.join("test_result", "finder", "finder_2019_09_1", "devices_regular_domains_tfidf_ratio"), 2)

    # get_test_ips_devices_info_by_test_ips_info()  # 用result文件夹中的test_ips_info来生成该pcap的设备描述文件(data文件夹中)
    #
    get_devices_performance()  # 获取每个设备在最佳阈值下的表现

    average_precision, average_recall, average_f05, average_f1, average_f2 = get_average_performance()
    logger.info("mode:{mode}\nprecision:{precision}\nrecall:{recall}\nf05:{f05}\nf1:{f1}\nf2:{f2}"
                .format(mode=MODE, precision=average_precision, recall=average_recall, f05=average_f05, f1=average_f1,
                        f2=average_f2))

    # get_average_performance_nat()  # 获取NAT情况下的结果

    # draw_theta_coefficients_performance()  # 画出在不同阈值系数下的NAT识别情况

    # draw_devices_performance()  # 每个设备一张图

    # type/vendor guessing result
    # domains_guessing_results()

    pass


if __name__ == '__main__':
    main()
