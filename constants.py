import os

# 其它的常量
BLACK_DOMAINS = [".amazonaws.com"]
BLACK_IPS = ["224.0.0.251", "192.168.1.1", "192.168.1.180", "192.168.1.208", "192.168.1.228", "192.168.1.243",
             "192.168.1.248",
             "192.168.1.239", "169.254.3.23", "169.254.235.84", ":1", ":2"]
COEFFICIENT_STR_LENGTH = 4
ENCODING_METHOD = "utf-8"
# EXCLUDED_DOMAINS_SUFFIX = [".ntp.org", ".arpa", ".local", ".nessus.org", ".#", ".lan", ".wlan0"]
EXCLUDED_DOMAINS_SUFFIX = [".arpa", ".local", ".nessus.org", ".#", ".lan", ".wlan0"]
FIND_WORD_USE_STRUCTURE = False  # 是否使用结构化的数据来查找关键词
IS_LAB_NETWORK = False
LANGUAGE_MAP = {
    "precision": "精确率",
    "recall": "召回率",
    "F2": "F2分数"
}
FIX_TARGETS = {
    "precision": "precision rate",
    "recall": "recall rate",
    "F2": "F2 score"
}
NAT_IP = "192.168.0.255"
PROTOCOL_PREFIX = ["www.", "http.", "https."]
REGULARITY_DELTA_TIME = 10
REGULARITY_THRESHOLD = 0.5
SPECIAL_SPLIT_SYMBOL = "\W+"
THETA_COEFFICIENT = 0.8
THETA_HIGH = 1
THETA_LOW = 0
THETA_STEP = 0.002
THETA_STR_LENGTH = 5
TOTAL_IPS_DEVICES_INFO_FILE = os.path.join(os.path.join("train_data", "finder", "finder.json"))
WHOIS_REGISTRANT_BLACK_LIST = ["Not Disclosed", "REDACTED FOR PRIVACY", "Domains By Proxy, LLC"]
WINDOW_SECONDS = 3600  # 时间窗口长度

# MongoDB中collection的名字
DEVICES_KNOWLEDGE_COL_NAME = "new_devices_knowledge"
DOMAINS_KNOWLEDGE_COL_NAME = "new_domains_knowledge"
GREAT_DOMAINS_COL_NAME = "new_great_domains"

# devices_info.json中各信息位置
DEVICES_INFO_TYPE_POS = 0  # devices_info.json中每个设备的类型的位置
DEVICES_INFO_VENDOR_POS = 1  # devices_info.json中每个设备的厂商的位置
DEVICES_INFO_IP_POS = 2  # devices_info.json中每个设备的ip的位置

# 头部信息
ORDINARY_HEADERS = {
    'User-Agent': 'Mozilla/4.0 (compatible; MSIE 5.5; Windows NT)',
    "accept-language": "en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7",
    "accept": "text/html"
}
PAGE_INFO_HEADERS = {
    'User-Agent': 'Mozilla/4.0 (compatible; MSIE 5.5; Windows NT)',
    "accept-language": "en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7",
    # "accept": "text/html"
}
RESULTS_NUM_HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36  Chrome/94.0.4606.61 Safari/537.36',
    "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
    # "accept-encoding": "gzip, deflate, br",
    "cache-control": "no-cache",
    "accept-language": "en-US,en;q=0.9,zh-CN;q=0,zh;q=0",
    # "accept": "text/html"
}

# 网络模式
if IS_LAB_NETWORK:
    MONGODB_CONNECTION_URL = "mongodb://192.168.1.101:27017/"  # MongoDB的连接字符串
    PROXIES = {
        "http": '192.168.1.101:7890',
        "https": '192.168.1.101:7890'
        # "http": 'socks5h://192.168.1.101:8888',
        # "https": 'socks5h://192.168.1.101:8888'
    }
else:
    MONGODB_CONNECTION_URL = "mongodb://127.0.0.1:27017/"  # MongoDB的连接字符串
    PROXIES = {
        "http": '127.0.0.1:7890',
        "https": '127.0.0.1:7890'
        # "http": 'socks5h://127.0.0.1:8888',
        # "https": 'socks5h://127.0.0.1:8888'
    }

# Google api的信息
GOOGLE_API_KEY = "0e9982527e64b4d19b25fbc4cf258451bb1025d34e652d6576d8b2376aad2b07"
GOOGLE_RAW_URL = "https://serpapi.com/search.json?engine=google&q={}&api_key={}&output=JSON"

# whois api的信息
WHOIS_API_KEY = "at_lUle2FQ7iPhyvrlhEB1Aq7hTVo00w"
WHOIS_OUTPUT_FORMAT = "res"
WHOIS_RAW_URL = "https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey={}&domainName={}&outputFormat={}"

# data文件夹中的文件，存放各种知识
DATA_FOLDER_NAME = "data"

COMMON_TYPES_FILE = os.path.join(DATA_FOLDER_NAME, "common_types.json")
DEVICE_MAPPING_XLSX = os.path.join(DATA_FOLDER_NAME, "device_mapping.xlsx")
GLOBAL_VENDORS_FILE = os.path.join(DATA_FOLDER_NAME, "global_vendors.json")
OTHER_EXCLUDED_DOMAINS_FILE = os.path.join(DATA_FOLDER_NAME, "other_excluded_domains.json")
TOP100_FILE = os.path.join(DATA_FOLDER_NAME, "top_100.csv")
TOP_DOMAINS_FILE = os.path.join(DATA_FOLDER_NAME, "top_domains.json")
WEBSITE_SUFFIX_FILE = os.path.join(DATA_FOLDER_NAME, "website_suffix.json")

# 需要训练的三个训练集
TRAIN_TARGET_NAME = "finder"
# TRAIN_TARGET_NAME = "arunan_dns_23-30"
# TRAIN_TARGET_NAME = "long_dns_2972_3665"

# train_data文件夹中存放训练数据，包括*.pcap和*.json
TRAIN_DATA_FOLDER_NAME = os.path.join("train_data", TRAIN_TARGET_NAME)
TRAIN_RESULT_FOLDER_NAME = os.path.join("train_result", TRAIN_TARGET_NAME)

TRAIN_PCAP_FILE = os.path.join(TRAIN_DATA_FOLDER_NAME, TRAIN_TARGET_NAME + ".pcap")
TRAIN_IPS_DEVICE_INFO_XLSX = os.path.join(TRAIN_DATA_FOLDER_NAME, TRAIN_TARGET_NAME + ".xlsx")
TRAIN_IPS_DEVICE_INFO_FILE = os.path.join(TRAIN_DATA_FOLDER_NAME, TRAIN_TARGET_NAME + ".json")

# 标识集
LABEL_TARGET_NAME = "finder"

# label_data文件夹中存放训练数据，包括*.pcap和*.json
LABEL_DATA_FOLDER_NAME = os.path.join("label_data", LABEL_TARGET_NAME)
LABEL_RESULT_FOLDER_NAME = os.path.join("label_result", LABEL_TARGET_NAME)

LABEL_PCAP_FILE = os.path.join(LABEL_DATA_FOLDER_NAME, LABEL_TARGET_NAME + ".pcap")
LABEL_IPS_DEVICE_INFO_XLSX = os.path.join(LABEL_DATA_FOLDER_NAME, LABEL_TARGET_NAME + ".xlsx")
LABEL_IPS_DEVICE_INFO_FILE = os.path.join(LABEL_DATA_FOLDER_NAME, LABEL_TARGET_NAME + ".json")

# 需要测试的测试集
TEST_TARGET_NAME = "finder"
# TEST_TARGET_NAME = "finder_2019_09_100000"
# TEST_TARGET_NAME = "arunan_dns_1"
# TEST_TARGET_NAME = "long_dns_901_1192"

# test_data文件夹中存放测试数据，包括*.pcap和*.json
TEST_DATA_FOLDER_NAME = os.path.join("test_data", TEST_TARGET_NAME)
# res文件夹中的文件，存放程序处理后的结果
TEST_RESULT_FOLDER_NAME = os.path.join("test_result", TEST_TARGET_NAME)  # 给用户使用
# TEST_RESULT_FOLDER_NAME = "test_result"  # 我自己测试数据结果使用

TEST_PCAP_FILE = os.path.join(TEST_DATA_FOLDER_NAME, TEST_TARGET_NAME + ".pcap")
TEST_IPS_DEVICES_INFO_FILE = os.path.join(TEST_DATA_FOLDER_NAME, TEST_TARGET_NAME + ".json")

ALL_THETAS_PERFORMANCE_FILE = os.path.join(TEST_RESULT_FOLDER_NAME, "all_thetas_performance.json")
TEST_IPS_DOMAINS_REGULARITY_SCORE_FILE = os.path.join(TEST_RESULT_FOLDER_NAME, "test_ips_domains_regularity_score.json")
TEST_IPS_DOMAINS_PKTS_TIME_FILE = os.path.join(TEST_RESULT_FOLDER_NAME, "test_ips_domains_pkts_time.json")
TEST_IPS_OTHER_DOMAINS_FILE = os.path.join(TEST_RESULT_FOLDER_NAME, "test_ips_other_domains.json")
TEST_IPS_PERFORMANCE_FILE = os.path.join(TEST_RESULT_FOLDER_NAME, "test_ips_performance.json")
TEST_IPS_POSSIBLE_DEVICES_FILE = os.path.join(TEST_RESULT_FOLDER_NAME, "test_ips_possible_devices.json")
TEST_IPS_POSSIBLE_DEVICES_SIMILARITY_FILE = os.path.join(TEST_RESULT_FOLDER_NAME,
                                                         "test_ips_possible_devices_similarity.json")
TEST_IPS_REPORT_FILE = os.path.join(TEST_RESULT_FOLDER_NAME, "test_ips_report.json")
TEST_IPS_INFO_FILE = os.path.join(TEST_RESULT_FOLDER_NAME, "test_ips_info.json")

# 存放总的结果
ALL_RESULT_FOLDER_NAME = os.path.join("all_result", TEST_TARGET_NAME)

DEVICES_PERFORMANCE_FOLDER_NAME = os.path.join(LABEL_RESULT_FOLDER_NAME, "devices_performance")
DEVICES_PERFORMANCE_FILE = os.path.join(TEST_RESULT_FOLDER_NAME, "devices_performance.json")

MODE = "53"

TRAIN_LABEL_DAYS = {
    "1": [
        [1],
        [2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30]
    ],
    "31": [
        [103],
        [4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30]
    ],
    "32": [
        [1, 2, 3],
        [4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30]
    ],
    "33": [
        [1, 11, 21],
        [2, 3, 4, 5, 6, 7, 8, 9, 10, 12, 13, 14, 15, 16, 17, 18, 19, 20, 22, 23, 24, 25, 26, 27, 28, 29, 30]
    ],
    "51": [
        [105],
        [6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30]
    ],
    "52": [
        [1, 2, 3, 4, 5],
        [6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30]
    ],
    "53": [
        [1, 7, 13, 19, 25],
        [2, 3, 4, 5, 6, 8, 9, 10, 11, 12, 14, 15, 16, 17, 18, 20, 21, 22, 23, 24, 26, 27, 28, 29, 30]
    ],
    "151": [
        [115],
        [16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30]
    ],
    "152": [
        [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
        [16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30]
    ],
    "153": [
        [1, 3, 5, 7, 9, 11, 13, 15, 17, 19, 21, 23, 25, 27, 29],
        [2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22, 24, 26, 28, 30]
    ],
    "251": [
        [125],
        [26, 27, 28, 29, 30]
    ],
    "252": [
        [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25],
        [26, 27, 28, 29, 30]
    ],
    "253": [
        [1, 2, 3, 4, 5, 7, 8, 9, 10, 11, 13, 14, 15, 16, 17, 19, 20, 21, 22, 23, 25, 26, 27, 28, 29],
        [6, 12, 18, 24, 30]
    ],
    "only30": [
        [30],
        [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29]
    ],
    "only15": [
        [15],
        [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30]
    ],
    "only11": [
        [11],
        [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30]
    ],
    "only21": [
        [21],
        [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 22, 23, 24, 25, 26, 27, 28, 29, 30]
    ],
    "only29": [
        [29],
        [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 30]
    ],
    "only3": [
        [3],
        [1, 2, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30]
    ],
    "last5": [
        [26, 27, 28, 29, 30],
        [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25]
    ]
}

TRAIN_DAYS, LABEL_DAYS = TRAIN_LABEL_DAYS[MODE]

TEST_FILE_LOW = 1
TEST_FILE_HIGH = 30
TRAIN_WINDOWS_NUM = 24  # 每个训练的模型的窗口数
LABEL_WINDOWS_NUM = 24  # 每个标记的模型的窗口数
TEST_WINDOWS_NUM = 24  # 每个测试的模型的窗口数

for train_day in TRAIN_DAYS:
    if train_day > 100:
        TRAIN_WINDOWS_NUM = 24 * (train_day - 100)


TEST_PREFIX = "finder_2019_09_"
# TEST_PREFIX = "finder_2019_09_for12_"
# TEST_PREFIX = "finder_2019_09_for48_"
# TEST_PREFIX = "finder_2019_09_for6_"
