#!/usr/bin/env python
# -*- coding:utf-8 -*-
# @Time    : 2021/05/14 13:55
# @Author  : Zixing Xiao
import json
import socket
import time
import numpy as np
import logging
from logging import handlers
import datetime
import tldextract

from constants import *


def mkdir_if_not_exist(folder_name):
    """
    如果没有文件夹，则创建
    :param folder_name: 文件夹
    :return:
    """
    if os.path.exists(folder_name):
        print("folder name : {folder_name} has already existed.".format(folder_name=folder_name))
    else:
        os.makedirs(folder_name)
        print("folder name : {folder_name} is created successfully.".format(folder_name=folder_name))


class Logger(object):
    """
    日志工具类
    """
    level_relations = {
        'debug': logging.DEBUG,
        'info': logging.INFO,
        'warning': logging.WARNING,
        'error': logging.ERROR,
        'critical': logging.CRITICAL
    }  # 日志级别关系映射

    def __init__(self, filename, level='info', when='D', backCount=3,
                 fmt='%(asctime)s %(levelname)s %(name)s[line:%(lineno)d]: %(message)s'):
        # self.logger = logging.getLogger(filename)
        self.logger = logging.getLogger(__name__)
        format_str = logging.Formatter(fmt)  # 设置日志格式
        self.logger.setLevel(self.level_relations.get(level))  # 设置日志级别
        sh = logging.StreamHandler()  # 往屏幕上输出
        sh.setFormatter(format_str)  # 设置屏幕上显示的格式
        th = handlers.TimedRotatingFileHandler(filename=filename, when=when, backupCount=backCount,
                                               encoding='utf-8')  # 往文件里写入#指定间隔时间自动生成文件的处理器
        # 实例化TimedRotatingFileHandler
        # interval是时间间隔，backupCount是备份文件的个数，如果超过这个个数，就会自动删除，when是间隔的时间单位，单位有以下几种：
        # S 秒
        # M 分
        # H 小时、
        # D 天、
        # W 每星期（interval==0时代表星期一）
        # midnight 每天凌晨
        th.setFormatter(format_str)  # 设置文件里写入的格式
        self.logger.addHandler(sh)  # 把对象加到logger里
        self.logger.addHandler(th)


logger = Logger('logs/iot_detective.log', level='debug').logger


def store_json(result, result_file):
    """
    存储字典为json文件
    :param result: 传入字典
    :param result_file: json文件
    :return:
    """
    with open(result_file, 'w') as file:
        file.write(json.dumps(result, indent=4, cls=DateEncoder))
    logger.info("store {file} successfully.".format(file=result_file))


def load_json(json_file, key=None):
    """
    从json文件读取字典
    :param json_file: json文件
    :param key: 指定键读取
    :return: 读取的字典
    """
    with open(json_file, 'r', encoding='utf8')as file:
        if key is None:
            return json.load(file)
        else:
            return json.load(file)[key]


def dict2sorted_list(raw_dict, compared_name=None):
    """
    将字典值进行排序，若有compared_name，则按compared_name进行排序
    :param raw_dict: 传入的字典
    :param compared_name: 按compared_name进行排序
    :return: 排好序的列表
    """
    if compared_name is None:
        result = sorted(raw_dict.items(), key=lambda x: x[1], reverse=True)
    else:
        result = sorted(raw_dict.items(), key=lambda x: x[1][compared_name], reverse=True)
    return result


def get_sorted_dict(raw_dict, compared_target="key", compared_name=None):
    """
    若compared_name为None，按字典值从大到小进行排序
    否则按字典值中的compared_name进行排序
    :param compared_target:
    :param raw_dict: 传入的字典
    :param compared_name: 按compared_name进行排序
    :return: 排好序的字典
    """
    mapping_pos = {"key": 0, "value": 1}
    if compared_name is None:
        result = sorted(raw_dict.items(), key=lambda x: x[mapping_pos[compared_target]], reverse=True)
    else:
        result = sorted(raw_dict.items(), key=lambda x: x[mapping_pos[compared_target]][compared_name], reverse=True)
    sorted_dict = dict()
    for key, val in result:
        sorted_dict[key] = val
    return sorted_dict


def get_sorted_dict_by_key_len(raw_dict):
    """
    若compared_name为None，按字典键长从大到小进行排序
    否则按字典值中的compared_name进行排序
    :param raw_dict: 传入的字典
    :return: 排好序的字典
    """
    result = sorted(raw_dict.items(), key=lambda x: len(x[0]), reverse=True)
    sorted_dict = dict()
    for key, val in result:
        sorted_dict[key] = val
    return sorted_dict


def get_sorted_dict_by_ip(raw_dict):
    """
    按ip排序字典
    :param raw_dict: 传入的字典
    :return: 按ip排序的字典
    """
    keys = list(raw_dict.keys())
    other_keys = [key for key in keys if ":" in key]
    for key in other_keys:
        keys.remove(key)
    sorted_keys = sorted(keys, key=socket.inet_aton)
    for key in other_keys:
        sorted_keys.append(key)
    sorted_dict = dict()
    for key in sorted_keys:
        sorted_dict[key] = raw_dict[key]
    return sorted_dict


def exchanged_dict(old_dict):
    """
    交换字典的键值
    :param old_dict: 传入的字典
    :return: 交换键值后的字典
    """
    return {k: v for v, k in old_dict.items()}


def calc_method_time(func):
    """
    计算方法所耗时间
    :param func: 方法
    :return: 耗时
    """

    def inner(*args, **kwargs):
        logger.info("开始运行方法: %s" % func.__name__)
        start = time.time()
        res = func(*args, **kwargs)
        end = time.time()
        logger.info("运行方法: %s完毕, 运行共计耗时: %s s" % (func.__name__, end - start))
        return res

    return inner


def is_excluded_domain(domain, excluded_domains, excluded_domains_suffix):
    """
    某域名是否需要被排除
    :param domain: 传入的域名
    :param excluded_domains: 被排除的域名
    :param excluded_domains_suffix: 被排除的前缀
    :return: 某域名是否需要被排除
    """
    for excluded_domain_suffix in excluded_domains_suffix:
        if domain.endswith(excluded_domain_suffix):
            return True
    if domain.startswith('www.'):
        # please insure that excluded_domains doesn't start with www
        # such as: google.com
        # return domain in excluded_domains or domain.split('www.')[1] in excluded_domains
        return domain[4:] in excluded_domains
    else:
        return domain in excluded_domains


def erase_protocol_prefix(domain):
    """
    去除掉域名的协议前缀，如"www.", "http.", "https."
    :param domain:
    :return:
    """
    for prefix in PROTOCOL_PREFIX:
        if domain.startswith(prefix):
            return domain[len(prefix):]
    return domain


def get_dot_product(vector_a, vector_b):
    """
    计算两个向量的数量积
    :param vector_a: 向量 a
    :param vector_b: 向量 b
    :return: 两个向量的数量积
    """
    vector_a = np.mat(vector_a)
    vector_b = np.mat(vector_b)
    num = float(vector_a * vector_b.T)
    sim = num
    return sim


def get_domains_dot_product(tfidf_a, tfidf_b):
    """
    计算两组domain tfidf间的数量积
    :param tfidf_a: 向量 a
    :param tfidf_b: 向量b
    :return: 两个向量的数量积
    """
    vector_a = []
    vector_b = []
    for domain, tfidf in tfidf_a.items():
        vector_a.append(tfidf)
        vector_b.append(tfidf_b.get(domain, 0))

    return get_dot_product(vector_a, vector_b)


def cal_tfidf_vectors_length(domains_tfidf):
    """
    计算domains_tfidf的向量长度
    :param domains_tfidf: domain的tfidf
    :return: 向量长度
    """
    domains_tfidf_vector = list()
    for domain_tfidf in domains_tfidf.values():
        domains_tfidf_vector.append(domain_tfidf)
    return np.linalg.norm(domains_tfidf_vector)


def get_key_by_max_value(my_dict, compared_name=None):
    """
    获取字典中值最大的对应的键
    :param my_dict: 传入的字典
    :param compared_name: 比较值的键
    :return: 值最大的对应的键
    """
    max_value = None
    best_key = None
    if compared_name is None:
        for key, value in my_dict.items():
            if not max_value or value > max_value:
                max_value = value
                best_key = key
    else:
        for key, value in my_dict.items():
            if not max_value or value[compared_name] > max_value:
                max_value = value[compared_name]
                best_key = key
    return best_key


def tuple_list_to_dict(my_list):
    """
    将二元组列表转为字典
    :param my_list: 列表，每个元素是一个二元组
    :return: 字典
    """
    my_dict = dict()
    for key, value in my_list:
        my_dict[key] = value
    return my_dict


def get_merged_domains(domains):
    """
    提取多个domain，合并二级域名及后缀，即b.a.com 和c.a.com合并为a.com
    :param domains: 合并前的domain列表
    :return: 合并后的domain列表
    """
    merged_domains = set()
    for domain in domains:
        sub_domain, second_domain, suffix = tldextract.extract(domain)
        merged_domain = second_domain + '.' + suffix
        merged_domains.add(merged_domain.lower())
    return list(merged_domains)


class DateEncoder(json.JSONEncoder):
    """
    将python中的时间类型转为为字符串，以便存入json
    """

    def default(self, obj):
        if isinstance(obj, datetime.datetime):
            return obj.strftime('%Y-%m-%d %H:%M:%S.%f')
        elif isinstance(obj, datetime.date):
            return obj.strftime("%Y-%m-%d")
        else:
            return json.JSONEncoder.default(self, obj)


def eliminate_dict_zero_value(src_dict):
    """
    消除字典中值为零的键值对
    :param src_dict:
    :return:
    """
    dst_dict = dict()
    for key, value in src_dict.items():
        if value != 0:
            dst_dict[key] = value
    return dst_dict


def eliminate_redundancy(redundancy_dict, target_dict):
    """
    将一些可能重复多次的词汇进行删重，如bell出现在doorbell中，bell会多计算了
    :param redundancy_dict: 知识库中的冗余词汇信息
    :param target_dict: 按计数值从大到小排序的去重后的字典
    :return:
    """
    key_len_sorted_redundancy_dict = get_sorted_dict_by_key_len(redundancy_dict)
    for redundancy_name in key_len_sorted_redundancy_dict.keys():
        key_len_sorted_redundancy_dict[redundancy_name] = sorted(key_len_sorted_redundancy_dict[redundancy_name],
                                                                 key=lambda mapping_name: len(mapping_name),
                                                                 reverse=True)
    sorted_target_dict = get_sorted_dict_by_key_len(target_dict)
    for redundant_name in sorted_target_dict.keys():
        if redundant_name in key_len_sorted_redundancy_dict.keys():
            for mapping_type in key_len_sorted_redundancy_dict[redundant_name]:
                sorted_target_dict[redundant_name] -= sorted_target_dict.get(mapping_type, 0)
    return get_sorted_dict(eliminate_dict_zero_value(sorted_target_dict), compared_target="value")


def get_devices_list(test_ips_devices_info_file):
    """
    获取测试ip设备描述文件中的所有设备
    :param test_ips_devices_info_file: 测试ip设备描述文件
    :return: 设备列表
    """
    test_ips_devices_info = load_json(test_ips_devices_info_file)
    devices_list = list()
    for ip, ip_info in test_ips_devices_info.items():
        device = ip_info["device"]
        devices_list.append(device)
    return sorted(devices_list)
