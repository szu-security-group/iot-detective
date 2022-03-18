import subprocess
import signal
import requests
import re
import pymongo
from pprint import pprint

from bs4 import BeautifulSoup
from bs4.element import Tag

from utils import *

MONGODB_DOWNLOAD_SUFFIX = load_json(WEBSITE_SUFFIX_FILE)
MONGODB_NOT_DOWNLOAD_SUFFIX = ['cgi', 'conf', 'diff', 'doc', 'jpeg', 'jpg', 'json', 'list', 'pdf', 'png', 'psm1', 'txt']


def get_mongodb_collections():
    """
    返回MongoDB中的集合
    :return:
    """
    client = pymongo.MongoClient(MONGODB_CONNECTION_URL)
    iot_db = client["iot"]
    old_google_col = iot_db["old_google"]
    linux_whois_col = iot_db["linux_whois"]
    google_col = iot_db["google"]
    website_col = iot_db["website"]
    mix_col = iot_db["mix"]
    domains_knowledge_col = iot_db["new_domains_knowledge"]
    devices_knowledge_col = iot_db["new_devices_knowledge"]
    great_domains_col = iot_db["new_great_domains"]
    urls_col = iot_db["urls"]
    return old_google_col, linux_whois_col, google_col, website_col, mix_col, domains_knowledge_col, devices_knowledge_col, great_domains_col, urls_col


OLD_GOOGLE_COL, LINUX_WHOIS_COL, GOOGLE_COL, WEBSITE_COL, MIX_COL, DOMAINS_KNOWLEDGE_COL, DEVICES_KNOWLEDGE_COL, GREAT_DOMAINS_COL, URLS_COL = get_mongodb_collections()

COLLECTION_MAPPING = {
    "new_great_domains": {"collection": GREAT_DOMAINS_COL, "primary_key": "domain"},
    "new_devices_knowledge": {"collection": DEVICES_KNOWLEDGE_COL, "primary_key": "device"},
    "new_domains_knowledge": {"collection": DOMAINS_KNOWLEDGE_COL, "primary_key": "domain"},
    "google": {"collection": GOOGLE_COL, "primary_key": "query_info"},
    "linux_whois": {"collection": LINUX_WHOIS_COL, "primary_key": "domain"},
    "mix": {"collection": MIX_COL},
    "website": {"collection": WEBSITE_COL, "primary_key": "domain"},
}


def use_linux_whois():
    """
    使用linux中的whois来批量查询TEST_IPS_INFO_FILE中域名的whois信息
    :return:
    """
    test_ips_info = load_json(TEST_IPS_INFO_FILE, "ips_domains_tfidf")
    for ip, domains_tfidf in test_ips_info.items():
        merged_domains = get_merged_domains(domains_tfidf.keys())
        for merged_domain in merged_domains:
            guess_domain_vendor_by_whois(merged_domain)


def guess_domain_vendor_by_whois(merged_domain):
    """
    获取merged_domain的组织信息
    :param merged_domain: 查询的合并后的域名
    :return:
    """
    linux_whois_dict = LINUX_WHOIS_COL.find_one({"domain": merged_domain})
    # if linux_whois_dict is None or linux_whois_dict["whois_info"] is None:
    # 如果linux_whois中没有该domain的whois信息或者由于之前被拒绝连接导致记录的whois_info为空
    if linux_whois_dict is None:
        linux_whois_dict = call_linux_whois(merged_domain)
        if type(linux_whois_dict["whois_info"]) is dict:
            vendor = linux_whois_dict["whois_info"].get("Registrant Organization")
            if vendor is None:
                vendor = linux_whois_dict["whois_info"].get("Registrant")
        else:
            vendor = None
        linux_whois_dict["vendor"] = vendor
        LINUX_WHOIS_COL.update_one({"domain": merged_domain}, {
            "$set": {"whois_info": linux_whois_dict["whois_info"], "vendor": linux_whois_dict["vendor"]}},
                                   upsert=True)  # 修改为更新，如果不存在，则插入
    else:
        vendor = linux_whois_dict["vendor"]
    if vendor in WHOIS_REGISTRANT_BLACK_LIST:  # 需要排除掉一些保护隐私的REGISTRANT特别信息
        vendor = None
    return vendor


def call_linux_whois(domain):
    """
    在linux中调用whois，并获取返回的信息
    :param domain: 要查询的域名
    :return:
    """
    print("call_linux_whois: {domain}".format(domain=domain))
    duplicated_key = ["Domain Status", "Name Server"]
    command = "whois {domain}".format(domain=domain)
    res = timeout_command(command, timeout=3)
    start_flag = False
    res_dict = None
    if res is not None:
        try:
            for line in res:
                line = str(line, encoding="utf-8")
                if line.startswith("Domain Name:"):  # whois键值对区域起始位置
                    res_dict = dict()
                    key, value = line.split(":")
                    res_dict[key] = value.strip()
                    start_flag = True
                if start_flag:
                    if line.startswith("\n") or line.startswith(">>>"):  # whois键值对区域下面是一个空行
                        break
                    else:
                        key, value = line.split(":", 1)
                        if key in duplicated_key:  # 该键可能有多个值
                            if key in res_dict.keys():  # 如果结果字典中已经有该键了
                                res_dict[key].append(value.strip())  # 列表添加值
                            else:
                                res_dict[key] = [value.strip()]  # 为第一个值初始化列表
                        else:
                            res_dict[key] = value.strip()
        except:  # 如果解析错误，直接返回原文字节数组的字符串格式数组
            res_dict = [str(line, encoding="utf-8") for line in res]
    return {"domain": domain, "whois_info": res_dict}


def timeout_command(command, timeout):
    """call shell-command and either return its output or kill it
    if it doesn't normally exit within timeout seconds and return None"""
    cmd = command.split(" ")
    start = datetime.datetime.now()
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    while process.poll() is None:
        time.sleep(0.2)
        now = datetime.datetime.now()
        if (now - start).seconds > timeout:
            os.kill(process.pid, signal.SIGKILL)
            os.waitpid(-1, os.WNOHANG)
            return None
    return process.stdout.readlines()


def star_mongodb():
    """
    测试MongoDB的链接
    :return:
    """
    client = pymongo.MongoClient(MONGODB_CONNECTION_URL)
    dblist = client.list_database_names()
    print(dblist)


def get_google_results_num(query_info):
    """
    获取query_info的google搜索结果数目
    :param query_info: 查询内容
    :return:
    """
    url = "https://www.google.com/search?q=" + query_info
    r = requests.get(url, headers=RESULTS_NUM_HEADERS, proxies=PROXIES)
    logger.info("get_google_results_num: {url}".format(url=url))
    ### search_obj = re.search(r'.*<div id="result-stats">About (.*) results<nobr>.*', r.text)
    # search_obj = re.search(r'.*<div id="result-stats">(.*) result[s]?<nobr>.*', r.text)
    search_obj = re.search(r'.*<div id="result-stats">(.*)<nobr>.*', r.text)
    if search_obj is None:
        if "did not match any documents" in r.text or "找不到和您查询的" in r.text or "沒有任何文件" in r.text:
            results_num = 0
        else:
            raise Exception(logger.info("既没有匹配到结果数目，又没显示查无结果"))
    else:
        word_list = search_obj.group(1).split(" ")
        if word_list[1][0].isdigit():
            results_num = int(word_list[1].replace(",", ""))
        else:
            results_num = int(word_list[0].replace(",", ""))
    print(results_num)
    return results_num


def get_google_page_info(query_info):
    """
    获取google搜索页面结果
    :param query_info: 查询内容
    :return:
    """
    page_info_dict = dict()
    url = "https://www.google.com/search?q=" + query_info
    r = requests.get(url, headers=PAGE_INFO_HEADERS, proxies=PROXIES)
    # with open('hello.html', 'w', encoding='utf-8') as f:
    #     f.write(r.text)
    # with open('hello.html', 'r', encoding='utf-8') as f:
    #     html_text = f.read()
    # soup = BeautifulSoup(html_text, 'html.parser')
    soup = BeautifulSoup(r.text, 'html.parser')
    child1 = soup.body.contents[2]
    is_structured = True

    # 获取structured_data和related_searches
    structured_data = list()
    related_searches = list()
    search_child = None
    for child2 in child1.contents:
        if child2.name == "div":
            search_child = child2
            for child3 in child2.contents:
                if child3.name == "div":
                    for child4 in child3.contents:
                        if child4.name == "div":
                            for child5 in child4.contents:
                                if child5.name == "div":
                                    try:
                                        child6_0 = child5.find(name="div")
                                        a_tag = child6_0.find(name="a")
                                        child7_0 = a_tag.find(name="span")
                                        title_tag = child7_0
                                        title = title_tag.string
                                        print("title: ", title)
                                        url = a_tag.attrs["href"][len("/url?q="):].split("&", 1)[0]
                                        print("url: ", url)
                                        # child7_1 = child7_0.next_sibling.next_sibling
                                        # url_tag = child7_1.find(name="span")
                                        # url = url_tag.string
                                        # print("url: ", url)
                                        child6_1 = child6_0.next_sibling
                                        description_tag = child6_1.find(name="table").find(name="tr").find(
                                            name="td").find(
                                            name="div").find(name="div").find(name="span").find(name="span")
                                        description = description_tag.text
                                        print("description: ", description)
                                        print("-" * 100)
                                        structured_data.append({"title": title, "url": url, "description": description})
                                    except:
                                        is_structured = False
    if isinstance(search_child, Tag):
        for child3 in search_child.contents:
            if child3.name == "div":
                for child4 in child3.contents:
                    if child4.name == "div":
                        for child5 in child4.contents:
                            if child5.name == "div":
                                try:
                                    child6_0 = child5.find(name="div")
                                    for search_block in child6_0.next_siblings:
                                        related_search_tag = search_block.find(name="table").find(name="tbody").find(
                                            name="tr").find(name="td").find(
                                            name="a").find(name="span").find(name="span")
                                        related_search = related_search_tag.text.strip()
                                        print("related_search: ", related_search)
                                        print("-" * 100)
                                        related_searches.append(related_search)
                                except:
                                    related_searches = None

    # 获取特殊tag的文本值，包括span的文本值和a中的href属性值
    span_tags_collections = child1.find_all(name="span")
    span_list = [span_tag.string for span_tag in span_tags_collections if span_tag.string is not None]
    a_tags_collections = child1.find_all(name="a")
    url_list = [a_tag.attrs["href"].split("&", 1)[0] for a_tag in a_tags_collections]
    a_text = [a_tag.string for a_tag in a_tags_collections if a_tag.string is not None]

    page_info_dict["result"] = r.text
    page_info_dict["is_structured"] = is_structured
    page_info_dict["structured_data"] = structured_data
    page_info_dict["tags_data"] = {"span": span_list, "url": url_list, "a_text": a_text}
    page_info_dict["related_searches"] = related_searches
    return page_info_dict


def get_query_info_google_result(query_info):
    """
    获取query_info的google页面结果及结果数目
    :param query_info: 查询内容
    :return:
    """
    google_dict = GOOGLE_COL.find_one({"query_info": query_info})
    if google_dict is None:
        # 1. 获取页面数据
        page_info = get_google_page_info(query_info)

        # 2. 获取搜索结果数目
        results_num = get_google_results_num(query_info)

        google_dict = {
            "query_info": query_info,
            "page_info": page_info,
            "results_num": results_num
        }
        GOOGLE_COL.insert_one(google_dict)
    return google_dict


def direct_visit_domain(domain):
    """
    直接访问域名
    :param domain: 访问的域名
    :return:
    """
    print("direct visit domain: {domain}".format(domain=domain))
    protocol = "https://"
    url = protocol + domain
    r = direct_visit_url(url)
    print("status_code: {code}".format(code=r.status_code))
    # print(r.text)
    # print(len(r.text))
    return r


def direct_visit_url(url):
    """
    访问url
    :param url: 访问url
    :return:
    """
    print("-" * 100)
    print("direct visit url: {url}".format(url=url))
    r = requests.get(url, headers=ORDINARY_HEADERS, proxies=PROXIES, verify=False, timeout=10)
    print("status_code: {code}".format(code=r.status_code))
    # print(r.text)
    print(len(r.text))
    return r


def extract_html_tags_data(r_text):
    """
    从文本中获取html指定标签的数据
    :param r_text: 文本
    :return:
    """
    soup = BeautifulSoup(r_text, 'html.parser')
    span_list = list()
    url_list = list()
    a_text = list()
    for content in soup.contents:
        if isinstance(content, Tag):
            # 获取特殊tag的文本值，包括span的文本值和a中的href属性值
            span_tags_collections = content.find_all(name="span")
            span_list.extend([span_tag.string for span_tag in span_tags_collections if span_tag.string is not None])
            a_tags_collections = content.find_all(name="a")
            url_list.extend(
                [a_tag.attrs["href"].split("&", 1)[0] for a_tag in a_tags_collections if "href" in a_tag.attrs])
            a_text.extend([a_tag.string for a_tag in a_tags_collections if a_tag.string is not None])
    return {"span": span_list, "url": url_list, "a_text": a_text}


def visit_domain(domain):
    """
    访问域名
    :param domain: 域名
    :return:
    """
    website_dict = WEBSITE_COL.find_one({"domain": domain})
    if website_dict is not None:
        return website_dict
    else:
        try:
            print("visit domain: {domain}".format(domain=domain))
            r = direct_visit_domain(domain)
            tags_data = None
            if r.status_code == 200:
                tags_data = extract_html_tags_data(r.text)
            website_dict = {
                "domain": domain,
                "exception": None,
                "status_code": r.status_code,
                "response": r.text,
                "tags_data": tags_data
            }
        except Exception as error:
            print(error)
            website_dict = {
                "domain": domain,
                "exception": repr(error),
                "response": None,
            }
        WEBSITE_COL.insert_one(website_dict)
    return website_dict


def visit_url(url):
    """
    访问url
    :param url: 访问url
    :return: url的返回信息
    """
    urls_dict = URLS_COL.find_one({"url": url})
    if urls_dict is not None:
        return urls_dict
    else:
        try:
            print("visit url: {url}".format(url=url))
            suffix = url.rsplit(".", 1)[1]
            # if suffix not in MONGODB_DOWNLOAD_SUFFIX:
            #     raise Exception("不支持下载{suffix}后缀的url内容".format(suffix=suffix))
            if suffix in MONGODB_NOT_DOWNLOAD_SUFFIX:
                raise Exception("suffix: .{suffix} is not supported to download.".format(suffix=suffix))
            r = direct_visit_url(url)
            tags_data = None
            if r.status_code == 200:
                tags_data = extract_html_tags_data(r.text)
            if len(r.text) >= 5 * 1024 * 1024:
                raise Exception("DocumentTooLarge: BSON document too large")
            url_dict = {
                "url": url,
                "exception": None,
                "status_code": r.status_code,
                "response": r.text,
                "tags_data": tags_data
            }
        except Exception as error:
            logger.info(error)
            url_dict = {
                "url": url,
                "exception": repr(error),
                "response": None,
            }
        URLS_COL.insert_one(url_dict)
    return url_dict


# def visit_domains():
#     test_ips_domains_regularity_score = load_json(TEST_IPS_DOMAINS_REGULARITY_SCORE_FILE)
#     for ip, domains_regularity_score in test_ips_domains_regularity_score.items():
#         for domain, regularity_score in domains_regularity_score.items():
#             if regularity_score >= 0.5:
#                 visit_domain(domain)


def get_jsonful_from_mongodb(collection_name, sub_key=None):
    """
    从MongoDB中获取文档，并将其转化为带有主键的json格式
    :param collection_name:
    :param sub_key:
    :return:
    """
    jsonful_collection = dict()
    collection = COLLECTION_MAPPING[collection_name]["collection"]
    primary_key = COLLECTION_MAPPING[collection_name]["primary_key"]
    for document in collection.find():
        key = document[primary_key]
        del document[primary_key]
        del document["_id"]
        if sub_key is None:
            jsonful_collection[key] = document
        else:
            jsonful_collection[key] = document[sub_key]
    return jsonful_collection


def visit_google_url(url):
    """
    访问google搜索结果的URL，可能是"/url?q=https://github.com/StevenBlack/hosts/issues/506"这样的形式
    :param url:
    :return:
    """
    if url.startswith("/url?q="):
        url = url[len("/url?q="):]
    elif url.startswith("/"):
        url = "https://www.google.com" + url
    return visit_url(url)


def delete_train_knowledge():
    """
    删除训练知识
    :return:
    """
    # 需要删除的集合
    deleted_collections = [GREAT_DOMAINS_COL, DEVICES_KNOWLEDGE_COL, DOMAINS_KNOWLEDGE_COL, MIX_COL]
    for collection in deleted_collections:
        collection_name = collection.name
        if collection.drop():
            print("删除集合：{collection}  成功".format(collection=collection_name))
        else:
            print("删除集合：{collection}  失败".format(collection=collection_name))


def get_val_from_mongodb(collection_name, val_name):
    """获取mix的训练iot设备数"""
    collection = COLLECTION_MAPPING[collection_name]["collection"]
    val = collection.find_one({"info": "train"})[val_name]
    return val


def get_mongodb_devices_threshold():
    devices_threshold = dict()
    for device_knowledge in DEVICES_KNOWLEDGE_COL.find():
        device = device_knowledge["device"]
        threshold = device_knowledge["threshold"]
        devices_threshold[device] = float(threshold)
    return devices_threshold


def test_mongodb():
    domain = "test"
    val = {"idf": 1, "devices_num": 2}
    DOMAINS_KNOWLEDGE_COL.update_one({"domain": domain}, {"$set": val}, upsert=True)


def main():
    # use_linux_whois()
    # res = call_linux_whois("tenda.com.cn")
    # print(res)
    # star_mongodb()
    # direct_visit_url("http://US.lgtvsdp.com")
    # get_google_results_num("d3gjecg2uu2eaq.cloudfront.net")
    # res = get_query_info_google_result("api.smartthings.com device")
    # res = get_google_page_info("api.smartthings.com device")
    # pprint(res)
    # direct_visit_domain("belkin.com")
    # visit_domain("belkin.com")
    # visit_domains()
    # extract_html_tags_data("belkin.com")
    # devices_knowledge_dict = get_jsonful_from_mongodb(DEVICES_KNOWLEDGE_COL_NAME, "domains_tfidf")
    # store_json(devices_knowledge_dict, "devices_knowledge_dict.json")
    # tmp = get_jsonful_from_mongodb("great_domains", sub_key="devices")
    # store_json(tmp, "tmp.json")
    # get_query_info_google_result("dcp.dc1.philips.com device")
    # visit_google_urls()
    # direct_visit_url("https://www.google.com.hk/url?q=https://www.reddit.com/r/privacy/comments/3aby4d/a_few_questions_on_how_to_get_rid_of_googleapiscom/")
    # delete_train_knowledge()
    test_mongodb()
    pass


if __name__ == '__main__':
    main()
