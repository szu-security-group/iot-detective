import requests
from bs4 import BeautifulSoup
import json

from utils import *

user_agent = 'Mozilla/4.0 (compatible; MSIE 5.5; Windows NT)'
headers = {'User-Agent': user_agent}


# r = requests.get('https://www.iotone.com/iotone500/', headers=headers)
# html_text = r.text



# companys = list()
# record_names = soup.find_all(class_="record-name")
# for i, record_name in enumerate(record_names):
#     if i == 0:
#         continue
#     tr = record_name.table.tr
#     for j, a in enumerate(tr.find_all(target="_blank")):
#         if j == 1:
#             company = a.string
#             companys.append(company)
# store_json({"vendors": companys}, "iotone500.json")


def main():

    url = "https://www.google.com/search?q=esdk-ffl.spotify.com"
    # url = "https://www.google.com/search?q=business.smartcamera.api.io.mi.com"
    # url = "https://www.google.com/search?q=hello"
    r = requests.get(url, headers=PAGE_INFO_HEADERS, proxies=PROXIES)
    # with open('hello.html', 'w', encoding='utf-8') as f:
    #     f.write(r.text)
    # with open('hello.html', 'r', encoding='utf-8') as f:
    #     html_text = f.read()
    html_text = r.text
    # store_json(r.text, "response.txt")
    # html_text = load_json("response.txt")
    soup = BeautifulSoup(html_text, 'html.parser')
    child1 = soup.body.contents[2]
    is_structured = True

    # 获取structured_data
    for child2 in child1.contents:
        if child2.name == "div":
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
                                        url = a_tag.attrs["href"].split("&", 1)[0]
                                        # child7_1 = child7_0.next_sibling.next_sibling
                                        # url_tag = child7_1.find(name="span")
                                        # url = url_tag.string
                                        # print("url: ", url)
                                        child6_1 = child6_0.next_sibling
                                        description_tag = child6_1.find(name="table").find(name="tr").find(
                                            name="td").find(
                                            name="div").find(name="div").find(name="span").find(name="span")
                                        description = description_tag.string
                                        print("description: ", description)
                                        print("-" * 100)
                                    except:
                                        is_structured = False
    # 获取特殊tag的文本值，包括span的文本值和a中的href属性值
    span_tags_collections = child1.find_all(name="span")
    span_list = [span_tag.string for span_tag in span_tags_collections]
    a_tags_collections = child1.find_all(name="a")
    url_list = [a_tag.attrs["href"].split("&", 1)[0] for a_tag in a_tags_collections]






if __name__ == '__main__':
    main()
