from utils import *
from star_query import *


def collect_types():
    """
    获取设备类型知识
    :return:
    """
    feng_paper_types = {"camera", "ipcam", "netcam", "cam", "dvr", "router", "nvr", "nvs", "video server",
                        "video encoder", "video recorder", "diskstation", "rackstation", "printer", "copier", "scanner",
                        "switches", "modem", "switch", "gateway", "access point"}
    my_types = {"tv"}
    collected_type = set()
    collected_type.update(feng_paper_types)
    collected_type.update(my_types)
    devices_type = get_jsonful_from_mongodb("devices_knowledge", "type")
    for device, types in devices_type.items():
        for one_type in types.split(", "):
            collected_type.add(one_type)
    sorted_types = sorted(collected_type)
    redundant_types_dict = dict()
    for type in sorted_types:
        for other_type in sorted_types:
            if type in other_type and type != other_type:
                if type not in redundant_types_dict.keys():
                    redundant_types_dict[type] = [other_type]
                else:
                    redundant_types_dict[type].append(other_type)
    store_json({"types_list": sorted_types, "redundant_type_dict": redundant_types_dict}, COMMON_TYPES_FILE)


def collect_vendors():
    """
    获取训练集中的产商名单
    :return:
    """
    collected_vendors = set()
    devices_vendors = get_jsonful_from_mongodb("devices_knowledge", "vendor")
    for device, type in devices_vendors.items():
        collected_vendors.add(type)
    store_json({"vendors_list": sorted(list(collected_vendors), reverse=False)}, GLOBAL_VENDORS_FILE)


def main():
    collect_types()
    # collect_vendors()  # 获取训练集中的产商名单


if __name__ == '__main__':
    main()
