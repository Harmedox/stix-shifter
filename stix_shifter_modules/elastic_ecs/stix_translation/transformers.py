from stix_shifter_utils.stix_translation.src.utils.transformers import ValueTransformer
from stix_shifter_utils.utils import logger

LOGGER = logger.set_logger(__name__)

class PathToStixRegistryKey(ValueTransformer):
    """A value transformer to convert elastic ecs Registry path to windows-registry-key.key STIX"""

    @staticmethod
    def transform(registry):

        stix_root_keys_mapping = {"HKLM": "HKEY_LOCAL_MACHINE", "HKCU": "HKEY_CURRENT_USER",
                                  "HKCR": "HKEY_CLASSES_ROOT", "HKCC": "HKEY_CURRENT_CONFIG",
                                  "HKPD": "HKEY_PERFORMANCE_DATA", "HKU": "HKEY_USERS", "HKDD": "HKEY_DYN_DATA"}
        try:
            splited = registry.split("\\")
            if splited[0] in stix_root_keys_mapping:
                map_root_key = stix_root_keys_mapping[splited[0]]
                splited[0] = map_root_key
            splited = splited[:-1]
            key = '\\'.join(splited)
            return key;
        except ValueError:
            LOGGER.error("Cannot convert root key to Stix formatted windows registry key")


class PathToStixRegistryValue(ValueTransformer):
    """A value transformer to convert elastic ecs Registry path to windows-registry-key.value STIX"""

    @staticmethod
    def transform(registry):

        try:
            splited = registry.split("\\")
            value = splited[-1]
            return [{ 'name': value }]
        except ValueError:
            LOGGER.error("Cannot convert root key to Stix formatted windows registry key")
    
class SetEmailAttachmentBody(ValueTransformer):
    """A value transformer to convert email attachment to email-message.body_multipart STIX and reference file STIX"""

    @staticmethod
    def transform(obj):
        result = []
        for item in obj:
            val = {}
            file_attachment = item["file"]
            val["content_type"] = file_attachment["mime_type"]
            val["content_disposition"] = "attachment; filename=\"{}\"".format(file_attachment["name"])
            result.append(val)
        return result