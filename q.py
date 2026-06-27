#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# MERGED - OLD (Bulk) + NEW (Rizer Endpoint) - RENDER COMPATIBLE
# TELEGRAM @beotherjkman

import json
import requests
import sys
import binascii
import jwt as pyjwt
import time
import random
import os
import hashlib
import re
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from queue import Queue
from datetime import datetime
from collections import defaultdict
from flask import Flask, request, jsonify
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import symbol_database as _symbol_database
from google.protobuf.internal import builder as _builder
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ==================== CONSTANTS ====================
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
RIZER = "1.126.1"
FREEFIRE_VERSION = "OB54"
MAJOR_LOGIN_URL = "https://loginbp.ggblueshark.com/MajorLogin"
INSPECT_URL = "https://100067.connect.garena.com/oauth/token/inspect"

# AES KEYS
AES_KEY = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
AES_IV = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])

LOGIN_HEADERS = {
    "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
    "Connection": "Keep-Alive",
    "Accept-Encoding": "gzip",
    "Content-Type": "application/octet-stream",
    "Expect": "100-continue",
    "X-Unity-Version": "2018.4.11f1",
    "X-GA": "v1 1",
    "ReleaseVersion": FREEFIRE_VERSION,
}

# Thread-safe containers
results_lock = threading.Lock()
token_cache = {}
token_cache_lock = threading.Lock()
stats = {"processed": 0, "successful": 0, "failed": 0, "duplicates": 0}
stats_lock = threading.Lock()

# ==================== PROTOBUF DEFINITIONS ====================
_sym_db = _symbol_database.Default()

# --- MAJOR LOGIN PROTO (Original from New File) ---
DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\x13MajorLoginReq.proto\"\xfa\n\n\nMajorLogin\x12\x12\n\nevent_time\x18\x03 \x01(\t\x12\x11\n\tgame_name\x18\x04 \x01(\t\x12\x13\n\x0bplatform_id\x18\x05 \x01(\x05\x12\x16\n\x0e\x63lient_version\x18\x07 \x01(\t\x12\x17\n\x0fsystem_software\x18\x08 \x01(\t\x12\x17\n\x0fsystem_hardware\x18\t \x01(\t\x12\x18\n\x10telecom_operator\x18\n \x01(\t\x12\x14\n\x0cnetwork_type\x18\x0b \x01(\t\x12\x14\n\x0cscreen_width\x18\x0c \x01(\r\x12\x15\n\rscreen_height\x18\r \x01(\r\x12\x12\n\nscreen_dpi\x18\x0e \x01(\t\x12\x19\n\x11processor_details\x18\x0f \x01(\t\x12\x0e\n\x06memory\x18\x10 \x01(\r\x12\x14\n\x0cgpu_renderer\x18\x11 \x01(\t\x12\x13\n\x0bgpu_version\x18\x12 \x01(\t\x12\x18\n\x10unique_device_id\x18\x13 \x01(\t\x12\x11\n\tclient_ip\x18\x14 \x01(\t\x12\x10\n\x08language\x18\x15 \x01(\t\x12\x0f\n\x07open_id\x18\x16 \x01(\t\x12\x14\n\x0copen_id_type\x18\x17 \x01(\t\x12\x13\n\x0b\x64\x65vice_type\x18\x18 \x01(\t\x12\'\n\x10memory_available\x18\x19 \x01(\x0b\x32\r.GameSecurity\x12\x14\n\x0c\x61\x63\x63\x65ss_token\x18\x1d \x01(\t\x12\x17\n\x0fplatform_sdk_id\x18\x1e \x01(\x05\x12\x1a\n\x12network_operator_a\x18) \x01(\t\x12\x16\n\x0enetwork_type_a\x18* \x01(\t\x12\x1c\n\x14\x63lient_using_version\x18\x39 \x01(\t\x12\x1e\n\x16\x65xternal_storage_total\x18< \x01(\x05\x12\"\n\x1a\x65xternal_storage_available\x18= \x01(\x05\x12\x1e\n\x16internal_storage_total\x18> \x01(\x05\x12\"\n\x1ainternal_storage_available\x18? \x01(\x05\x12#\n\x1bgame_disk_storage_available\x18@ \x01(\x05\x12\x1f\n\x17game_disk_storage_total\x18\x41 \x01(\x05\x12%\n\x1d\x65xternal_sdcard_avail_storage\x18\x42 \x01(\x05\x12%\n\x1d\x65xternal_sdcard_total_storage\x18\x43 \x01(\x05\x12\x10\n\x08login_by\x18I \x01(\x05\x12\x14\n\x0clibrary_path\x18J \x01(\t\x12\x12\n\nreg_avatar\x18L \x01(\x05\x12\x15\n\rlibrary_token\x18M \x01(\t\x12\x14\n\x0c\x63hannel_type\x18N \x01(\x05\x12\x10\n\x08\x63pu_type\x18O \x01(\x05\x12\x18\n\x10\x63pu_architecture\x18Q \x01(\t\x12\x1b\n\x13\x63lient_version_code\x18S \x01(\t\x12\x14\n\x0cgraphics_api\x18V \x01(\t\x12\x1d\n\x15supported_astc_bitset\x18W \x01(\r\x12\x1a\n\x12login_open_id_type\x18X \x01(\x05\x12\x18\n\x10\x61nalytics_detail\x18Y \x01(\x0c\x12\x14\n\x0cloading_time\x18\\ \x01(\r\x12\x17\n\x0frelease_channel\x18] \x01(\t\x12\x12\n\nextra_info\x18^ \x01(\t\x12 \n\x18\x61ndroid_engine_init_flag\x18_ \x01(\r\x12\x0f\n\x07if_push\x18\x61 \x01(\x05\x12\x0e\n\x06is_vpn\x18\x62 \x01(\x05\x12\x1c\n\x14origin_platform_type\x18\x63 \x01(\t\x12\x1d\n\x15primary_platform_type\x18\x64 \x01(\t\"5\n\x0cGameSecurity\x12\x0f\n\x07version\x18\x06 \x01(\x05\x12\x14\n\x0chidden_value\x18\x08 \x01(\x04\x62\x06proto3')
_globals = globals()
_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, _globals)
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, 'MajorLoginReq_pb2', _globals)
if not _descriptor._USE_C_DESCRIPTORS:
    DESCRIPTOR._loaded_options = None
    _globals['_MAJORLOGIN']._serialized_start = 24
    _globals['_MAJORLOGIN']._serialized_end = 1426
    _globals['_GAMESECURITY']._serialized_start = 1428
    _globals['_GAMESECURITY']._serialized_end = 1481
MajorLogin = _globals['MajorLogin']
GameSecurity = _globals['GameSecurity']

# --- MAJOR LOGIN RES PROTO ---
DESCRIPTOR2 = _descriptor_pool.Default().AddSerializedFile(b'\n\x13MajorLoginRes.proto\"|\n\rMajorLoginRes\x12\x13\n\x0b\x61\x63\x63ount_uid\x18\x01 \x01(\x04\x12\x0e\n\x06region\x18\x02 \x01(\t\x12\r\n\x05token\x18\x08 \x01(\t\x12\x0b\n\x03url\x18\n \x01(\t\x12\x11\n\ttimestamp\x18\x15 \x01(\x03\x12\x0b\n\x03key\x18\x16 \x01(\x0c\x12\n\n\x02iv\x18\x17 \x01(\x0c\x62\x06proto3')
_globals2 = globals()
_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR2, _globals2)
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR2, 'MajorLoginRes_pb2', _globals2)
if not _descriptor._USE_C_DESCRIPTORS:
    DESCRIPTOR2._loaded_options = None
    _globals2['_MAJORLOGINRES']._serialized_start = 23
    _globals2['_MAJORLOGINRES']._serialized_end = 147
MajorLoginRes = _globals2['MajorLoginRes']

# --- GAMEDATA PROTO (Old File) ---
GAMEDATA_DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(
    b'\n\x08my.proto\"\xae\t\n\x08GameData\x12\x11\n\ttimestamp\x18\x03 \x01(\t\x12\x11\n\tgame_name\x18\x04 \x01(\t\x12\x14\n\x0cgame_version\x18\x05 \x01(\x05\x12\x14\n\x0cversion_code\x18\x07 \x01(\t\x12\x0f\n\x07os_info\x18\x08 \x01(\t\x12\x13\n\x0b\x64\x65vice_type\x18\t \x01(\t\x12\x18\n\x10network_provider\x18\n \x01(\t\x12\x17\n\x0f\x63onnection_type\x18\x0b \x01(\t\x12\x14\n\x0cscreen_width\x18\x0c \x01(\x05\x12\x15\n\rscreen_height\x18\r \x01(\x05\x12\x0b\n\x03\x64pi\x18\x0e \x01(\t\x12\x10\n\x08\x63pu_info\x18\x0f \x01(\t\x12\x11\n\ttotal_ram\x18\x10 \x01(\x05\x12\x10\n\x08gpu_name\x18\x11 \x01(\t\x12\x13\n\x0bgpu_version\x18\x12 \x01(\t\x12\x0f\n\x07user_id\x18\x13 \x01(\t\x12\x12\n\nip_address\x18\x14 \x01(\t\x12\x10\n\x08language\x18\x15 \x01(\t\x12\x0f\n\x07open_id\x18\x16 \x01(\t\x12\x15\n\rplatform_type\x18\x17 \x01(\x05\x12\x1a\n\x12\x64\x65vice_form_factor\x18\x18 \x01(\t\x12\x14\n\x0c\x64\x65vice_model\x18\x19 \x01(\t\x12\x14\n\x0c\x61\x63\x63\x65ss_token\x18\x1d \x01(\t\x12\x18\n\x10unknown_field_30\x18\x1e \x01(\x05\x12\"\n\x1asecondary_network_provider\x18) \x01(\t\x12!\n\x19secondary_connection_type\x18* \x01(\t\x12\x11\n\tunique_id\x18\x39 \x01(\t\x12\x10\n\x08\x66ield_60\x18< \x01(\x05\x12\x10\n\x08\x66ield_61\x18= \x01(\x05\x12\x10\n\x08\x66ield_62\x18> \x01(\x05\x12\x10\n\x08\x66ield_63\x18? \x01(\x05\x12\x10\n\x08\x66ield_64\x18@ \x01(\x05\x12\x10\n\x08\x66ield_65\x18\x41 \x01(\x05\x12\x10\n\x08\x66ield_66\x18\x42 \x01(\x05\x12\x10\n\x08\x66ield_67\x18\x43 \x01(\x05\x12\x10\n\x08\x66ield_70\x18\x46 \x01(\x05\x12\x10\n\x08\x66ield_73\x18I \x01(\x05\x12\x14\n\x0clibrary_path\x18J \x01(\t\x12\x10\n\x08\x66ield_76\x18L \x01(\x05\x12\x10\n\x08\x61pk_info\x18M \x01(\t\x12\x10\n\x08\x66ield_78\x18N \x01(\x05\x12\x10\n\x08\x66ield_79\x18O \x01(\x05\x12\x17\n\x0fos_architecture\x18Q \x01(\t\x12\x14\n\x0c\x62uild_number\x18S \x01(\t\x12\x10\n\x08\x66ield_85\x18U \x01(\x05\x12\x18\n\x10graphics_backend\x18V \x01(\t\x12\x19\n\x11max_texture_units\x18W \x01(\x05\x12\x15\n\rrendering_api\x18X \x01(\x05\x12\x18\n\x10\x65ncoded_field_89\x18Y \x01(\t\x12\x10\n\x08\x66ield_92\x18\\ \x01(\x05\x12\x13\n\x0bmarketplace\x18] \x01(\t\x12\x16\n\x0e\x65ncryption_key\x18^ \x01(\t\x12\x15\n\rtotal_storage\x18_ \x01(\x05\x12\x10\n\x08\x66ield_97\x18\x61 \x01(\x05\x12\x10\n\x08\x66ield_98\x18\x62 \x01(\x05\x12\x10\n\x08\x66ield_99\x18\x63 \x01(\t\x12\x11\n\tfield_100\x18\x64 \x01(\tb\x06proto3'
)
_builder.BuildMessageAndEnumDescriptors(GAMEDATA_DESCRIPTOR, _globals)
_builder.BuildTopDescriptorsAndMessages(GAMEDATA_DESCRIPTOR, 'my_pb2', _globals)
GameData = _sym_db.GetSymbol('GameData')

# --- GARENA420 PROTO ---
GARENA420_DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(
    b'\n\x13jwt_generator.proto\"\xd2\x02\n\nGarena_420\x12\x12\n\naccount_id\x18\x01 \x01(\x03\x12\x0e\n\x06region\x18\x02 \x01(\t\x12\r\n\x05place\x18\x03 \x01(\t\x12\x10\n\x08location\x18\x04 \x01(\t\x12\x0e\n\x06status\x18\x05 \x01(\t\x12\r\n\x05token\x18\x08 \x01(\t\x12\n\n\x02id\x18\t \x01(\x05\x12\x0b\n\x03\x61pi\x18\n \x01(\t\x12\x0e\n\x06number\x18\x0c \x01(\x05\x12\x1e\n\tGarena420\x18\x0f \x01(\x0b\x32\x0b.Garena_420\x12\x0c\n\x04\x61rea\x18\x10 \x01(\t\x12\x11\n\tmain_area\x18\x12 \x01(\t\x12\x0c\n\x04\x63ity\x18\x13 \x01(\t\x12\x0c\n\x04name\x18\x14 \x01(\t\x12\x11\n\ttimestamp\x18\x15 \x01(\x03\x12\x0e\n\x06\x62inary\x18\x16 \x01(\x0c\x12\x13\n\x0b\x62inary_data\x18\x17 \x01(\x0c\x1a\"\n\x12\x44\x65\x63rypted_Payloads\x12\x0c\n\x04type\x18\x01 \x01(\x05\x62\x06proto3'
)
_builder.BuildMessageAndEnumDescriptors(GARENA420_DESCRIPTOR, _globals)
_builder.BuildTopDescriptorsAndMessages(GARENA420_DESCRIPTOR, 'output_pb2', _globals)
Garena_420 = _sym_db.GetSymbol('Garena_420')

# ==================== CRYPTO ====================
def encrypt_aes(data: bytes) -> bytes:
    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    return cipher.encrypt(pad(data, AES.block_size))

def encrypt_data(data_bytes):
    return encrypt_aes(data_bytes)

# ==================== HELPERS ====================
def decode_jwt(token):
    try:
        decoded = pyjwt.decode(token, options={"verify_signature": False})
        return str(decoded.get("account_id")), decoded.get("nickname"), decoded.get("lock_region")
    except:
        try:
            parts = token.split('.')
            if len(parts) == 3:
                import base64
                payload = json.loads(base64.urlsafe_b64decode(parts[1] + '==').decode())
                return str(payload.get("account_id")), payload.get("nickname"), payload.get("lock_region")
        except:
            pass
    return None, None, None

def get_openid_from_inspect(access_token):
    url = f"{INSPECT_URL}?token={access_token}"
    headers = {"User-Agent": "GarenaMSDK/4.0.30", "Accept": "application/json"}
    try:
        resp = requests.get(url, headers=headers, timeout=10, verify=False)
        if resp.status_code == 200:
            data = resp.json()
            return data.get("open_id")
    except:
        pass
    return None

def login_with_uid_pass(uid, password):
    """Login to Garena using UID and password to get access token"""
    try:
        device_id = hashlib.md5(f"{uid}{time.time()}{random.random()}".encode()).hexdigest()
        login_data = {
            "username": uid,
            "password": password,
            "grant_type": "password",
            "client_id": "100067",
            "client_secret": "e23e884daa5bd67944b2c6c0f57b240c",
        }
        headers = {
            "User-Agent": "GarenaMSDK/4.0.30",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Device-Id": device_id
        }
        response = requests.post(
            "https://account.garena.com/api/v1/login",
            json=login_data,
            headers=headers,
            timeout=15,
            verify=False
        )
        if response.status_code == 200:
            data = response.json()
            if data.get("code") == 0 and data.get("data", {}).get("access_token"):
                return data["data"]["access_token"]
        
        alt_data = {
            "email": uid if '@' in uid else None,
            "username": uid if '@' not in uid else None,
            "password": password
        }
        alt_response = requests.post(
            "https://api.garena.com/auth/v1/login",
            json=alt_data,
            headers={"User-Agent": "Garena/4.0.30", "Content-Type": "application/json"},
            timeout=15,
            verify=False
        )
        if alt_response.status_code == 200:
            alt_json = alt_response.json()
            if alt_json.get("access_token"):
                return alt_json["access_token"]
        return None
    except Exception as e:
        return None

# ==================== MAJOR LOGIN BUILDER (New File Style) ====================
def build_major_login(open_id: str, access_token: str, platform_type: int) -> bytes:
    major = MajorLogin()
    major.event_time = "2025-03-23 12:00:00"
    major.game_name = "free fire"
    major.platform_id = 1
    major.client_version = RIZER
    major.system_software = "Android OS 9 / API-28 (PQ3B.190801.10101846/G9650ZHU2ARC6)"
    major.system_hardware = "Handheld"
    major.telecom_operator = "TELEGRAM:@beotherjkman"
    major.network_type = "WIFI"
    major.screen_width = 1920
    major.screen_height = 1080
    major.screen_dpi = "280"
    major.processor_details = "ARM64 FP ASIMD AES VMH | 2865 | 4"
    major.memory = 3003
    major.gpu_renderer = "Adreno (TM) 640"
    major.gpu_version = "OpenGL ES 3.1 v1.46"
    major.unique_device_id = "Google|34a7dcdf-a7d5-4cb6-8d7e-3b0e448a0c57"
    major.client_ip = "223.191.51.89"
    major.language = "en"
    major.open_id = open_id
    major.open_id_type = "4"
    major.device_type = "Handheld"
    major.memory_available.version = 55
    major.memory_available.hidden_value = 81
    major.access_token = access_token
    major.platform_sdk_id = 1
    major.network_operator_a = "Verizon"
    major.network_type_a = "WIFI"
    major.client_using_version = "7428b253defc164018c604a1ebbfebdf"
    major.external_storage_total = 36235
    major.external_storage_available = 31335
    major.internal_storage_total = 2519
    major.internal_storage_available = 703
    major.game_disk_storage_available = 25010
    major.game_disk_storage_total = 26628
    major.external_sdcard_avail_storage = 32992
    major.external_sdcard_total_storage = 36235
    major.login_by = 3
    major.library_path = "/data/app/com.dts.freefireth-YPKM8jHEwAJlhpmhDhv5MQ==/lib/arm64"
    major.reg_avatar = 1
    major.library_token = "5b892aaabd688e571f688053118a162b|/data/app/com.dts.freefireth-YPKM8jHEwAJlhpmhDhv5MQ==/base.apk"
    major.channel_type = 3
    major.cpu_type = 2
    major.cpu_architecture = "64"
    major.client_version_code = "2019118695"
    major.graphics_api = "OpenGLES2"
    major.supported_astc_bitset = 16383
    major.login_open_id_type = 4
    major.analytics_detail = b"FwQVTgUPX1UaUllDDwcWCRBpWA0FUgsvA1snWlBaO1kFYg=="
    major.loading_time = 13564
    major.release_channel = "android"
    major.extra_info = "KqsHTymw5/5GB23YGniUYN2/q47GATrq7eFeRatf0NkwLKEMQ0PK5BKEk72dPflAxUlEBir6Vtey83XqF593qsl8hwY="
    major.android_engine_init_flag = 110009
    major.if_push = 1
    major.is_vpn = 1
    major.origin_platform_type = str(platform_type)
    major.primary_platform_type = str(platform_type)
    return major.SerializeToString()

def try_major_login(open_id: str, access_token: str, platform_type: int):
    payload = build_major_login(open_id, access_token, platform_type)
    encrypted_payload = encrypt_aes(payload)
    
    headers = {
        "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 11; ASUS_Z01QD Build/PI)",
        "Connection": "Keep-Alive",
        "Accept-Encoding": "gzip",
        "Content-Type": "application/x-www-form-urlencoded",
        "X-Unity-Version": "2018.4.11f1",
        "X-GA": "v1 1",
        "ReleaseVersion": "OB54"
    }
    try:
        resp = requests.post(MAJOR_LOGIN_URL, data=encrypted_payload, headers=headers, verify=False, timeout=10)
        if resp.status_code != 200:
            return None
        major_res = MajorLoginRes()
        major_res.ParseFromString(resp.content)
        if major_res.token:
            return {
                "account_uid": str(major_res.account_uid),
                "region": major_res.region,
                "token": major_res.token,
                "url": major_res.url,
                "timestamp": major_res.timestamp,
                "key": major_res.key.hex(),
                "iv": major_res.iv.hex()
            }
    except Exception as e:
        print(f"MajorLogin error for platform {platform_type}: {e}")
    return None

# ==================== OLD-STYLE MAJOR LOGIN (Alternative) ====================
def major_login_old(access_token, open_id):
    platforms = [8, 3, 4, 6, 1, 2, 5, 7]
    for pt in platforms:
        try:
            game = GameData()
            game.timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
            game.game_name = "free fire"
            game.game_version = 1
            game.version_code = "2.124.1"
            game.os_info = "Android OS 9 / API-28 (PI/rel.cjw.20220518.114133)"
            game.device_type = "Handheld"
            game.network_provider = "Verizon Wireless"
            game.connection_type = "WIFI"
            game.screen_width = 1280
            game.screen_height = 960
            game.dpi = "240"
            game.cpu_info = "ARMv7 VFPv3 NEON VMH | 2400 | 4"
            game.total_ram = 5951
            game.gpu_name = "Adreno (TM) 640"
            game.gpu_version = "OpenGL ES 3.0"
            game.user_id = f"Google|{hashlib.md5(open_id.encode()).hexdigest()}"
            game.ip_address = f"{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,255)}"
            game.language = "en"
            game.open_id = open_id
            game.access_token = access_token
            game.platform_type = pt
            game.field_99 = str(pt)
            game.field_100 = str(pt)
            
            ser = game.SerializeToString()
            enc = encrypt_data(ser)
            edata = bytes.fromhex(binascii.hexlify(enc).decode('utf-8'))
            resp = requests.post(MAJOR_LOGIN_URL, data=edata, headers=LOGIN_HEADERS, verify=False, timeout=10)
            
            if resp.status_code == 200:
                msg = Garena_420()
                msg.ParseFromString(resp.content)
                if msg.token:
                    return msg.token
        except:
            continue
    return None

# ==================== PROCESS FUNCTIONS (From Old File) ====================
def process_access_token(access_token, timestamp=None):
    if timestamp is None:
        timestamp = time.time()
    
    with token_cache_lock:
        if access_token in token_cache:
            cached_result = token_cache[access_token]
            if cached_result.get('timestamp', 0) >= timestamp:
                with stats_lock:
                    stats['duplicates'] += 1
                return cached_result.get('result')
    
    result = {
        "access_token": access_token,
        "success": False,
        "jwt": None,
        "uid": None,
        "region": None,
        "error": None,
        "timestamp": timestamp
    }
    
    open_id = get_openid_from_inspect(access_token)
    if not open_id:
        result["error"] = "Invalid access token or could not fetch open_id"
        with token_cache_lock:
            token_cache[access_token] = {'result': result, 'timestamp': timestamp}
        return result
    
    # Try NEW style first
    new_style_platforms = [2, 3, 4, 6, 8]
    for pt in new_style_platforms:
        ml_result = try_major_login(open_id, access_token, pt)
        if ml_result and ml_result.get('token'):
            jwt_token = ml_result['token']
            uid, name, region = decode_jwt(jwt_token)
            if uid:
                result["success"] = True
                result["jwt"] = jwt_token
                result["uid"] = uid
                result["region"] = region
                result["nickname"] = name
                result["account_uid"] = ml_result.get("account_uid")
                result["url"] = ml_result.get("url")
                with token_cache_lock:
                    token_cache[access_token] = {'result': result, 'timestamp': timestamp}
                return result
    
    # Fallback to OLD style
    jwt_token = major_login_old(access_token, open_id)
    if jwt_token:
        uid, name, region = decode_jwt(jwt_token)
        if uid:
            result["success"] = True
            result["jwt"] = jwt_token
            result["uid"] = uid
            result["region"] = region
            result["nickname"] = name
            with token_cache_lock:
                token_cache[access_token] = {'result': result, 'timestamp': timestamp}
            return result
    
    result["error"] = "MajorLogin failed. Token may be expired or invalid"
    with token_cache_lock:
        token_cache[access_token] = {'result': result, 'timestamp': timestamp}
    return result

def process_uid_pass(uid, password, timestamp=None):
    if timestamp is None:
        timestamp = time.time()
    
    result = {
        "uid": uid,
        "password": password,
        "success": False,
        "jwt": None,
        "region": None,
        "access_token": None,
        "error": None,
        "timestamp": timestamp
    }
    
    access_token = login_with_uid_pass(uid, password)
    if not access_token:
        result["error"] = "Failed to login with UID:PASS - invalid credentials"
        return result
    
    result["access_token"] = access_token
    jwt_result = process_access_token(access_token, timestamp)
    
    if jwt_result.get("success"):
        result["success"] = True
        result["jwt"] = jwt_result["jwt"]
        result["region"] = jwt_result["region"]
        result["uid"] = jwt_result["uid"]
    else:
        result["error"] = jwt_result.get("error", "Unknown error")
    
    return result

# ==================== BULK PROCESSING (From Old File) ====================
def load_tokens_from_json(filepath):
    with open(filepath, 'r') as f:
        content = f.read()
    content = re.sub(r',\s*\]', ']', content)
    content = re.sub(r',\s*\}', '}', content)
    content = re.sub(r'//.*?$', '', content, flags=re.MULTILINE)
    content = re.sub(r'/\*.*?\*/', '', content, flags=re.DOTALL)
    try:
        data = json.loads(content)
    except json.JSONDecodeError as e:
        import ast
        try:
            data = ast.literal_eval(content)
        except:
            raise json.JSONDecodeError(f"Invalid JSON: {e}", content, e.pos)
    
    tokens = []
    if isinstance(data, list):
        for item in data:
            if isinstance(item, dict):
                token = item.get('token') or item.get('access_token') or item.get('ACCESS TOKEN')
                if token:
                    tokens.append(token)
            elif isinstance(item, str):
                tokens.append(item)
    elif isinstance(data, dict):
        token = data.get('token') or data.get('access_token') or data.get('ACCESS TOKEN')
        if token:
            tokens.append(token)
    return tokens

def load_credentials_from_file(filepath):
    credentials = []
    with open(filepath, 'r') as f:
        for line in f:
            line = line.strip()
            if line and ':' in line:
                uid, password = line.split(':', 1)
                credentials.append({'uid': uid.strip(), 'password': password.strip()})
    return credentials

def save_results_to_json(results, output_file="jwttoken.json"):
    latest_results = {}
    for r in results:
        if r.get('success') and r.get('jwt'):
            key = r.get('uid') or r.get('access_token')
            if key:
                if key not in latest_results or latest_results[key].get('timestamp', 0) < r.get('timestamp', 0):
                    latest_results[key] = r
    
    output = []
    for r in latest_results.values():
        if r.get('success') and r.get('jwt'):
            region = r.get('region', 'ind').lower()
            api_url = f"https://client.{region}.freefiremobile.com"
            output.append({
                "uid": r.get('uid'),
                "token": r.get('jwt'),
                "region": r.get('region'),
                "api": api_url,
                "generated_at": datetime.now().isoformat()
            })
    
    script_output_path = os.path.join(SCRIPT_DIR, output_file)
    with open(script_output_path, 'w') as f:
        json.dump(output, f, indent=2)
    
    return script_output_path, len(output)

def bulk_process_threaded(items, process_func, max_workers=5, delay=0):
    results = []
    completed = 0
    total = len(items)
    item_queue = Queue()
    for item in items:
        item_queue.put(item)
    
    def worker():
        nonlocal completed
        while True:
            try:
                item = item_queue.get(timeout=1)
            except:
                break
            timestamp = time.time()
            if isinstance(item, dict) and 'access_token' in item:
                result = process_func(item['access_token'], timestamp)
            elif isinstance(item, dict) and 'uid' in item:
                result = process_func(item['uid'], item['password'], timestamp)
            elif isinstance(item, str):
                result = process_func(item, timestamp)
            else:
                result = {"success": False, "error": "Invalid item type"}
            
            with results_lock:
                results.append(result)
                completed += 1
                with stats_lock:
                    if result.get('success'):
                        stats['successful'] += 1
                    else:
                        stats['failed'] += 1
                    stats['processed'] += 1
            
            if delay > 0:
                time.sleep(delay)
            item_queue.task_done()
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(worker) for _ in range(max_workers)]
        for future in as_completed(futures):
            pass
    return results

def smart_deduplicate_tokens(tokens):
    seen = set()
    unique_tokens = []
    for token in tokens:
        if token not in seen:
            seen.add(token)
            unique_tokens.append(token)
        else:
            with stats_lock:
                stats['duplicates'] += 1
    return unique_tokens

# ==================== FLASK APP ====================
app = Flask(__name__)

# ==================== API ENDPOINTS ====================

@app.route('/rizer', methods=['GET'])
def rizer_endpoint():
    """Single token processing - Original Rizer endpoint"""
    access_token = request.args.get('access_token')
    if not access_token:
        return jsonify({"error": "Missing 'access_token' parameter"}), 400
    
    inspect_url = f"{INSPECT_URL}?token={access_token}"
    try:
        insp_resp = requests.get(inspect_url, timeout=10)
        if insp_resp.status_code != 200:
            return jsonify({"error": "Failed to inspect token", "status_code": insp_resp.status_code}), 400
        insp_data = insp_resp.json()
        open_id = insp_data.get('open_id')
        if not open_id:
            return jsonify({"error": "open_id not found in inspect response"}), 400
    except Exception as e:
        return jsonify({"error": f"Inspect request failed: {str(e)}"}), 500
    
    platform_types = [2, 3, 4, 6, 8]
    last_error = None
    for pt in platform_types:
        result = try_major_login(open_id, access_token, pt)
        if result:
            jwt_decoded = decode_jwt(result['token'])
            return jsonify({
                "success": True,
                "platform_type_used": pt,
                "jwt": result['token'],
                "jwt_decoded": {"header": {}, "payload": jwt_decoded},
                "account_uid": result['account_uid'],
                "region": result['region'],
                "url": result['url'],
                "timestamp": result['timestamp']
            })
        else:
            last_error = f"Failed with platform_type {pt}"
    
    return jsonify({
        "success": False,
        "error": "MajorLogin failed. Account may be banned, not registered, or token invalid.",
        "detail": last_error
    }), 401

@app.route('/bulk', methods=['POST'])
def bulk_endpoint():
    """Bulk process tokens from JSON body"""
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Invalid JSON body"}), 400
    
    tokens = []
    if isinstance(data, list):
        for item in data:
            if isinstance(item, dict):
                token = item.get('token') or item.get('access_token')
                if token:
                    tokens.append(token)
            elif isinstance(item, str):
                tokens.append(item)
    elif isinstance(data, dict):
        token = data.get('token') or data.get('access_token')
        if token:
            tokens.append(token)
        items = data.get('tokens') or data.get('items') or data.get('list')
        if isinstance(items, list):
            for item in items:
                if isinstance(item, str):
                    tokens.append(item)
                elif isinstance(item, dict):
                    t = item.get('token') or item.get('access_token')
                    if t:
                        tokens.append(t)
    
    if not tokens:
        return jsonify({"error": "No tokens found in request body"}), 400
    
    # Get thread count from request
    max_workers = request.args.get('threads', 10)
    try:
        max_workers = int(max_workers)
    except:
        max_workers = 10
    
    original_count = len(tokens)
    tokens = smart_deduplicate_tokens(tokens)
    
    start_time = time.time()
    results = bulk_process_threaded(tokens, process_access_token, max_workers, 0.3)
    elapsed = time.time() - start_time
    
    successful = [r for r in results if r.get('success')]
    
    output_file, count = save_results_to_json(results)
    
    return jsonify({
        "success": True,
        "summary": {
            "total_received": original_count,
            "unique_processed": len(tokens),
            "successful": stats['successful'],
            "failed": stats['failed'],
            "duplicates_removed": original_count - len(tokens) + stats['duplicates'],
            "time_taken_seconds": round(elapsed, 2),
            "speed_tokens_per_sec": round(len(tokens)/elapsed, 2) if elapsed > 0 else 0
        },
        "results": successful[:50],  # First 50 successful
        "total_results": count,
        "output_file": output_file
    })

@app.route('/bulk/tokens', methods=['POST'])
def bulk_tokens_from_file():
    """Upload tokens JSON file and process"""
    if 'file' not in request.files:
        return jsonify({"error": "No file uploaded. Use form-data with key 'file'"}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "Empty filename"}), 400
    
    try:
        content = file.read().decode('utf-8')
        tokens = json.loads(content)
        
        token_list = []
        if isinstance(tokens, list):
            for item in tokens:
                if isinstance(item, dict):
                    t = item.get('token') or item.get('access_token') or item.get('ACCESS TOKEN')
                    if t:
                        token_list.append(t)
                elif isinstance(item, str):
                    token_list.append(item)
        elif isinstance(tokens, dict):
            t = tokens.get('token') or tokens.get('access_token') or tokens.get('ACCESS TOKEN')
            if t:
                token_list.append(t)
        
        if not token_list:
            return jsonify({"error": "No tokens found in uploaded file"}), 400
        
        max_workers = request.args.get('threads', 10)
        try:
            max_workers = int(max_workers)
        except:
            max_workers = 10
        
        original_count = len(token_list)
        token_list = smart_deduplicate_tokens(token_list)
        
        start_time = time.time()
        results = bulk_process_threaded(token_list, process_access_token, max_workers, 0.3)
        elapsed = time.time() - start_time
        
        successful = [r for r in results if r.get('success')]
        
        return jsonify({
            "success": True,
            "summary": {
                "total_received": original_count,
                "unique_processed": len(token_list),
                "successful": stats['successful'],
                "failed": stats['failed'],
                "duplicates_removed": original_count - len(token_list) + stats['duplicates'],
                "time_taken_seconds": round(elapsed, 2)
            },
            "results": successful[:50]
        })
    except Exception as e:
        return jsonify({"error": f"Failed to process file: {str(e)}"}), 500

@app.route('/bulk/uidpass', methods=['POST'])
def bulk_uidpass():
    """Bulk process UID:PASS pairs"""
    data = request.get_json(silent=True)
    
    credentials = []
    
    if isinstance(data, list):
        for item in data:
            if isinstance(item, dict) and 'uid' in item and 'password' in item:
                credentials.append(item)
            elif isinstance(item, str) and ':' in item:
                parts = item.split(':', 1)
                credentials.append({'uid': parts[0].strip(), 'password': parts[1].strip()})
    elif isinstance(data, dict):
        if 'uid' in data and 'password' in data:
            credentials.append(data)
        items = data.get('credentials') or data.get('list') or data.get('accounts')
        if isinstance(items, list):
            for item in items:
                if isinstance(item, dict) and 'uid' in item and 'password' in item:
                    credentials.append(item)
                elif isinstance(item, str) and ':' in item:
                    parts = item.split(':', 1)
                    credentials.append({'uid': parts[0].strip(), 'password': parts[1].strip()})
    
    if not credentials:
        return jsonify({"error": "No credentials found. Use format: [{\"uid\":\"...\",\"password\":\"...\"}]"}), 400
    
    max_workers = request.args.get('threads', 5)
    try:
        max_workers = int(max_workers)
    except:
        max_workers = 5
    
    start_time = time.time()
    results = bulk_process_threaded(credentials, process_uid_pass, max_workers, 1.0)
    elapsed = time.time() - start_time
    
    successful = [r for r in results if r.get('success')]
    
    return jsonify({
        "success": True,
        "summary": {
            "total": len(credentials),
            "successful": stats['successful'],
            "failed": stats['failed'],
            "time_taken_seconds": round(elapsed, 2)
        },
        "results": successful[:50]
    })

@app.route('/status', methods=['GET'])
def status_endpoint():
    """Check API status and stats"""
    with stats_lock:
        current_stats = {
            "processed": stats['processed'],
            "successful": stats['successful'],
            "failed": stats['failed'],
            "duplicates": stats['duplicates']
        }
    
    with token_cache_lock:
        cache_size = len(token_cache)
    
    return jsonify({
        "status": "running",
        "version": RIZER,
        "stats": current_stats,
        "cache_size": cache_size,
        "endpoints": {
            "/rizer": "GET - Single token (query param: access_token)",
            "/bulk": "POST - Bulk tokens in JSON body",
            "/bulk/tokens": "POST - Upload tokens file (form-data key: file)",
            "/bulk/uidpass": "POST - Bulk UID:PASS processing",
            "/status": "GET - API status"
        }
    })

@app.route('/', methods=['GET'])
def home():
    return jsonify({
        "name": "Free Fire JWT Generator API",
        "version": RIZER,
        "author": "@beotherjkman",
        "endpoints": {
            "/rizer": "GET - Single token processing",
            "/bulk": "POST - Bulk token processing",
            "/bulk/tokens": "POST - Upload file processing",
            "/bulk/uidpass": "POST - UID:PASS processing",
            "/status": "GET - API status"
        },
        "docs": "Send access_token as query param for /rizer, or POST JSON body for bulk endpoints"
    })

# ==================== MAIN ====================
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8000))
    app.run(host='0.0.0.0', port=port, debug=False)