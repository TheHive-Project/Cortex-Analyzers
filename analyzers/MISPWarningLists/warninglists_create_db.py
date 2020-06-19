#!/usr/bin/env python
# coding: utf-8

import re
import json
import logging
import ipaddress
from glob import glob 
from tqdm import tqdm
from tld import get_tld

logging.basicConfig(filename='import.log',level=logging.DEBUG)


import psycopg2.extras
from sqlalchemy import Table, Column, Integer, String, MetaData, ForeignKey, Index, create_engine
from sqlalchemy.sql import select
from sqlalchemy.dialects.postgresql import CIDR

conn_string = "<insert_postgres_conn_strin>"
warninglists_path = "misp-warninglists/**/list.json"

engine = create_engine(conn_string, use_batch_mode=True)
conn = engine.connect()

# UPDATE TLD FROM MOZILLA
from tld.utils import update_tld_names
update_tld_names()


# HASH REGEX
md5_re = re.compile(r"^[a-f0-9]{32}(:.+)?$", re.IGNORECASE)
sha1_re = re.compile(r"^[a-f0-9]{40}(:.+)?$", re.IGNORECASE)
sha224_re = re.compile(r"^[a-f0-9]{56}(:.+)?$", re.IGNORECASE)
sha256_re = re.compile(r"^[a-f0-9]{64}(:.+)?$", re.IGNORECASE)
sha512_re = re.compile(r"^[a-f0-9]{128}(:.+)?$", re.IGNORECASE)



items = {}
avoid_list = []

file_list = [file for file in glob(warninglists_path, recursive=True) if file.split("/")[-2] not in avoid_list]
for file_item in file_list:
    with open(file_item, 'r') as f:
        json_data = json.load(f)
        file_name = file_item.split("/")[-2]
        items[file_name] = {}
        items[file_name]['version'] = str(json_data['version'])
        items[file_name]['list'] = {x:{} for x in json_data['list']}
    
for k, v in items.items():
    logging.debug(f"NAME: {k} - VERSION: {v['version']} - ITEMS: {len(v['list'])}")


# In[7]:

for k, v in tqdm(items.items()):
    for item in v['list'].keys():        
        new_item = item    
        if new_item.startswith('.'):
            new_item = "*" + new_item        
        if new_item.endswith('.'):
            new_item = new_item[:-1]
        try:
            ipaddress.ip_address(new_item)
            items[k]['list'][item]['type'] = 'cidr'
            items[k]['list'][item]['address'] = new_item
        except:      
            try:
                ipaddress.ip_network(new_item)
                items[k]['list'][item]['type'] = 'cidr'
                items[k]['list'][item]['address'] = new_item
            except:
                if md5_re.match(new_item):
                    items[k]['list'][item]['type'] = 'md5'
                    items[k]['list'][item]['hash'] = new_item
                elif sha1_re.match(new_item):
                    items[k]['list'][item]['type'] = 'sha1'
                    items[k]['list'][item]['hash'] = new_item
                elif sha224_re.match(new_item):
                    items[k]['list'][item]['type'] = 'sha224'
                    items[k]['list'][item]['hash'] = new_item
                elif sha256_re.match(new_item):
                    items[k]['list'][item]['type'] = 'sha256'
                    items[k]['list'][item]['hash'] = new_item
                elif sha512_re.match(new_item):
                    items[k]['list'][item]['type'] = 'sha512'
                    items[k]['list'][item]['hash'] = new_item
                else:
                    if new_item.find(".") == -1:
                        logging.error(f"NOT VALID: {new_item} [{k}]")
                        continue
                    try:
                        ext = get_tld(new_item, fix_protocol=True, as_object=True)
                        items[k]['list'][item]['type'] = 'url-domain'
                        items[k]['list'][item]['subdomain'] = ext.subdomain if ext.subdomain != '' else None
                        items[k]['list'][item]['domain'] = ext.domain
                        items[k]['list'][item]['tld'] = ext.tld
                        items[k]['list'][item]['query'] = ext.parsed_url[2] if ext.parsed_url[2] != '' else None
                    except:
                        logging.error(f"NOT VALID: {new_item} [{k}]")


# CREATE OR USE DB
metadata = MetaData()

warninglists = Table(
    "warninglists",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("list_name", String),
    Column("list_version", String),
    Column("address", CIDR),
    Column("hash", String),
    Column("subdomain", String),
    Column("domain", String),
    Column("tld", String),
    Column("query", String),
)

warninglists_address_idx = Index("warninglists_address_idx", warninglists.c.address)
warninglists_hash_idx = Index("warninglists_hash_idx", warninglists.c.hash)
warninglists_domain_idx = Index("warninglists_domain_idx", warninglists.c.domain)

try:
    warninglists.create(engine)
except:
    logging.error("DB already exists")


try:
    warninglists_address_idx.drop(engine)
except:
    logging.error("warninglists_address_idx does not exists")


try:
    warninglists_hash_idx.drop(engine)
except:
    logging.error("warninglists_hash_idx does not exists")


try:
    warninglists_domain_idx.drop(engine)
except:
    logging.error("warninglists_domain_idx does not exists")


# CHECK IF OLD RELEASE ARE IN DB
s = select([warninglists.c.list_name, warninglists.c.list_version]).distinct()
last_versions = [x for x in conn.execute(s)]
print(f"{len(last_versions)} list already available in db")


# INSERT, UPDATE OR SKIP 
raw_conn = engine.raw_connection()
cursor = raw_conn.cursor()

for k, v in tqdm(items.items()):
    name = k
    version = items[k]['version']
    if (name, version) not in last_versions:
        if name in [x[0] for x in last_versions]:
            logging.debug(f"{(name, version)} is an update - DELETE OLD RELEASE")
            d = warninglists.delete().where(warninglists.c.list_name == name)
            conn.execute(d)

        logging.debug(f"{(name, version)} not in db - BULK IMPORTING")
        tbi = [{
            'list_name': name,
            'list_version': version,
            'address': item.get('address', None),
            'hash': item.get('hash', None),
            'subdomain': item.get('subdomain', None),
            'domain': item.get('domain', None),
            'tld': item.get('tld', None),
            'query': item.get('query', None),
        } for item_old_name, item in v['list'].items()]
        psycopg2.extras.execute_batch(cursor, """INSERT INTO warninglists(list_name, list_version, address, hash, subdomain, domain, tld, query) VALUES (%(list_name)s, %(list_version)s, %(address)s, %(hash)s, %(subdomain)s, %(domain)s, %(tld)s, %(query)s)""", tbi)
        raw_conn.commit()
    else:
        logging.debug(f"{name}, {version} already in db - SKIPPING")
        
cursor.close()
conn.close()
raw_conn.close()

try:
    warninglists_address_idx.create(engine)
except:
    logging.error(f"warninglists_address_idx already exists")
try:
    warninglists_hash_idx.create(engine)
except:
    logging.error(f"warninglists_hash_idx already exists")
try:
    warninglists_domain_idx.create(engine)
except:
    logging.error(f"warninglists_domain_idx already exists")
engine.dispose()
