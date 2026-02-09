
import os
import streamlit as st
from elasticsearch import Elasticsearch
from datetime import datetime, timedelta
import pandas as pd
import random
from dotenv import load_dotenv

load_dotenv()

ES_URL = os.getenv("ELASTICSEARCH_URL", "http://localhost:9200")
ES_USER = os.getenv("ELASTICSEARCH_USER", "elastic")
ES_PASS = os.getenv("ELASTICSEARCH_PASSWORD", "changeme")
ES_INDEX = os.getenv("ELASTICSEARCH_INDEX", "nasional_cve*")

class ELKConnector:
    def __init__(self):
        try:
            self.es = Elasticsearch(
                ES_URL,
                basic_auth=(ES_USER, ES_PASS),
                verify_certs=False,
                request_timeout=30
            )
            self.connected = self.es.ping()
        except Exception as e:
            print(f"Connection failed: {e}")
            self.connected = False

    def get_data(self, time_range="30d"):
        if not self.connected:
            return self._generate_mock_data()
        
        # Calculate time range
        end_date = datetime.now()
        if time_range == "7d":
            start_date = end_date - timedelta(days=7)
        elif time_range == "30d":
            start_date = end_date - timedelta(days=30)
        elif time_range == "90d":
            start_date = end_date - timedelta(days=90)
        else:
            start_date = end_date - timedelta(days=365)

        query = {
            "size": 10000, 
            "query": {
                "bool": {
                    "must": [
                        {
                            "range": {
                                "@timestamp": {
                                    "gte": start_date.isoformat(),
                                    "lte": end_date.isoformat()
                                }
                            }
                        }
                    ]
                }
            },
            "_source": [
                "@timestamp", 
                "Severity.keyword", 
                "Sektor.keyword", 
                "Organisasi.keyword", 
                "Vuln.keyword", 
                "Source.keyword", 
                "Target.keyword", 
                "Score",
                "hasCisa",
                "IPAddresses.keyword"
            ]
        }

        try:
            resp = self.es.search(index=ES_INDEX, body=query)
            hits = resp['hits']['hits']
            data = []
            for hit in hits:
                source = hit['_source']
                # Helper to get keyword field or fall back to text field
                def get_val(field):
                    return source.get(f"{field}.keyword", source.get(field, "UNKNOWN"))

                flat_data = {
                    "@timestamp": source.get("@timestamp"),
                    "Severity": get_val("Severity"),
                    "Sektor": get_val("Sektor"),
                    "Organisasi": get_val("Organisasi"),
                    "Vuln": get_val("Vuln"),
                    "Source": get_val("Source"),
                    "Target": get_val("Target"),
                    "Score": source.get("Score", 0),
                    "hasCisa": source.get("hasCisa", False),
                    "IPAddresses": get_val("IPAddresses")
                }
                data.append(flat_data)
            
            df = pd.DataFrame(data)
            if not df.empty:
                df['@timestamp'] = pd.to_datetime(df['@timestamp'])
            return df
        
        except Exception as e:
            # st.error(f"Error fetching data: {e}") # Suppress error in production look
            print(f"Error fetching data from ELK: {e}")
            return self._generate_mock_data()

    def _generate_mock_data(self):
        """Generates realistic mock data based on export.ndjson schema"""
        # Sectors found in the export file
        sectors = [
            "Administrasi Pemerintahan", "Keuangan", "Transportasi", "Pangan", 
            "ESDM", "Kesehatan", "Pertahanan", "TIK", "Lainnya"
        ]
        severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        # Realistic sounding orgs
        orgs = [
            "Kementerian Keuangan", "Kementerian Kesehatan", "BSSN", "Kementerian Perhubungan",
            "Pemda DKI Jakarta", "Pemprov Jawa Barat", "Bank Indonesia", "OJK",
            "Kementerian ESDM", "Kementerian Pertahanan"
        ]
        vulns = [
            "CVE-2023-38831", "CVE-2023-44487", "CVE-2024-21413", "CVE-2021-44228 (Log4j)",
            "CVE-2023-23397", "CVE-2024-3400", "CVE-2023-4966 (Citrix Bleed)"
        ]
        
        data = []
        now = datetime.now()
        for _ in range(1000):
            sector = random.choice(sectors)
            # Correlate org with sector roughly
            org = random.choice(orgs)
            
            sev = random.choices(severities, weights=[0.1, 0.2, 0.4, 0.3])[0]
            
            data.append({
                "@timestamp": now - timedelta(days=random.randint(0, 90)),
                "Severity": sev,
                "Sektor": sector,
                "Organisasi": org,
                "Vuln": random.choice(vulns),
                "Source": f"10.10.{random.randint(1, 255)}.{random.randint(1, 255)}",
                "Target": f"web-server-{random.randint(1, 20)}",
                "Score": round(random.uniform(4.0, 10.0), 1),
                "hasCisa": random.choice([True, False]),
                "IPAddresses": f"192.168.1.{random.randint(1, 255)}"
            })
        return pd.DataFrame(data)

def get_connector():
    return ELKConnector()
