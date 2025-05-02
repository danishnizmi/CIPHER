"""
Ingestion module for threat intelligence feeds.
Handles downloading, parsing, and storing threat intelligence data from various sources.
"""

import os
import json
import csv
import requests
import io
import datetime
import logging
from typing import Dict, List, Any, Optional, Tuple
from google.cloud import storage
from google.cloud import bigquery
import config

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class FeedIngestion:
    """Class to handle the ingestion of threat intelligence feeds."""
    
    def __init__(self):
        """Initialize the FeedIngestion class with GCP clients."""
        self.storage_client = storage.Client()
        self.bigquery_client = bigquery.Client()
        self.bucket_name = config.GCS_BUCKET_NAME
        self.bucket = self.storage_client.bucket(self.bucket_name)
        
        # Ensure bucket exists
        self._ensure_bucket_exists()
        
    def _ensure_bucket_exists(self):
        """Create the GCS bucket if it doesn't exist."""
        try:
            if not self.bucket.exists():
                self.storage_client.create_bucket(
                    self.bucket_name, 
                    location=config.GCS_BUCKET_LOCATION
                )
                logger.info(f"Created new bucket: {self.bucket_name}")
        except Exception as e:
            logger.error(f"Error ensuring bucket exists: {str(e)}")
            raise
            
    def download_feed(self, url: str, headers: Optional[Dict] = None) -> Tuple[str, bytes]:
        """
        Download content from the specified URL.
        
        Args:
            url: The URL to download from
            headers: Optional request headers
            
        Returns:
            Tuple of (content_type, content_bytes)
        """
        try:
            logger.info(f"Downloading feed from {url}")
            response = requests.get(url, headers=headers, timeout=60)
            response.raise_for_status()
            
            content_type = response.headers.get('Content-Type', '')
            return content_type, response.content
        except requests.RequestException as e:
            logger.error(f"Error downloading feed from {url}: {str(e)}")
            raise
            
    def store_raw_feed(self, feed_name: str, content: bytes, content_type: str) -> str:
        """
        Store the raw feed content in Google Cloud Storage.
        
        Args:
            feed_name: Name of the feed
            content: Raw content bytes
            content_type: MIME type of the content
            
        Returns:
            GCS URI of the stored file
        """
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        file_extension = self._get_file_extension(content_type)
        blob_name = f"raw/{feed_name}/{timestamp}{file_extension}"
        
        try:
            blob = self.bucket.blob(blob_name)
            blob.upload_from_string(content, content_type=content_type)
            gcs_uri = f"gs://{self.bucket_name}/{blob_name}"
            logger.info(f"Stored raw feed at {gcs_uri}")
            return gcs_uri
        except Exception as e:
            logger.error(f"Error storing raw feed: {str(e)}")
            raise
            
    def _get_file_extension(self, content_type: str) -> str:
        """
        Determine file extension based on content type.
        
        Args:
            content_type: MIME type of the content
            
        Returns:
            File extension including the dot
        """
        if 'json' in content_type.lower():
            return '.json'
        elif 'csv' in content_type.lower():
            return '.csv'
        elif 'text/plain' in content_type.lower():
            return '.txt'
        else:
            return '.dat'
            
    def parse_feed(self, feed_name: str, content: bytes, content_type: str) -> List[Dict]:
        """
        Parse the feed content based on its type and format.
        
        Args:
            feed_name: Name of the feed
            content: Raw content bytes
            content_type: MIME type of the content
            
        Returns:
            List of parsed items as dictionaries
        """
        if feed_name == "threatfox":
            return self._parse_threatfox(content)
        elif feed_name == "phishtank":
            return self._parse_phishtank(content)
        elif feed_name == "urlhaus":
            return self._parse_urlhaus(content)
        elif feed_name == "cisa_kev":
            return self._parse_cisa_kev(content)
        elif feed_name == "tor_exit_nodes":
            return self._parse_tor_exit_nodes(content)
        else:
            logger.warning(f"Unknown feed type: {feed_name}. Attempting generic parsing.")
            # Try generic parsing based on content type
            if 'json' in content_type.lower():
                try:
                    return self._parse_json_generic(content)
                except:
                    logger.error(f"Failed to parse {feed_name} as JSON")
                    return []
            elif 'csv' in content_type.lower():
                try:
                    return self._parse_csv_generic(content)
                except:
                    logger.error(f"Failed to parse {feed_name} as CSV")
                    return []
            else:
                logger.error(f"Unsupported content type for {feed_name}: {content_type}")
                return []
            
    def _parse_threatfox(self, content: bytes) -> List[Dict]:
        """Parse ThreatFox JSON format."""
        try:
            data = json.loads(content)
            parsed_data = []
            
            for threat_id, threat_details in data.items():
                for ioc in threat_details:
                    # Add the threat_id to each record
                    ioc['threat_id'] = threat_id
                    # Add timestamp for when we ingested this
                    ioc['ingestion_timestamp'] = datetime.datetime.utcnow().isoformat()
                    parsed_data.append(ioc)
                    
            logger.info(f"Parsed {len(parsed_data)} ThreatFox IOCs")
            return parsed_data
        except Exception as e:
            logger.error(f"Error parsing ThreatFox data: {str(e)}")
            raise
            
    def _parse_phishtank(self, content: bytes) -> List[Dict]:
        """Parse PhishTank JSON format."""
        try:
            data = json.loads(content)
            
            for item in data:
                # Add timestamp for when we ingested this
                item['ingestion_timestamp'] = datetime.datetime.utcnow().isoformat()
                
            logger.info(f"Parsed {len(data)} PhishTank URLs")
            return data
        except Exception as e:
            logger.error(f"Error parsing PhishTank data: {str(e)}")
            raise
            
    def _parse_urlhaus(self, content: bytes) -> List[Dict]:
        """Parse URLhaus CSV format."""
        try:
            # Skip the header comments that start with #
            content_str = content.decode('utf-8')
            lines = content_str.split('\n')
            
            csv_content = '\n'.join([line for line in lines if not line.startswith('#')])
            
            csv_reader = csv.DictReader(io.StringIO(csv_content))
            
            parsed_data = []
            for row in csv_reader:
                if row:  # Skip empty rows
                    # Add timestamp for when we ingested this
                    row['ingestion_timestamp'] = datetime.datetime.utcnow().isoformat()
                    parsed_data.append(row)
                    
            logger.info(f"Parsed {len(parsed_data)} URLhaus entries")
            return parsed_data
        except Exception as e:
            logger.error(f"Error parsing URLhaus data: {str(e)}")
            raise
            
    def _parse_cisa_kev(self, content: bytes) -> List[Dict]:
        """Parse CISA Known Exploited Vulnerabilities JSON format."""
        try:
            data = json.loads(content)
            vulnerabilities = data.get('vulnerabilities', [])
            
            # Add metadata and timestamp to each record
            for vuln in vulnerabilities:
                vuln['catalog_version'] = data.get('catalogVersion')
                vuln['date_released'] = data.get('dateReleased')
                vuln['ingestion_timestamp'] = datetime.datetime.utcnow().isoformat()
                
            logger.info(f"Parsed {len(vulnerabilities)} CISA KEV entries")
            return vulnerabilities
        except Exception as e:
            logger.error(f"Error parsing CISA KEV data: {str(e)}")
            raise
            
    def _parse_tor_exit_nodes(self, content: bytes) -> List[Dict]:
        """Parse Tor exit nodes list (plain text, one IP per line)."""
        try:
            content_str = content.decode('utf-8').strip()
            ips = [line.strip() for line in content_str.splitlines() if line.strip()]
            
            timestamp = datetime.datetime.utcnow().isoformat()
            parsed_data = [
                {
                    'ip_address': ip,
                    'source': 'torproject',
                    'type': 'tor_exit_node',
                    'ingestion_timestamp': timestamp
                }
                for ip in ips
            ]
            
            logger.info(f"Parsed {len(parsed_data)} Tor exit nodes")
            return parsed_data
        except Exception as e:
            logger.error(f"Error parsing Tor exit nodes: {str(e)}")
            raise
            
    def _parse_json_generic(self, content: bytes) -> List[Dict]:
        """Generic parser for JSON content."""
        data = json.loads(content)
        
        # Handle both list and dict formats
        if isinstance(data, list):
            return data
        elif isinstance(data, dict):
            # If it's a dict with a single key that's a list, return that list
            for key, value in data.items():
                if isinstance(value, list):
                    return value
            # Otherwise, return the dict as a single-item list
            return [data]
        else:
            logger.warning(f"Unexpected JSON structure: {type(data)}")
            return []
            
    def _parse_csv_generic(self, content: bytes) -> List[Dict]:
        """Generic parser for CSV content."""
        content_str = content.decode('utf-8')
        
        # Skip lines that start with # (comments)
        lines = content_str.split('\n')
        csv_content = '\n'.join([line for line in lines if not line.startswith('#')])
        
        csv_reader = csv.DictReader(io.StringIO(csv_content))
        return list(csv_reader)
            
    def store_processed_feed(self, feed_name: str, data: List[Dict]) -> str:
        """
        Store the processed feed data in Google Cloud Storage as JSON.
        
        Args:
            feed_name: Name of the feed
            data: Processed data as list of dictionaries
            
        Returns:
            GCS URI of the stored file
        """
        if not data:
            logger.warning(f"No data to store for {feed_name}")
            return ""
            
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        blob_name = f"processed/{feed_name}/{timestamp}.json"
        
        try:
            blob = self.bucket.blob(blob_name)
            blob.upload_from_string(
                json.dumps(data, indent=2),
                content_type='application/json'
            )
            gcs_uri = f"gs://{self.bucket_name}/{blob_name}"
            logger.info(f"Stored processed feed at {gcs_uri}")
            return gcs_uri
        except Exception as e:
            logger.error(f"Error storing processed feed: {str(e)}")
            raise
            
    def upload_to_bigquery(self, feed_name: str, data: List[Dict]) -> bool:
        """
        Upload the processed data to BigQuery.
        
        Args:
            feed_name: Name of the feed
            data: Processed data as list of dictionaries
            
        Returns:
            True if successful, False otherwise
        """
        if not data:
            logger.warning(f"No data to upload to BigQuery for {feed_name}")
            return False
            
        table_id = f"{config.BQ_DATASET_ID}.{feed_name}"
        
        try:
            # Create or update schema based on the first item
            schema = self._infer_schema(data[0])
            
            # Check if table exists, if not create it
            try:
                self.bigquery_client.get_table(table_id)
            except Exception:
                # Table doesn't exist, create it
                table = bigquery.Table(table_id, schema=schema)
                self.bigquery_client.create_table(table)
                logger.info(f"Created new table: {table_id}")
            
            # Insert data
            job_config = bigquery.LoadJobConfig(
                schema=schema,
                write_disposition=bigquery.WriteDisposition.WRITE_APPEND,
            )
            
            job = self.bigquery_client.load_table_from_json(
                data,
                table_id,
                job_config=job_config
            )
            job.result()  # Wait for the job to complete
            
            logger.info(f"Uploaded {len(data)} rows to BigQuery table {table_id}")
            return True
        except Exception as e:
            logger.error(f"Error uploading to BigQuery: {str(e)}")
            return False
            
    def _infer_schema(self, sample: Dict) -> List[bigquery.SchemaField]:
        """
        Infer BigQuery schema from a sample dictionary.
        
        Args:
            sample: A sample dictionary to infer the schema from
            
        Returns:
            List of BigQuery SchemaField objects
        """
        schema = []
        
        for key, value in sample.items():
            if isinstance(value, bool):
                field_type = 'BOOLEAN'
            elif isinstance(value, int):
                field_type = 'INTEGER'
            elif isinstance(value, float):
                field_type = 'FLOAT'
            elif isinstance(value, dict):
                field_type = 'RECORD'
                # For nested fields, recursively infer the schema
                fields = self._infer_schema(value)
                schema.append(bigquery.SchemaField(key, field_type, fields=fields))
                continue
            elif isinstance(value, list):
                # For simplicity, treat lists as strings (JSON serialized)
                # More complex handling would be needed for proper REPEATED fields
                field_type = 'STRING'
            else:
                field_type = 'STRING'
                
            schema.append(bigquery.SchemaField(key, field_type))
            
        return schema
    
    def process_feed(self, feed_config: Dict) -> Dict:
        """
        Process a feed based on its configuration.
        
        Args:
            feed_config: Configuration for the feed
            
        Returns:
            Dictionary with processing results
        """
        feed_name = feed_config['name']
        feed_url = feed_config['url']
        headers = feed_config.get('headers', {})
        
        try:
            # Download the feed
            content_type, content = self.download_feed(feed_url, headers)
            
            # Store the raw feed
            raw_uri = self.store_raw_feed(feed_name, content, content_type)
            
            # Parse the feed
            parsed_data = self.parse_feed(feed_name, content, content_type)
            
            # Store the processed feed
            processed_uri = self.store_processed_feed(feed_name, parsed_data)
            
            # Upload to BigQuery if configured
            bigquery_success = False
            if feed_config.get('upload_to_bigquery', False):
                bigquery_success = self.upload_to_bigquery(feed_name, parsed_data)
            
            return {
                'feed_name': feed_name,
                'timestamp': datetime.datetime.utcnow().isoformat(),
                'raw_uri': raw_uri,
                'processed_uri': processed_uri,
                'record_count': len(parsed_data),
                'bigquery_upload': bigquery_success,
                'status': 'success'
            }
            
        except Exception as e:
            logger.error(f"Error processing feed {feed_name}: {str(e)}")
            return {
                'feed_name': feed_name,
                'timestamp': datetime.datetime.utcnow().isoformat(),
                'error': str(e),
                'status': 'failed'
            }

def ingest_all_feeds():
    """Ingest all feeds defined in the config."""
    ingestion = FeedIngestion()
    results = []
    
    for feed_config in config.THREAT_FEEDS:
        logger.info(f"Processing feed: {feed_config['name']}")
        result = ingestion.process_feed(feed_config)
        results.append(result)
        
    # Log summary
    success_count = sum(1 for r in results if r['status'] == 'success')
    logger.info(f"Feed ingestion complete. {success_count}/{len(results)} feeds processed successfully.")
    
    return results

def ingest_feed(feed_name: str):
    """
    Ingest a specific feed by name.
    
    Args:
        feed_name: Name of the feed to ingest
        
    Returns:
        Processing result dictionary
    """
    ingestion = FeedIngestion()
    
    # Find the feed config by name
    feed_config = None
    for fc in config.THREAT_FEEDS:
        if fc['name'] == feed_name:
            feed_config = fc
            break
            
    if not feed_config:
        logger.error(f"Feed {feed_name} not found in configuration")
        return {
            'feed_name': feed_name,
            'timestamp': datetime.datetime.utcnow().isoformat(),
            'error': 'Feed not found in configuration',
            'status': 'failed'
        }
        
    logger.info(f"Processing feed: {feed_name}")
    return ingestion.process_feed(feed_config)

if __name__ == "__main__":
    # When run as a script, ingest all feeds
    ingest_all_feeds()
