import pandas as pd
import json
import geoip2.database
import os
import tempfile
from datetime import datetime
import io

def parse_audit_logs(file_content, file_type, geoip_db_path=None):
    """
    Parse audit logs from an uploaded file (CSV or Excel).
    """
    try:
        # Read data based on file type
        if file_type == 'csv':
            df = pd.read_csv(io.BytesIO(file_content))
        else:  # Excel
            df = pd.read_excel(io.BytesIO(file_content))

        # Select relevant columns
        columns_of_interest = ['CreationDate', 'Operation', 'UserId', 'AuditData']
        
        # Check if all required columns exist
        missing_columns = [col for col in columns_of_interest if col not in df.columns]
        if missing_columns:
            return None, f"Missing required columns: {', '.join(missing_columns)}"
        
        df = df[columns_of_interest]

        # Convert CreationDate to datetime for sorting
        df['CreationDate'] = pd.to_datetime(df['CreationDate'])
        df = df.sort_values(by='CreationDate')

        # Open the GeoLite2 database if available
        geo_reader = None
        if geoip_db_path and os.path.exists(geoip_db_path):
            try:
                geo_reader = geoip2.database.Reader(geoip_db_path)
            except Exception as ge:
                return None, f"Error loading GeoIP database: {str(ge)}"
        else:
            return None, "GeoIP database not found"

        # Parse AuditData and create a timeline with geolocation data
        timeline = []
        error_count = 0
        
        for _, row in df.iterrows():
            try:
                audit_data = json.loads(row['AuditData'])
                event = {
                    'Timestamp': row['CreationDate'],
                    'Operation': row['Operation'],
                    'UserId': row['UserId'],
                    'ClientIP': audit_data.get('ClientIP', 'N/A'),
                    'ResultStatus': audit_data.get('ResultStatus', 'N/A')
                }
                
                # For FileAccessed events, extract the file name if available
                if row['Operation'] == 'FileAccessed':
                    event['FileName'] = audit_data.get('SourceFileName', 'N/A')
                else:
                    event['FileName'] = ''

                # Lookup geolocation info for the IP (if possible)
                ip = event['ClientIP']
                if geo_reader and ip != 'N/A':
                    try:
                        # Handle IPv6 addresses that might have port info
                        if ':' in ip and not ip.startswith('['):
                            ip = ip.split(':')[0]
                            
                        response = geo_reader.city(ip)
                        
                        country = response.country.iso_code if response.country.iso_code else "Unknown"
                        city = response.city.name if response.city.name else "Unknown"
                        region = response.subdivisions.most_specific.name if response.subdivisions.most_specific.name else "Unknown"
                        
                        event['Country'] = country
                        event['Region'] = region
                        event['City'] = city
                        
                        # Add coordinates for mapping
                        event['Latitude'] = response.location.latitude
                        event['Longitude'] = response.location.longitude
                        
                    except Exception as e:
                        event['Country'] = "Unknown"
                        event['Region'] = "Unknown"
                        event['City'] = "Unknown"
                        event['Latitude'] = None
                        event['Longitude'] = None
                else:
                    event['Country'] = "Unknown"
                    event['Region'] = "Unknown"
                    event['City'] = "Unknown"
                    event['Latitude'] = None
                    event['Longitude'] = None

                timeline.append(event)
            except json.JSONDecodeError:
                error_count += 1
        
        if geo_reader:
            geo_reader.close()

        if len(timeline) == 0:
            return None, "No valid data could be parsed from the file"
            
        # Provide a warning if there were parsing errors
        warning = None
        if error_count > 0:
            warning = f"{error_count} records had invalid JSON data and were skipped."
            
        return timeline, warning

    except Exception as e:
        return None, f"Error processing file: {str(e)}"

def is_ip_anomalous(event):
    """
    Returns True if the event's IP is considered anomalous.
    An IP is NOT anomalous if it is exactly '192.168.1.160' (Frans usual IP).
    Otherwise, if the geolocated Country is not 'US' or the Region is not 'Massachusetts',
    then the event is considered anomalous.
    """
    ip = event.get('ClientIP', 'N/A')
    if ip == '192.168.1.160':
        return False
    country = event.get('Country', "Unknown")
    region = event.get('Region', "Unknown")
    # If the country is not usa or region is not Mass, flag as anomalous
    if country != 'US' or region != 'Massachusetts':
        return True
    return False

def detect_compromised_events(timeline):
    """
    Returns events exhibiting suspicious activity AND having an anomalous IP.
    Suspicious activity is defined as:
      - Operation is either 'SoftDelete' or 'MoveToDeletedItems'
      OR
      - The user has logged in from more than 3 unique IP addresses.
    """
    suspicious_ops = ['SoftDelete', 'MoveToDeletedItems']
    compromised_events = []
    user_ip_map = {}

    # First, build a map of unique IP addresses
    for event in timeline:
        user_id = event['UserId']
        client_ip = event['ClientIP']
        if user_id not in user_ip_map:
            user_ip_map[user_id] = set()
        user_ip_map[user_id].add(client_ip)

    # Flag an event as compromised if it looks like suspicious activity and has a weird IP
    for event in timeline:
        user_id = event['UserId']
        suspicious_activity = (event['Operation'] in suspicious_ops or len(user_ip_map[user_id]) > 3)
        if suspicious_activity and is_ip_anomalous(event):
            compromised_events.append(event)
    
    return compromised_events

def filter_files_accessed(timeline):
    """Return events where the operation is 'FileAccessed'."""
    return [event for event in timeline if event['Operation'] == 'FileAccessed']

def filter_anomalous_ips(timeline):
    """Return only events where the IP is considered anomalous per our criteria."""
    return [event for event in timeline if is_ip_anomalous(event)]

def get_stats(timeline, compromised_events, files_accessed, anomalous_ips):
    """Generate statistics about the data."""
    stats = {
        "total_events": len(timeline),
        "compromised_events": len(compromised_events),
        "files_accessed": len(files_accessed),
        "anomalous_ips": len(anomalous_ips),
        "unique_users": len(set(event['UserId'] for event in timeline)),
        "unique_ips": len(set(event['ClientIP'] for event in timeline)),
        "unique_operations": len(set(event['Operation'] for event in timeline)),
        "operation_counts": {},
        "country_counts": {},
    }
    
    # Count operations
    for event in timeline:
        op = event['Operation']
        stats["operation_counts"][op] = stats["operation_counts"].get(op, 0) + 1
    
    # Count countries
    for event in timeline:
        country = event.get('Country', 'Unknown')
        stats["country_counts"][country] = stats["country_counts"].get(country, 0) + 1
    
    return stats

def get_ip_summary(timeline):
    """Generate a summary of IP addresses in the dataset."""
    ip_summary = {}
    
    for event in timeline:
        ip = event.get('ClientIP', 'N/A')
        if ip == 'N/A':
            continue
            
        if ip not in ip_summary:
            ip_summary[ip] = {
                'count': 0,
                'country': event.get('Country', 'Unknown'),
                'region': event.get('Region', 'Unknown'),
                'city': event.get('City', 'Unknown'),
                'latitude': event.get('Latitude'),
                'longitude': event.get('Longitude'),
                'operations': set(),
                'users': set(),
                'is_anomalous': is_ip_anomalous(event),
                'first_seen': event['Timestamp'],
                'last_seen': event['Timestamp']
            }
        
        ip_summary[ip]['count'] += 1
        ip_summary[ip]['operations'].add(event['Operation'])
        ip_summary[ip]['users'].add(event['UserId'])
        
        # Update first/last seen
        if event['Timestamp'] < ip_summary[ip]['first_seen']:
            ip_summary[ip]['first_seen'] = event['Timestamp']
        if event['Timestamp'] > ip_summary[ip]['last_seen']:
            ip_summary[ip]['last_seen'] = event['Timestamp']
    
    # Convert sets to lists for easier display
    for ip in ip_summary:
        ip_summary[ip]['operations'] = list(ip_summary[ip]['operations'])
        ip_summary[ip]['users'] = list(ip_summary[ip]['users'])
    
    return ip_summary
