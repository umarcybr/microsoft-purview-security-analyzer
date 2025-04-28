import pandas as pd
import json
import os
import time
import ipaddress
import geoip2.database

# Pre-defined IP location data for known IPs (like Frans' usual IP)
KNOWN_IPS = {
    '192.168.1.160': {
        'Country': 'US',
        'Region': 'Massachusetts',
        'City': 'Boston',
        'Latitude': 42.3601,
        'Longitude': -71.0589
    }
}

def is_private_ip(ip):
    """Check if an IP address is private."""
    if ip == 'N/A':
        return True
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return True  # If not a valid IP, treat as private

def get_ip_geolocation(ip, geo_reader=None):
    """
    Get geolocation data for an IP address using GeoLite2 database.
    
    Parameters:
    ip (str): IP address
    geo_reader: GeoLite2 database reader object
    
    Returns:
    dict: Geolocation data (country, region, city, latitude, longitude)
    """
    # Check for known IPs first (like Frans's usual IP)
    if ip in KNOWN_IPS:
        return KNOWN_IPS[ip]
    
    # Skip private IPs
    if is_private_ip(ip):
        return {
            'Country': 'Local',
            'Region': 'Network',
            'City': 'Private',
            'Latitude': 0,
            'Longitude': 0
        }
    
    # Try to use the GeoLite2 database
    if geo_reader and ip != 'N/A':
        try:
            response = geo_reader.city(ip)
            country = response.country.iso_code if response.country.iso_code else "Unknown"
            region = response.subdivisions.most_specific.name if response.subdivisions.most_specific.name else "Unknown"
            city = response.city.name if response.city.name else "Unknown"
            latitude = response.location.latitude if response.location.latitude else 0
            longitude = response.location.longitude if response.location.longitude else 0
            
            return {
                'Country': country,
                'Region': region,
                'City': city,
                'Latitude': latitude,
                'Longitude': longitude
            }
        except Exception as e:
            print(f"Error looking up IP {ip} in GeoLite2 database: {e}")
    
    # Default values if all lookups fail
    return {
        'Country': 'Unknown',
        'Region': 'Unknown',
        'City': 'Unknown',
        'Latitude': 0,
        'Longitude': 0
    }

def parse_audit_logs(file_path, geoip_db_path="./attached_assets/GeoLite2-City.mmdb"):
    """
    Parse audit logs from CSV or Excel file and return a timeline of events with geolocation data.
    
    Parameters:
    file_path (str): Path to the input CSV or Excel file
    geoip_db_path (str): Path to the GeoLite2 database
    
    Returns:
    list: Timeline of events with geolocation data
    """
    try:
        # Initialize GeoIP2 reader if database file exists
        geo_reader = None
        try:
            if os.path.exists(geoip_db_path):
                geo_reader = geoip2.database.Reader(geoip_db_path)
                print(f"Successfully loaded GeoLite2 database from {geoip_db_path}")
            else:
                print(f"GeoLite2 database not found at {geoip_db_path}. Trying other locations...")
                # Try alternate locations
                alt_paths = [
                    "GeoLite2-City.mmdb",
                    "./GeoLite2-City.mmdb",
                    "../attached_assets/GeoLite2-City.mmdb",
                    "/attached_assets/GeoLite2-City.mmdb",
                ]
                for alt_path in alt_paths:
                    if os.path.exists(alt_path):
                        geo_reader = geoip2.database.Reader(alt_path)
                        print(f"Successfully loaded GeoLite2 database from {alt_path}")
                        break
                
                if not geo_reader:
                    print("GeoLite2 database not found in any location. IP geolocation will be limited.")
        except Exception as e:
            print(f"Error opening GeoIP database: {e}")
            geo_reader = None

        # Determine file type and read accordingly
        file_extension = os.path.splitext(file_path)[1].lower()
        
        if file_extension == '.csv':
            df = pd.read_csv(file_path)
        elif file_extension in ['.xlsx', '.xls']:
            df = pd.read_excel(file_path)
        else:
            raise ValueError(f"Unsupported file format: {file_extension}")

        # Select relevant columns if they exist
        columns_of_interest = ['CreationDate', 'Operation', 'UserId', 'AuditData']
        for col in columns_of_interest:
            if col not in df.columns:
                raise ValueError(f"Required column '{col}' not found in the input file")
        
        df = df[columns_of_interest]

        # Convert CreationDate to datetime for sorting
        df['CreationDate'] = pd.to_datetime(df['CreationDate'])
        df = df.sort_values(by='CreationDate')

        # Parse AuditData and create a timeline with geolocation data
        timeline = []
        # Keep track of IPs we've already looked up to avoid repeated lookups
        ip_geo_cache = {}
        
        for _, row in df.iterrows():
            try:
                # Check if AuditData is a string, if so, parse it
                audit_data = row['AuditData']
                if isinstance(audit_data, str):
                    audit_data = json.loads(audit_data)
                elif not isinstance(audit_data, dict):
                    # If it's neither a string nor a dict, skip this row
                    continue
                
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
                
                # Use our cache to avoid looking up the same IP multiple times
                if ip in ip_geo_cache:
                    event.update(ip_geo_cache[ip])
                else:
                    # Get geolocation data and cache it
                    geo_data = get_ip_geolocation(ip, geo_reader)
                    ip_geo_cache[ip] = geo_data
                    event.update(geo_data)

                timeline.append(event)
            except json.JSONDecodeError:
                print(f"Error parsing AuditData for record at {row['CreationDate']}")
        
        # Clean up geo reader
        if geo_reader:
            geo_reader.close()
            
        return timeline

    except Exception as e:
        print(f"Error processing file: {e}")
        raise

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
    # If the country is not USA or region is not Mass, flag as anomalous
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