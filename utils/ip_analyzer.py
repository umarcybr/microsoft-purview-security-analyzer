import pandas as pd
import re
import geoip2.database
import os
from pathlib import Path

def analyze_ips(df):
    """
    Analyze the DataFrame to identify anomalous IPs and their details.
    
    Args:
        df (pandas.DataFrame): DataFrame containing the log data
        
    Returns:
        tuple: (list of anomalous IPs, dictionary with IP details)
    """
    # Identify IP address columns
    ip_columns = [col for col in df.columns if any(term in col for term in ['ip', 'address', 'source'])]
    
    # If no IP columns found, try to find columns with IP-like values
    if not ip_columns:
        for col in df.columns:
            # Check if any value in the column matches basic IP format
            if df[col].astype(str).str.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$').any():
                ip_columns.append(col)
    
    # If still no IP columns found, raise an error
    if not ip_columns:
        raise ValueError("No IP address columns found in the file. Please ensure your data contains IP information.")
    
    # Identify file/resource access columns
    file_columns = [col for col in df.columns if any(term in col for term in ['file', 'resource', 'path', 'access'])]
    
    # Use the first IP column if multiple are found
    ip_column = ip_columns[0]
    
    # Extract all unique IPs
    all_ips = pd.unique(df[ip_column].astype(str))
    
    # Filter for valid IPs
    ip_pattern = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
    valid_ips = [ip for ip in all_ips if ip_pattern.match(ip)]
    
    # Identify anomalous IPs (this is a simple heuristic that can be improved)
    # For this example, we'll consider IPs anomalous if they appear less frequently
    ip_counts = df[ip_column].value_counts()
    
    # Calculate average and standard deviation of access counts
    avg_count = ip_counts.mean()
    std_count = ip_counts.std()
    
    # IPs with very low frequency (less than average - 1 standard deviation)
    # or very high frequency (more than average + 2 standard deviations) are considered anomalous
    anomalous_ips = []
    for ip in valid_ips:
        count = ip_counts.get(ip, 0)
        if count < max(1, avg_count - std_count) or count > avg_count + 2 * std_count:
            anomalous_ips.append(ip)
    
    # Get details for each anomalous IP
    ip_details = {}
    for ip in anomalous_ips:
        # Get accessed files for this IP
        if file_columns:
            file_col = file_columns[0]
            accessed_files = df[df[ip_column] == ip][file_col].unique().tolist()
        else:
            accessed_files = []
        
        # Get geolocation data
        geo_data = get_ip_geolocation(ip)
        
        # Store all details
        ip_details[ip] = {
            'country': geo_data.get('country', 'Unknown'),
            'city': geo_data.get('city', 'Unknown'),
            'latitude': geo_data.get('latitude', 0),
            'longitude': geo_data.get('longitude', 0),
            'accessed_files': accessed_files,
            'access_count': int(ip_counts.get(ip, 0))
        }
    
    return anomalous_ips, ip_details

def get_ip_geolocation(ip):
    """
    Get geolocation data for an IP address using GeoLite2-City.mmdb.
    
    Args:
        ip (str): IP address
        
    Returns:
        dict: Geolocation data (country, city, latitude, longitude)
    """
    # Try common paths for the GeoLite2-City.mmdb database
    possible_paths = [
        './GeoLite2-City.mmdb',
        '../GeoLite2-City.mmdb',
        '/app/GeoLite2-City.mmdb',
        str(Path.home() / 'GeoLite2-City.mmdb')
    ]
    
    db_path = None
    for path in possible_paths:
        if os.path.exists(path):
            db_path = path
            break
    
    if not db_path:
        # If database file not found, return dummy data
        return {
            'country': 'Unknown',
            'city': 'Unknown',
            'latitude': 0,
            'longitude': 0
        }
    
    try:
        # Open the GeoLite2 database
        with geoip2.database.Reader(db_path) as reader:
            # Look up the IP address
            response = reader.city(ip)
            
            # Extract relevant information
            return {
                'country': response.country.name or 'Unknown',
                'city': response.city.name or 'Unknown',
                'latitude': response.location.latitude or 0,
                'longitude': response.location.longitude or 0
            }
    except Exception as e:
        # Handle errors (invalid IP, not found in database, etc.)
        print(f"Error getting geolocation for IP {ip}: {str(e)}")
        return {
            'country': 'Unknown',
            'city': 'Unknown',
            'latitude': 0,
            'longitude': 0
        }
