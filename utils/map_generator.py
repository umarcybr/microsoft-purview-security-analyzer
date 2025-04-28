import folium
from folium.plugins import MarkerCluster
import tempfile

def generate_map(anomalous_ips, ip_details):
    """
    Generate an interactive map with markers for anomalous IPs.
    
    Args:
        anomalous_ips (list): List of anomalous IP addresses
        ip_details (dict): Dictionary with details for each anomalous IP
        
    Returns:
        str: HTML string of the generated map
    """
    # Create a map centered on the first anomalous IP, or default to world view
    if anomalous_ips and ip_details:
        first_ip = anomalous_ips[0]
        first_details = ip_details[first_ip]
        center_lat = first_details.get('latitude', 0)
        center_lon = first_details.get('longitude', 0)
        
        # If coordinates are not available, default to world view
        if center_lat == 0 and center_lon == 0:
            center_lat = 0
            center_lon = 0
            zoom_start = 2
        else:
            zoom_start = 4
    else:
        # Default to world view if no anomalous IPs found
        center_lat = 0
        center_lon = 0
        zoom_start = 2
    
    # Create the map
    m = folium.Map(location=[center_lat, center_lon], zoom_start=zoom_start, 
                  tiles='OpenStreetMap')
    
    # Add title and description
    title_html = '''
         <h3 align="center" style="font-size:16px"><b>Anomalous IP Activity Map</b></h3>
         <p align="center" style="font-size:12px">Red markers indicate potentially malicious activity</p>
         '''
    m.get_root().html.add_child(folium.Element(title_html))
    
    # Create a marker cluster for better performance with many points
    marker_cluster = MarkerCluster().add_to(m)
    
    # Add markers for each anomalous IP
    for ip in anomalous_ips:
        details = ip_details.get(ip, {})
        lat = details.get('latitude', 0)
        lon = details.get('longitude', 0)
        
        # Skip if no geolocation data
        if lat == 0 and lon == 0:
            continue
        
        # Create popup content
        popup_content = f"""
        <div style="width:250px">
            <b>IP Address:</b> {ip}<br>
            <b>Country:</b> {details.get('country', 'Unknown')}<br>
            <b>City:</b> {details.get('city', 'Unknown')}<br>
            <b>Access Count:</b> {details.get('access_count', 0)}<br>
            <b>Accessed Files:</b><br>
        """
        
        # Add list of accessed files
        accessed_files = details.get('accessed_files', [])
        if accessed_files:
            popup_content += "<ul style='padding-left:20px; margin-top:5px'>"
            for file in accessed_files[:10]:  # Limit to 10 files to avoid huge popups
                popup_content += f"<li>{file}</li>"
            
            if len(accessed_files) > 10:
                popup_content += f"<li>... and {len(accessed_files) - 10} more</li>"
            
            popup_content += "</ul>"
        else:
            popup_content += "<p>No file access data available</p>"
        
        popup_content += "</div>"
        
        # Create and add the marker
        folium.Marker(
            location=[lat, lon],
            popup=folium.Popup(popup_content, max_width=300),
            tooltip=f"IP: {ip} - {details.get('country', 'Unknown')}",
            icon=folium.Icon(color='red', icon='info-sign')
        ).add_to(marker_cluster)
    
    # Save the map to a temporary HTML file
    with tempfile.NamedTemporaryFile(suffix='.html', delete=False) as tmp_file:
        m.save(tmp_file.name)
        # Read the HTML content
        with open(tmp_file.name, 'r') as f:
            html_content = f.read()
        
        # Delete the temporary file
        import os
        os.unlink(tmp_file.name)
    
    return html_content
