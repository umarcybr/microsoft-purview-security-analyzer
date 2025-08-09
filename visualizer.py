import folium
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from folium.plugins import MarkerCluster
import streamlit as st

def create_ip_map(ip_events):
    """
    Creates a folium map with markers for IP addresses.
    
    Args:
        ip_events: List of events with IP data, including lat/long
    
    Returns:
        A folium map object
    """
    # Create base map centered at a default location
    m = folium.Map(location=[20, 0], zoom_start=2, )
    
    # Add marker clusters to handle many points
    marker_cluster = MarkerCluster().add_to(m)
    
    # Track IPs that have been added to avoid duplicates
    added_ips = set()
    
    # Add markers for each IP
    for event in ip_events:
        ip = event.get('ClientIP')
        lat = event.get('Latitude')
        lon = event.get('Longitude')
        
        # Skip if no location data or already added
        if not lat or not lon or ip in added_ips:
            continue
            
        added_ips.add(ip)
        
        # Determine if anomalous
        is_anomalous = is_ip_anomalous(event)
        
        # Create popup content
        popup_html = f"""
        <div style="width: 200px">
            <b>IP:</b> {ip}<br>
            <b>Country:</b> {event.get('Country', 'Unknown')}<br>
            <b>Region:</b> {event.get('Region', 'Unknown')}<br>
            <b>City:</b> {event.get('City', 'Unknown')}<br>
            <b>User:</b> {event.get('UserId', 'Unknown')}<br>
            <b>First Seen:</b> {event.get('Timestamp').strftime('%Y-%m-%d %H:%M:%S')}<br>
            <b>Anomalous:</b> {"Yes" if is_anomalous else "No"}<br>
        </div>
        """
        
        # Choose color based on anomalous status
        color = 'red' if is_anomalous else 'blue'
        
        # Add marker to the cluster
        folium.Marker(
            location=[lat, lon],
            popup=folium.Popup(popup_html, max_width=300),
            icon=folium.Icon(color=color, icon='info-sign'),
        ).add_to(marker_cluster)
    
    return m

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

def create_ip_detail_map(ip_data):
    """Creates a map for a single IP with detailed information."""
    if not ip_data.get('latitude') or not ip_data.get('longitude'):
        return None
        
    m = folium.Map(location=[ip_data['latitude'], ip_data['longitude']], zoom_start=10)
    
    # Create popup with detailed information
    popup_html = f"""
    <div style="width: 250px">
        <h4>{ip_data.get('ip', 'Unknown IP')}</h4>
        <b>Location:</b> {ip_data.get('city', 'Unknown')}, {ip_data.get('region', 'Unknown')}, {ip_data.get('country', 'Unknown')}<br>
        <b>Events:</b> {ip_data.get('count', 0)}<br>
        <b>Users:</b> {', '.join(ip_data.get('users', []))}<br>
        <b>First Seen:</b> {ip_data.get('first_seen').strftime('%Y-%m-%d %H:%M:%S') if isinstance(ip_data.get('first_seen'), pd.Timestamp) else 'Unknown'}<br>
        <b>Last Seen:</b> {ip_data.get('last_seen').strftime('%Y-%m-%d %H:%M:%S') if isinstance(ip_data.get('last_seen'), pd.Timestamp) else 'Unknown'}<br>
        <b>Anomalous:</b> {"Yes" if ip_data.get('is_anomalous', False) else "No"}<br>
    </div>
    """
    
    # Add marker
    color = 'red' if ip_data.get('is_anomalous', False) else 'blue'
    folium.Marker(
        location=[ip_data['latitude'], ip_data['longitude']],
        popup=folium.Popup(popup_html, max_width=300),
        icon=folium.Icon(color=color, icon='info-sign'),
    ).add_to(m)
    
    return m

def create_operations_chart(timeline):
    """Create a bar chart of operations."""
    operations = {}
    for event in timeline:
        op = event.get('Operation', 'Unknown')
        operations[op] = operations.get(op, 0) + 1
    
    # Convert to dataframe
    df = pd.DataFrame({
        'Operation': list(operations.keys()),
        'Count': list(operations.values())
    })
    
    # Sort by count descending
    df = df.sort_values('Count', ascending=False)
    
    # Create chart
    fig = px.bar(
        df,
        x='Operation',
        y='Count',
        title='Operations by Frequency',
        color='Operation'
    )
    
    return fig

def create_country_chart(timeline):
    """Create a bar chart of countries."""
    countries = {}
    for event in timeline:
        country = event.get('Country', 'Unknown')
        countries[country] = countries.get(country, 0) + 1
    
    # Convert to dataframe
    df = pd.DataFrame({
        'Country': list(countries.keys()),
        'Count': list(countries.values())
    })
    
    # Sort by count descending
    df = df.sort_values('Count', ascending=False)
    
    # Create chart
    fig = px.bar(
        df,
        x='Country',
        y='Count',
        title='Events by Country',
        color='Country'
    )
    
    return fig

def create_timeline_chart(timeline):
    """Create a timeline chart showing events over time."""
    # Convert to dataframe
    df = pd.DataFrame(timeline)
    
    # Group by day and operation
    df['date'] = df['Timestamp'].dt.date
    daily_counts = df.groupby(['date', 'Operation']).size().reset_index(name='count')
    
    # Create chart
    fig = px.line(
        daily_counts,
        x='date',
        y='count',
        color='Operation',
        title='Events Over Time',
        labels={'date': 'Date', 'count': 'Number of Events'}
    )
    
    return fig

def create_anomalous_ip_chart(timeline):
    """Create a pie chart showing anomalous vs normal IPs."""
    # Count anomalous vs normal
    anomalous = 0
    normal = 0
    
    for event in timeline:
        if is_ip_anomalous(event):
            anomalous += 1
        else:
            normal += 1
    
    # Create chart
    fig = go.Figure(data=[go.Pie(
        labels=['Anomalous', 'Normal'],
        values=[anomalous, normal],
        hole=.3,
        marker_colors=['#FF5252', '#4CAF50']
    )])
    
    fig.update_layout(title_text="Anomalous vs Normal Events")
    
    return fig
