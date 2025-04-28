import streamlit as st
import pandas as pd
import folium
from streamlit_folium import folium_static
import tempfile
import os
import json
from utils import parse_audit_logs, detect_compromised_events, filter_files_accessed, filter_anomalous_ips

# Set page configuration
st.set_page_config(
    page_title="Security Audit Log Analyzer",
    page_icon="🔒",
    layout="wide"
)

# Title and description
st.title("🔒 Security Audit Log Analyzer")
st.markdown("""
This tool analyzes audit logs to identify anomalous IP activities and potential security breaches.
Upload your CSV or Excel file containing the audit logs to get started.
""")

# Sidebar for file upload and options
with st.sidebar:
    st.header("Upload Data")
    uploaded_file = st.file_uploader("Choose a CSV or Excel file", type=["csv", "xlsx", "xls"])
    
    st.header("GeoIP Database")
    geoip_file = st.file_uploader("Upload GeoLite2-City.mmdb (optional)", type=["mmdb"])
    
    if uploaded_file is not None:
        st.success("File uploaded successfully!")
        
        # Save the GeoIP database to a temporary file if uploaded
        geoip_db_path = None
        if geoip_file is not None:
            temp_dir = tempfile.mkdtemp()
            geoip_db_path = os.path.join(temp_dir, "GeoLite2-City.mmdb")
            with open(geoip_db_path, "wb") as f:
                f.write(geoip_file.getbuffer())
            st.success("GeoIP database loaded!")

# Main content area
if uploaded_file is not None:
    # Process the uploaded file
    try:
        file_extension = uploaded_file.name.split(".")[-1].lower()
        
        # Save the uploaded file to a temporary location
        with tempfile.NamedTemporaryFile(delete=False, suffix=f'.{file_extension}') as tmp_file:
            tmp_file.write(uploaded_file.getbuffer())
            temp_filepath = tmp_file.name
        
        with st.spinner("Analyzing audit logs..."):
            # Process the file based on its extension
            timeline = parse_audit_logs(temp_filepath, geoip_db_path)
            compromised_events = detect_compromised_events(timeline)
            files_accessed = filter_files_accessed(timeline)
            anomalous_ips = filter_anomalous_ips(timeline)
        
        # Clean up temporary file
        os.unlink(temp_filepath)
        
        # Display summary metrics
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Total Events", len(timeline))
        with col2:
            st.metric("Suspicious Events", len(compromised_events))
        with col3:
            st.metric("Files Accessed", len(files_accessed))
        with col4:
            st.metric("Anomalous IPs", len({event['ClientIP'] for event in anomalous_ips}))
        
        # Create tabs for different views
        tab1, tab2, tab3, tab4 = st.tabs(["Map View", "Suspicious Events", "Files Accessed", "Timeline"])
        
        with tab1:
            st.header("Anomalous IP Locations")
            
            # Create a map centered at a default location
            m = folium.Map(location=[40, 0], zoom_start=2)
            
            # Add markers for anomalous IPs
            unique_ips = {}
            for event in anomalous_ips:
                ip = event['ClientIP']
                country = event['Country']
                region = event['Region']
                
                # Skip if IP is Unknown or missing geo data
                if ip == 'N/A' or country == "Unknown":
                    continue
                
                # Create a key for each unique location to avoid duplicate markers
                key = f"{ip}_{country}_{region}"
                if key not in unique_ips:
                    unique_ips[key] = {
                        'ip': ip,
                        'country': country,
                        'region': region,
                        'events': []
                    }
                unique_ips[key]['events'].append(event)
            
            # Add markers to the map
            for location_key, location_data in unique_ips.items():
                # Get first event to extract geo coordinates (assuming all events for this IP have same coords)
                first_event = location_data['events'][0]
                
                # Prepare popup content
                popup_content = f"""
                <b>IP:</b> {location_data['ip']}<br>
                <b>Country:</b> {location_data['country']}<br>
                <b>Region:</b> {location_data['region']}<br>
                <b>Events:</b> {len(location_data['events'])}<br>
                <hr>
                <b>Events Details:</b><br>
                """
                
                for i, event in enumerate(location_data['events'][:5]):  # Limit to first 5 events to avoid huge popups
                    popup_content += f"""
                    <b>Event {i+1}:</b><br>
                    - Time: {event['Timestamp']}<br>
                    - Operation: {event['Operation']}<br>
                    - User: {event['UserId']}<br>
                    """
                    if event.get('FileName'):
                        popup_content += f"- File: {event['FileName']}<br>"
                        
                if len(location_data['events']) > 5:
                    popup_content += f"<i>...and {len(location_data['events']) - 5} more events</i>"
                
                # Add marker to map
                folium.Marker(
                    # For demo purposes, we'll generate coordinates based on the country code
                    # In a real implementation, you would use actual lat/long from the GeoIP lookup
                    location=[
                        40 + hash(location_data['country']) % 30 - 15,  # Pseudo-random latitude
                        hash(location_data['region']) % 60 - 30         # Pseudo-random longitude
                    ],
                    popup=folium.Popup(popup_content, max_width=300),
                    tooltip=f"{location_data['ip']} ({location_data['country']})",
                    icon=folium.Icon(color='red', icon='info-sign')
                ).add_to(m)
            
            # Display the map
            folium_static(m)
            
            # Display table of anomalous IPs
            st.subheader("Anomalous IP Details")
            if anomalous_ips:
                df_anomalous = pd.DataFrame(anomalous_ips)
                st.dataframe(df_anomalous, use_container_width=True)
            else:
                st.info("No anomalous IPs detected in the dataset.")
        
        with tab2:
            st.header("Suspicious Events")
            if compromised_events:
                df_compromised = pd.DataFrame(compromised_events)
                st.dataframe(df_compromised, use_container_width=True)
            else:
                st.info("No suspicious events detected in the dataset.")
        
        with tab3:
            st.header("Files Accessed Events")
            if files_accessed:
                df_files = pd.DataFrame(files_accessed)
                st.dataframe(df_files, use_container_width=True)
            else:
                st.info("No file access events found in the dataset.")
        
        with tab4:
            st.header("Complete Timeline")
            if timeline:
                df_timeline = pd.DataFrame(timeline)
                st.dataframe(df_timeline, use_container_width=True)
            else:
                st.info("No timeline events found in the dataset.")
        
        # Add download button for the results
        st.subheader("Download Results")
        
        # Create a temporary Excel file with the results
        with tempfile.NamedTemporaryFile(delete=False, suffix='.xlsx') as tmp_xlsx:
            with pd.ExcelWriter(tmp_xlsx.name, engine='openpyxl') as writer:
                pd.DataFrame(timeline).to_excel(writer, sheet_name='Timeline', index=False)
                pd.DataFrame(compromised_events).to_excel(writer, sheet_name='Suspicious Events', index=False)
                pd.DataFrame(files_accessed).to_excel(writer, sheet_name='FilesAccessed', index=False)
                pd.DataFrame(anomalous_ips).to_excel(writer, sheet_name='AnomalousIPs', index=False)
            
            # Provide download button
            with open(tmp_xlsx.name, "rb") as f:
                excel_data = f.read()
                st.download_button(
                    label="Download Excel Report",
                    data=excel_data,
                    file_name="security_analysis_report.xlsx",
                    mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
                )
            
            # Clean up the temporary file
            os.unlink(tmp_xlsx.name)
        
    except Exception as e:
        st.error(f"Error processing file: {str(e)}")
        st.exception(e)
else:
    # Display instructions when no file is uploaded
    st.info("📤 Please upload a CSV or Excel file containing audit logs to begin analysis.")
    
    # Display example data structure
    st.subheader("Expected Data Structure")
    st.markdown("""
    The uploaded file should contain audit logs with the following columns:
    
    - **CreationDate**: The timestamp of the event
    - **Operation**: The operation performed (e.g., FileAccessed, SoftDelete)
    - **UserId**: The user ID associated with the event
    - **AuditData**: JSON data containing details like ClientIP, ResultStatus, etc.
    
    For optimal results, also upload the GeoLite2-City.mmdb database for IP geolocation.
    """)

# Footer
st.markdown("---")
st.markdown("🔒 Security Audit Log Analyzer - Helping IT teams identify potential security breaches")
