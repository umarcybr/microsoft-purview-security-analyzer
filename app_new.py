import streamlit as st
import pandas as pd
import folium
from streamlit_folium import st_folium
import tempfile
import os
import json
from security_analyzer import parse_audit_logs, detect_compromised_events, filter_files_accessed, filter_anomalous_ips, apply_filters

# Initialize session state variables to store processed data between re-renders
if 'processed' not in st.session_state:
    st.session_state.processed = False
if 'timeline' not in st.session_state:
    st.session_state.timeline = None
if 'compromised_events' not in st.session_state:
    st.session_state.compromised_events = None
if 'files_accessed' not in st.session_state:
    st.session_state.files_accessed = None
if 'anomalous_ips' not in st.session_state:
    st.session_state.anomalous_ips = None

# Set page configuration
st.set_page_config(
    page_title="Microsoft Purview Security Analyzer",
    page_icon="🔒",
    layout="wide"
)

# Title and description
st.title("Microsoft Purview Security Analyzer")
st.markdown("""
This tool helps identify anomalous IP activities and potentially compromised events in audit logs.
Upload your CSV or Excel file to analyze the data and visualize suspicious activities on the map.
""")

# Add file upload widget
uploaded_file = st.file_uploader("Upload CSV or Excel file", type=["csv", "xlsx", "xls"])

# Add filtering options in sidebar
st.sidebar.header("🔍 Anomaly Filters")
st.sidebar.markdown("Customize which types of anomalies to display:")

# Initialize filter states if not already set
if 'filter_by_risk_level' not in st.session_state:
    st.session_state.filter_by_risk_level = ['High', 'Medium', 'Low']
if 'filter_by_operation' not in st.session_state:
    st.session_state.filter_by_operation = []
if 'filter_by_country' not in st.session_state:
    st.session_state.filter_by_country = []
if 'filter_by_date_range' not in st.session_state:
    st.session_state.filter_by_date_range = False

# Risk Level Filter
st.sidebar.subheader("Risk Level")
risk_levels = st.sidebar.multiselect(
    "Select risk levels to display:",
    options=['High', 'Medium', 'Low'],
    default=st.session_state.filter_by_risk_level,
    key='risk_filter'
)
st.session_state.filter_by_risk_level = risk_levels

# Anomaly Type Filter
st.sidebar.subheader("Anomaly Types")
anomaly_types = st.sidebar.multiselect(
    "Select anomaly types:",
    options=['Geographic Anomaly', 'Time Anomaly', 'Access Pattern Anomaly', 'Failed Authentication', 'Privilege Escalation'],
    default=[],
    key='anomaly_type_filter'
)

# Geographic Filter
st.sidebar.subheader("Geographic Filter")
enable_geo_filter = st.sidebar.checkbox("Filter by geographic location", value=False)
if enable_geo_filter:
    excluded_countries = st.sidebar.multiselect(
        "Exclude countries:",
        options=['Unknown', 'Local', 'US', 'CA', 'GB', 'DE', 'FR', 'JP', 'AU'],
        default=['Local'],
        help="Select countries to exclude from results"
    )
else:
    excluded_countries = []

# Time-based Filter
st.sidebar.subheader("Time Filter")
enable_time_filter = st.sidebar.checkbox("Filter by time period", value=False)
if enable_time_filter:
    time_filter_type = st.sidebar.selectbox(
        "Time filter type:",
        options=['Business Hours Only', 'Outside Business Hours', 'Weekends Only', 'Custom Range']
    )
    if time_filter_type == 'Custom Range':
        col1, col2 = st.sidebar.columns(2)
        with col1:
            start_time = st.time_input("Start time", value=None)
        with col2:
            end_time = st.time_input("End time", value=None)
else:
    time_filter_type = None

# IP Pattern Filter
st.sidebar.subheader("IP Pattern Filter")
enable_ip_filter = st.sidebar.checkbox("Filter by IP patterns", value=False)
if enable_ip_filter:
    ip_filter_options = st.sidebar.multiselect(
        "IP pattern types:",
        options=['First-time IPs', 'Frequent IPs', 'Single-use IPs', 'Cross-country IPs'],
        default=[],
        help="Filter based on IP usage patterns"
    )
else:
    ip_filter_options = []

# Reset filters button
if st.sidebar.button("Reset All Filters"):
    st.session_state.filter_by_risk_level = ['High', 'Medium', 'Low']
    st.session_state.filter_by_operation = []
    st.session_state.filter_by_country = []
    st.session_state.filter_by_date_range = False
    st.rerun()

# Function to save uploaded file temporarily
def save_uploaded_file(uploaded_file):
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=os.path.splitext(uploaded_file.name)[1]) as tmp:
            tmp.write(uploaded_file.getvalue())
            return tmp.name
    except Exception as e:
        st.error(f"Error saving file: {e}")
        return None

# Function to create map with anomalous IPs
def create_map(anomalous_ips):
    # Create a map centered at a default location
    m = folium.Map(location=[20, 0], zoom_start=2)
    
    # Add markers for each anomalous IP
    ip_locations = {}
    
    for idx, event in enumerate(anomalous_ips):
        # Skip if Country or Region is unknown
        if event.get('Country') == 'Unknown' or event.get('Region') == 'Unknown':
            continue
        
        # Get location and create a unique key
        lat = event.get('Latitude', 0)
        lon = event.get('Longitude', 0)
        
        if lat == 0 and lon == 0:
            continue
            
        location_key = f"{lat}_{lon}"
        
        # Check if we already have a marker at this location
        if location_key in ip_locations:
            ip_locations[location_key]['count'] += 1
            ip_locations[location_key]['events'].append(event)
        else:
            ip_locations[location_key] = {
                'lat': lat,
                'lon': lon,
                'count': 1,
                'events': [event]
            }
    
    # Add markers for each unique location
    for location_key, location_data in ip_locations.items():
        # Create popup with all events at this location
        popup_content = "<div style='width: 300px'><h4>Location Events</h4>"
        for idx, event in enumerate(location_data['events']):
            popup_content += f"""
            <div style="margin-bottom: 10px; border-bottom: 1px solid #ccc; padding-bottom: 5px;">
                <p><b>Event {idx+1}</b></p>
                <p><b>IP Address:</b> {event.get('ClientIP', 'N/A')}</p>
                <p><b>Timestamp:</b> {event.get('Timestamp', 'N/A')}</p>
                <p><b>Operation:</b> {event.get('Operation', 'N/A')}</p>
                <p><b>User ID:</b> {event.get('UserId', 'N/A')}</p>
                <p><b>Location:</b> {event.get('Region', 'Unknown')}, {event.get('Country', 'Unknown')}</p>
            </div>
            """
        popup_content += "</div>"
        
        # Add marker with the count of events
        folium.Marker(
            location=[location_data['lat'], location_data['lon']],
            popup=folium.Popup(popup_content, max_width=350),
            tooltip=f"{location_data['count']} event(s) at this location",
            icon=folium.Icon(color='red', icon='info-sign')
        ).add_to(m)
    
    return m

# Function to process the data (only runs when we need to)
def process_data(file_path):
    # Set up a progress bar for file processing
    progress_bar = st.progress(0)
    status_text = st.empty()
    
    # Process the file with progress updates
    status_text.text("Reading and parsing the file...")
    progress_bar.progress(10)
    
    # Parse the audit logs with our optimized geolocation service
    timeline = parse_audit_logs(file_path)
    
    if not timeline:
        progress_bar.progress(100)
        status_text.text("")
        st.error("No data could be processed from the file. Please check the file format.")
        return False
    
    status_text.text("Processing IP geolocation data...")
    progress_bar.progress(50)
    
    # Continue with analysis
    status_text.text("Analyzing anomalies and generating insights...")
    progress_bar.progress(80)
    
    # Extract insights
    compromised_events = detect_compromised_events(timeline)
    files_accessed = filter_files_accessed(timeline)
    anomalous_ips = filter_anomalous_ips(timeline)
    
    # Store results in session state
    st.session_state.timeline = timeline
    st.session_state.compromised_events = compromised_events
    st.session_state.files_accessed = files_accessed
    st.session_state.anomalous_ips = anomalous_ips
    st.session_state.processed = True
    
    # Complete the progress bar
    progress_bar.progress(100)
    status_text.text("")
    st.success(f"Successfully processed {len(timeline)} events.")
    return True

# Main application logic
if uploaded_file is not None:
    try:
        # Reset session state if a new file is uploaded
        current_file = getattr(st.session_state, 'current_file', None) 
        if current_file != uploaded_file.name:
            st.session_state.processed = False
            st.session_state.current_file = uploaded_file.name
        
        # Only process the file if we haven't already done so for this file
        if not st.session_state.processed:
            # Save uploaded file temporarily
            temp_file_path = save_uploaded_file(uploaded_file)
            # Process the file only if we have a valid file path
            if temp_file_path:
                process_data(temp_file_path)
                # Clean up temporary file when done
                if os.path.exists(temp_file_path):
                    os.unlink(temp_file_path)
            else:
                st.error("Failed to save uploaded file. Please try again.")
        
        # If processing was successful, display the results
        if st.session_state.processed and st.session_state.timeline is not None:
            # Get data from session state
            timeline = st.session_state.timeline
            compromised_events = st.session_state.compromised_events or []
            files_accessed = st.session_state.files_accessed or []
            anomalous_ips = st.session_state.anomalous_ips or []
            
            # Apply custom filters
            filter_config = {
                'risk_levels': risk_levels,
                'anomaly_types': anomaly_types,
                'excluded_countries': excluded_countries,
                'time_filter_type': time_filter_type if enable_time_filter else None,
                'ip_filter_options': ip_filter_options if enable_ip_filter else [],
            }
            
            # Add custom time range if applicable
            if enable_time_filter and time_filter_type == 'Custom Range':
                if 'start_time' in locals() and 'end_time' in locals():
                    filter_config['start_time'] = start_time
                    filter_config['end_time'] = end_time
            
            # Apply filters to each dataset
            filtered_compromised = apply_filters(compromised_events, filter_config)
            filtered_files_accessed = apply_filters(files_accessed, filter_config) 
            filtered_anomalous_ips = apply_filters(anomalous_ips, filter_config)
            filtered_timeline = apply_filters(timeline, filter_config)
            
            # Update variables to use filtered data
            compromised_events = filtered_compromised
            files_accessed = filtered_files_accessed
            anomalous_ips = filtered_anomalous_ips
            timeline_filtered = filtered_timeline
            
            # Display filter summary if filters are active
            active_filters = []
            if risk_levels and len(risk_levels) < 3:
                active_filters.append(f"Risk: {', '.join(risk_levels)}")
            if anomaly_types:
                active_filters.append(f"Types: {', '.join(anomaly_types)}")
            if excluded_countries:
                active_filters.append(f"Excluded: {', '.join(excluded_countries)}")
            if enable_time_filter:
                active_filters.append(f"Time: {time_filter_type}")
            if enable_ip_filter and ip_filter_options:
                active_filters.append(f"IP: {', '.join(ip_filter_options)}")
            
            if active_filters:
                st.info(f"🔍 **Active Filters:** {' | '.join(active_filters)}")
            
            # Add legend for risk levels
            st.markdown("""
            **Risk Level Legend:**
            <div style="display: flex; gap: 20px; margin: 10px 0;">
                <span style="background-color: #ff4444; color: white; padding: 4px 8px; border-radius: 4px;">High Risk</span>
                <span style="background-color: #ff8800; color: white; padding: 4px 8px; border-radius: 4px;">Medium Risk</span>
                <span style="background-color: #44aa44; color: white; padding: 4px 8px; border-radius: 4px;">Low Risk</span>
            </div>
            """, unsafe_allow_html=True)
            
            # Display summary statistics
            col1, col2, col3, col4 = st.columns(4)
            total_before = len(st.session_state.timeline)
            col1.metric("Total Events", f"{len(timeline_filtered)}", delta=f"{len(timeline_filtered) - total_before}" if active_filters else None)
            col2.metric("Suspicious Events", len(compromised_events))
            col3.metric("Files Accessed", len(files_accessed))
            col4.metric("Anomalous IPs", len(anomalous_ips))
            
            # Create tabs for different views
            tab1, tab2, tab3, tab4 = st.tabs(["Map View", "Suspicious Events", "Files Accessed", "All Events"])
            
            with tab1:
                st.subheader("Anomalous IP Activity Map")
                st.markdown("Red markers indicate locations with anomalous IP activity. Click on a marker to see details.")
                
                # Create and display the map
                if anomalous_ips:
                    map_data = create_map(anomalous_ips)
                    st_folium(map_data, width=1200, height=600)
                else:
                    st.info("No anomalous IP activity detected in the data.")
                
                # Display anomalous IP events in a table
                if anomalous_ips:
                    st.subheader("Anomalous IP Events")
                    # Convert to DataFrame for better display
                    anomalous_df = pd.DataFrame(anomalous_ips)
                    # Format timestamp column
                    if 'Timestamp' in anomalous_df.columns:
                        anomalous_df['Timestamp'] = pd.to_datetime(anomalous_df['Timestamp']).dt.strftime('%Y-%m-%d %H:%M:%S')
                    
                    # Add color coding for risk levels if available
                    if 'RiskLevel' in anomalous_df.columns:
                        def highlight_risk(val):
                            if val == 'High':
                                return 'background-color: #ff4444; color: white'
                            elif val == 'Medium':
                                return 'background-color: #ff8800; color: white'
                            elif val == 'Low':
                                return 'background-color: #44aa44; color: white'
                            return ''
                        styled_df = anomalous_df.style.applymap(highlight_risk, subset=['RiskLevel'])
                        st.dataframe(styled_df)
                    else:
                        st.dataframe(anomalous_df)
            
            with tab2:
                st.subheader("Suspicious Events")
                if compromised_events:
                    compromised_df = pd.DataFrame(compromised_events)
                    # Format timestamp column
                    if 'Timestamp' in compromised_df.columns:
                        compromised_df['Timestamp'] = pd.to_datetime(compromised_df['Timestamp']).dt.strftime('%Y-%m-%d %H:%M:%S')
                    
                    # Add color coding for risk levels if available
                    if 'RiskLevel' in compromised_df.columns:
                        def highlight_risk(val):
                            if val == 'High':
                                return 'background-color: #ff4444; color: white'
                            elif val == 'Medium':
                                return 'background-color: #ff8800; color: white'
                            elif val == 'Low':
                                return 'background-color: #44aa44; color: white'
                            return ''
                        styled_df = compromised_df.style.applymap(highlight_risk, subset=['RiskLevel'])
                        st.dataframe(styled_df)
                    else:
                        st.dataframe(compromised_df)
                else:
                    st.info("No suspicious events detected in the data.")
            
            with tab3:
                st.subheader("Files Accessed")
                if files_accessed:
                    files_df = pd.DataFrame(files_accessed)
                    # Format timestamp column
                    if 'Timestamp' in files_df.columns:
                        files_df['Timestamp'] = pd.to_datetime(files_df['Timestamp']).dt.strftime('%Y-%m-%d %H:%M:%S')
                    
                    # Add color coding for risk levels if available
                    if 'RiskLevel' in files_df.columns:
                        def highlight_risk(val):
                            if val == 'High':
                                return 'background-color: #ff4444; color: white'
                            elif val == 'Medium':
                                return 'background-color: #ff8800; color: white'
                            elif val == 'Low':
                                return 'background-color: #44aa44; color: white'
                            return ''
                        styled_df = files_df.style.applymap(highlight_risk, subset=['RiskLevel'])
                        st.dataframe(styled_df)
                    else:
                        st.dataframe(files_df)
                else:
                    st.info("No file access events found in the data.")
            
            with tab4:
                st.subheader("All Events")
                timeline_df = pd.DataFrame(timeline_filtered)
                # Format timestamp column and add new columns if they exist
                if 'Timestamp' in timeline_df.columns:
                    timeline_df['Timestamp'] = pd.to_datetime(timeline_df['Timestamp']).dt.strftime('%Y-%m-%d %H:%M:%S')
                
                # Show additional analysis columns if present
                if 'RiskLevel' in timeline_df.columns:
                    # Reorder columns to show risk level and anomaly types prominently
                    cols = list(timeline_df.columns)
                    priority_cols = ['Timestamp', 'RiskLevel', 'AnomalyTypes', 'Operation', 'ClientIP', 'Country', 'UserId']
                    new_order = []
                    for col in priority_cols:
                        if col in cols:
                            new_order.append(col)
                            cols.remove(col)
                    new_order.extend(cols)
                    timeline_df = timeline_df[new_order]
                    
                    # Add color coding for risk levels
                    def highlight_risk(val):
                        if val == 'High':
                            return 'background-color: #ff4444; color: white'
                        elif val == 'Medium':
                            return 'background-color: #ff8800; color: white'
                        elif val == 'Low':
                            return 'background-color: #44aa44; color: white'
                        return ''
                    
                    styled_df = timeline_df.style.applymap(highlight_risk, subset=['RiskLevel'])
                    st.dataframe(styled_df)
                else:
                    st.dataframe(timeline_df)
            
            # Option to download results
            st.subheader("Download Results")
            
            # Prepare data for download
            output = {
                "timeline": timeline,
                "compromised_events": compromised_events,
                "files_accessed": files_accessed,
                "anomalous_ips": anomalous_ips
            }
            
            # Convert to JSON for download
            json_data = json.dumps(output, default=str)
            st.download_button(
                label="Download Results as JSON",
                data=json_data,
                file_name="security_analysis_results.json",
                mime="application/json"
            )
    
    except Exception as e:
        st.error(f"An error occurred during processing: {str(e)}")
        import traceback
        st.error(traceback.format_exc())
else:
    # Display instructions when no file is uploaded
    st.info("Please upload a CSV or Excel file containing audit logs to begin analysis.")
    
    # Show example of expected data format
    st.subheader("Expected Data Format")
    st.markdown("""
    The uploaded file should contain audit log data with at least the following columns:
    - CreationDate: Timestamp of the event
    - Operation: Type of operation performed
    - UserId: User identifier
    - AuditData: JSON data containing details like ClientIP
    
    Other columns will be used if available but are not required.
    """)
    
    # Show sample of the analysis capabilities
    st.subheader("Analysis Capabilities")
    st.markdown("""
    This tool will:
    1. Identify anomalous IP addresses based on geolocation
    2. Detect potentially compromised events
    3. Track file access operations
    4. Visualize suspicious activities on an interactive map
    5. Provide detailed tables of all events for further investigation
    """)