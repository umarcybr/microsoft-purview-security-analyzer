# Overview

**Microsoft Purview Security Analyzer** - A comprehensive security audit log analysis tool built with Streamlit. This open-source application helps security professionals identify anomalous IP activities and potential security breaches in Microsoft Purview audit logs. The tool processes CSV and Excel files, performs geolocation analysis, and visualizes suspicious activities on an interactive dark-themed interface with world mapping capabilities.

## Project Status
- **Current Phase**: Production-ready for GitHub release
- **Name**: Microsoft Purview Security Analyzer  
- **Purpose**: Open-source tool for security community
- **UI Theme**: Dark mode for security analyst preference
- **Session Management**: Optimized to prevent map interaction reloading issues

# User Preferences

Preferred communication style: Simple, everyday language.

# System Architecture

## Frontend Architecture
The application uses Streamlit as the web framework, providing a simple and intuitive interface for security analysts. The UI is organized with a sidebar for file uploads and configuration, and a main content area for displaying analysis results, maps, and data tables. The architecture supports real-time processing and visualization of uploaded audit log files.

## Data Processing Pipeline
The core processing logic is distributed across multiple modules:
- **File Processing**: Handles CSV and Excel file parsing with robust error handling and encoding detection
- **Security Analysis**: Performs IP geolocation, anomaly detection, and event classification
- **Visualization**: Creates interactive maps using Folium and generates charts for data insights

## Geolocation Services
The system integrates with the GeoLite2 database for IP geolocation services. It includes fallback mechanisms for known private IPs and handles cases where geolocation data is unavailable. The architecture supports both online and offline geolocation analysis.

## Data Analysis Engine
The application implements several analysis algorithms:
- **Anomalous IP Detection**: Uses statistical methods to identify IPs with unusual access patterns
- **Compromised Event Identification**: Analyzes audit logs for suspicious activities and security breaches
- **File Access Monitoring**: Tracks and filters file access events for security analysis
- **Timeline Analysis**: Processes chronological event data for pattern recognition

## Session Management
The application uses Streamlit's session state to maintain processed data between user interactions, preventing unnecessary reprocessing of large datasets and improving performance.

# External Dependencies

## Geolocation Database
- **GeoLite2-City.mmdb**: MaxMind's GeoLite2 database for IP geolocation services
- Optional upload functionality allows users to provide their own GeoIP database

## Python Libraries
- **Streamlit**: Web application framework and UI components
- **Pandas**: Data manipulation and analysis for audit log processing
- **Folium**: Interactive map generation and geospatial visualization
- **Streamlit-Folium**: Integration layer between Streamlit and Folium maps
- **GeoIP2**: Python library for interfacing with MaxMind GeoIP databases
- **Plotly**: Additional charting and visualization capabilities (referenced in visualizer.py)

## File Format Support
- **CSV Files**: Standard comma-separated values with multiple encoding support
- **Excel Files**: .xlsx and .xls formats through pandas Excel engine

## Map Services
- **OpenStreetMap**: Default tile provider for map visualization
- **Folium Plugins**: MarkerCluster for performance optimization with large datasets