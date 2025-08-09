# Microsoft Purview Security Analyzer

A web-based security analysis tool that leverages Streamlit to process CSV/Excel files and visualize anomalous IP activities with interactive mapping capabilities.

## Features

- **Interactive Geospatial Mapping**: Visualize suspicious IP activities on an interactive world map
- **File Processing**: Support for CSV and Excel files containing audit logs
- **Anomaly Detection**: Identify potentially compromised events and anomalous IP addresses
- **Data Visualization**: Interactive tables and charts for detailed analysis
- **Export Functionality**: Download analysis results in JSON format

## Installation

### Prerequisites

- Python 3.8 or higher
- pip package manager

### Setup

1. Clone this repository:
```bash
git clone https://github.com/yourusername/microsoft-purview-security-analyzer.git
cd microsoft-purview-security-analyzer
```

2. Install required packages:
```bash
pip install streamlit pandas folium streamlit-folium geoip2 openpyxl trafilatura
```

3. The GeoLite2 database is included in the repository for convenience

## Usage

1. Start the application:
```bash
streamlit run app_new.py
```

2. Open your web browser and navigate to `http://localhost:8501`

3. Upload your CSV or Excel file containing audit logs

4. Analyze the results in the interactive dashboard

## Expected Data Format

The uploaded file should contain audit log data with at least the following columns:
- **CreationDate**: Timestamp of the event
- **Operation**: Type of operation performed
- **UserId**: User identifier
- **AuditData**: JSON data containing details like ClientIP

Additional columns will be utilized if available.

## File Structure

```
microsoft-purview-security-analyzer/
├── app_new.py                 # Main Streamlit application
├── security_analyzer.py      # Core analysis functions
├── attached_assets/           # Data files and assets
│   └── GeoLite2-City.mmdb   # GeoIP database (included)
├── .streamlit/
│   └── config.toml           # Streamlit configuration
├── pyproject.toml            # Python dependencies
└── README.md                 # This file
```

## Analysis Capabilities

This tool provides:

1. **Anomalous IP Detection**: Identify IP addresses with unusual geographic patterns
2. **Compromised Event Detection**: Flag potentially suspicious activities
3. **File Access Tracking**: Monitor file operations and access patterns
4. **Interactive Mapping**: Visualize geographic distribution of security events
5. **Detailed Reporting**: Generate comprehensive analysis reports

## Technologies Used

- **Streamlit**: Web application framework
- **Folium**: Interactive mapping
- **Pandas**: Data manipulation and analysis
- **GeoIP2**: IP geolocation services
- **Trafilatura**: Web content extraction

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

### Third-Party Data
This product includes GeoLite2 data created by MaxMind, available from [https://www.maxmind.com](https://www.maxmind.com). The GeoLite2 database is licensed under the [Creative Commons Attribution-ShareAlike 4.0 International License](https://creativecommons.org/licenses/by-sa/4.0/).

## Disclaimer

This tool is for educational and legitimate security analysis purposes only. Users are responsible for ensuring compliance with all applicable laws and regulations when analyzing data.

## Support

For questions or issues, please open an issue on the GitHub repository.