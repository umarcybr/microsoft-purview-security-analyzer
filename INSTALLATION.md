# Installation Guide - Microsoft Purview Security Analyzer

## Quick Start

### Option 1: Using pip (Recommended)

1. **Clone the repository**:
```bash
git clone https://github.com/yourusername/microsoft-purview-security-analyzer.git
cd microsoft-purview-security-analyzer
```

2. **Create a virtual environment** (optional but recommended):
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. **Install dependencies**:
```bash
pip install streamlit pandas folium streamlit-folium geoip2 openpyxl trafilatura
```

### Option 2: Using requirements file

If you create your own requirements.txt file with the following content:
```
streamlit>=1.28.0
pandas>=2.0.0
folium>=0.14.0
streamlit-folium>=0.15.0
geoip2>=4.7.0
openpyxl>=3.1.0
trafilatura>=1.6.0
```

Then install with:
```bash
pip install -r requirements.txt
```

## Required Data Files

### GeoLite2 Database Setup

**Important**: You must download the GeoLite2 database file manually:

1. Visit [MaxMind GeoLite2](https://dev.maxmind.com/geoip/geoip2/geolite2/)
2. Create a free account
3. Download the **GeoLite2-City.mmdb** file
4. Create the `attached_assets` directory in your project folder
5. Place the downloaded file at: `attached_assets/GeoLite2-City.mmdb`

**File structure should be**:
```
microsoft-purview-security-analyzer/
├── attached_assets/
│   └── GeoLite2-City.mmdb  # You must download this
├── app_new.py
├── security_analyzer.py
└── ...
```

## Running the Application

1. **Start the application**:
```bash
streamlit run app_new.py
```

2. **Access the web interface**:
   - Open your browser and go to `http://localhost:8501`
   - The application will automatically open in your default browser

## Troubleshooting

### Common Issues

**1. "ModuleNotFoundError" when running**
- Make sure all dependencies are installed: `pip install streamlit pandas folium streamlit-folium geoip2 openpyxl trafilatura`

**2. "FileNotFoundError: GeoLite2-City.mmdb"**
- Download the GeoLite2 database file as described above
- Ensure it's placed in the correct location: `attached_assets/GeoLite2-City.mmdb`

**3. "Port already in use"**
- If port 8501 is busy, Streamlit will automatically use the next available port
- Check the terminal output for the correct URL

**4. Application won't start**
- Ensure you're in the correct directory
- Check that Python 3.8+ is installed: `python --version`
- Try running with: `python -m streamlit run app_new.py`

### System Requirements

- **Python**: 3.8 or higher
- **Operating System**: Windows, macOS, or Linux
- **Memory**: At least 2GB RAM recommended
- **Storage**: 500MB for dependencies and database files

### Performance Tips

- For large files (>100MB), consider increasing system memory
- Close other browser tabs when processing large datasets
- Use SSD storage for better file processing performance

## Development Setup

If you plan to modify or contribute to the project:

1. **Fork the repository** on GitHub
2. **Clone your fork**:
```bash
git clone https://github.com/yourusername/microsoft-purview-security-analyzer.git
```
3. **Create a development branch**:
```bash
git checkout -b feature/your-feature-name
```
4. **Make your changes and test**
5. **Submit a pull request**

## Deployment Options

### Local Network Access
To allow access from other devices on your network:
```bash
streamlit run app_new.py --server.address 0.0.0.0
```

### Production Deployment
For production deployment, consider:
- [Streamlit Cloud](https://streamlit.io/cloud)
- [Heroku](https://heroku.com)
- [AWS](https://aws.amazon.com)
- [Docker containers](https://docker.com)

## Support

If you encounter issues:
1. Check this installation guide
2. Review the main [README.md](README.md)
3. Open an issue on the GitHub repository