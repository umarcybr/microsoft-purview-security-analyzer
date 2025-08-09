"""Setup script for Microsoft Purview Security Analyzer."""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="microsoft-purview-security-analyzer",
    version="1.0.0",
    author="Security Analyzer Team",
    description="A web-based security analysis tool for Microsoft Purview audit logs",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/microsoft-purview-security-analyzer",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Environment :: Web Environment",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Security",
        "Topic :: Scientific/Engineering :: Information Analysis",
        "Topic :: Internet :: Log Analysis"
    ],
    python_requires=">=3.8",
    install_requires=[
        "streamlit>=1.28.0",
        "pandas>=2.0.0",
        "folium>=0.14.0",
        "streamlit-folium>=0.15.0",
        "geoip2>=4.7.0",
        "openpyxl>=3.1.0",
        "trafilatura>=1.6.0",
    ],
    extras_require={
        "dev": [
            "pytest>=6.0",
            "black>=22.0",
            "flake8>=4.0",
            "mypy>=0.950",
        ],
    },
    include_package_data=True,
    package_data={
        "": ["attached_assets/*.mmdb"],
    },
    entry_points={
        "console_scripts": [
            "purview-analyzer=app_new:main",
        ],
    },
    keywords="security audit analysis microsoft purview streamlit",
)