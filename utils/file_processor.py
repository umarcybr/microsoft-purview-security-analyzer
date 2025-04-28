import pandas as pd
import os

def process_file(file_path):
    """
    Process the uploaded CSV or Excel file and return a pandas DataFrame.
    
    Args:
        file_path (str): Path to the uploaded file
        
    Returns:
        pandas.DataFrame: Processed data from the file
    """
    # Determine file type based on extension
    file_extension = os.path.splitext(file_path)[1].lower()
    
    # Process CSV file
    if file_extension == '.csv':
        try:
            # Try different encodings and delimiters
            try:
                df = pd.read_csv(file_path, encoding='utf-8')
            except UnicodeDecodeError:
                df = pd.read_csv(file_path, encoding='latin1')
            except pd.errors.ParserError:
                # Try with different delimiter
                df = pd.read_csv(file_path, encoding='utf-8', delimiter=';')
        except Exception as e:
            raise Exception(f"Failed to process CSV file: {str(e)}")
    
    # Process Excel file
    elif file_extension in ['.xlsx', '.xls']:
        try:
            df = pd.read_excel(file_path)
        except Exception as e:
            raise Exception(f"Failed to process Excel file: {str(e)}")
    
    else:
        raise ValueError(f"Unsupported file format: {file_extension}")
    
    # Basic data cleaning
    # Remove duplicate rows
    df = df.drop_duplicates()
    
    # Handle missing values
    df = df.fillna('')
    
    # Standardize column names (lowercase, replace spaces with underscores)
    df.columns = [col.lower().replace(' ', '_') for col in df.columns]
    
    # Identify IP address columns
    ip_columns = [col for col in df.columns if any(term in col for term in ['ip', 'address', 'source'])]
    
    # If no IP columns found, raise an error
    if not ip_columns:
        raise ValueError("No IP address columns found in the file. Please ensure your data contains IP information.")
    
    # Ensure at least one column contains valid IPs
    valid_ip_found = False
    for col in ip_columns:
        # Check if any value in the column matches basic IP format
        if df[col].astype(str).str.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$').any():
            valid_ip_found = True
            break
    
    if not valid_ip_found:
        raise ValueError("No valid IP addresses found in the expected columns.")
    
    return df
