import re
from urllib.parse import urlparse
import html

def validate_url(url):
    """Validate if the provided URL is properly formatted."""
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except:
        return False

def sanitize_input(input_str):
    """Sanitize user input to prevent XSS and other injection attacks."""
    # HTML escape the input
    sanitized = html.escape(input_str)
    
    # Remove potentially dangerous characters
    sanitized = re.sub(r'[;<>&]', '', sanitized)
    
    # Ensure URL starts with http:// or https://
    if not sanitized.startswith(('http://', 'https://')):
        sanitized = 'http://' + sanitized
        
    return sanitized
