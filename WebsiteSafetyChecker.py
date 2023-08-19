import requests
from bs4 import BeautifulSoup
import sslyze
from sslyze import ServerNetworkLocationViaDirectConnection
from sslyze.plugins import CertificateInfoPlugin, TrustStoresPlugin, CertificatesValidationPlugin

# Function to check SSL certificate validity
def check_ssl_certificate(url):
    try:
        # Use sslyze to check the SSL certificate
        server_location = ServerNetworkLocationViaDirectConnection.with_ip_address_lookup(url)
        scanner = sslyze.Scanner(network_location=server_location)
        scanner.queue_plugin(CertificateInfoPlugin())
        scanner.queue_plugin(TrustStoresPlugin())
        scanner.queue_plugin(CertificatesValidationPlugin())

        # Run the scanner
        scanner_result = scanner.run()
        
        # Check certificate validity
        for plugin_result in scanner_result.as_text():
            if "Certificate has expired" in plugin_result:
                return False
            if "Certificate is trusted" in plugin_result:
                return True
        
        return True  # If no issues found
    except Exception as e:
        print(f"Error checking SSL certificate: {str(e)}")
        return False

# Function to check domain reputation
def check_domain_reputation(url):
    try:
        # You can use third-party services or APIs to check domain reputation here.
        # For simplicity, we're not implementing this in this example.
        # You might use services like Google Safe Browsing or others for a more in-depth check.
        return True  # Placeholder for reputation check
    except Exception as e:
        print(f"Error checking domain reputation: {str(e)}")
        return False

# Main function to check website safety
def check_website_safety(url):
    try:
        # Check SSL certificate
        ssl_safe = check_ssl_certificate(url)
        
        # Check domain reputation
        reputation_safe = check_domain_reputation(url)
        
        if ssl_safe and reputation_safe:
            return "The website is safe."
        else:
            return "The website may not be safe."
    except Exception as e:
        print(f"Error checking website safety: {str(e)}")
        return "Error checking website safety."

if __name__ == "__main__":
    website_url = input("Enter the website URL: ")
    result = check_website_safety(website_url)
    print(result)
