The Advanced Web Scanner is a versatile Python-based web application that integrates tools like Sublist3r, Dirble, Nmap, and WhatWeb for a full-spectrum web domain scan. Designed for both security professionals and enthusiasts, it provides a user-friendly Flask-based interface for easy operation.

This tool's capabilities range from discovering subdomains with Sublist3r to conducting directory enumeration with Dirble, comprehensive network scanning using Nmap, and identifying website technologies with WhatWeb. Its modular design allows for easy extension and customization, catering to a variety of security assessment needs.

It's important to use the Advanced Web Scanner responsibly and legally. This tool is meant for ethical security testing and research, and users should ensure they have permission to scan target domains.

💿 Installation 💿
Installation with setup.sh and requirements.txt
Clone the repository
cd web-scanner
sudo ./setup.sh
pip install -r requirements.txt
⭐ Usage ⭐
To use the Advanced Web Scanner, follow these steps:

python3 app.py
This command starts the Flask server and runs the web application. Access the web interface through your web browser to begin scanning.

Features
Subdomain Discovery: Utilizes Sublist3r for extensive subdomain searching.
Directory Enumeration: Uses Dirble for rapid directory discovery.
Network Scanning: Integrates Nmap for detailed network analysis.
Website Identification: Employs WhatWeb for identifying technologies used by web servers.
Customization
You can customize the scanning commands and behaviors by editing the COMMANDS dictionary in the script. This allows you to tailor the tool to your specific needs.

Output Processing
The scanner output is processed to ensure readability and user-friendliness. ANSI escape codes and other unnecessary information are removed for clearer results.

Contributing
Your contributions to improve the Advanced Web Scanner are highly appreciated:

Fork the repository.
Create a new branch for your feature (git checkout -b feature-name).
Commit your changes (git commit -am 'Add a new feature').
Push to the branch (git push origin feature-name).
Create a new Pull Request.
Disclaimer
The Advanced Web Scanner is intended for educational and ethical use only. Ensure you have authorization before scanning any domains.

Copyright 2024
