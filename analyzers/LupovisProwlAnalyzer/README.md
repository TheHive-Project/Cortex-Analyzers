# LupovisProwlAnalyzer

## Overview

The `LupovisProwlAnalyzer` is an analyzer for [TheHive](https://thehive-project.org) that integrates with the [Lupovis Prowl API](https://api.prowl.lupovis.io) to evaluate the reputation of IP addresses

## Features

- **IP Reputation Analysis**: Checks if an IP address is linked to malicious activities.
- **Detailed Reporting**: Generates both detailed and summary reports for analysis results.
- **Flexible Configuration**: Supports configuration of API keys and proxy settings.

## Requirements

- **Python Version**: 3.x
- **Dependencies**: Listed in `requirements.txt`

## Installation

1. **Clone the Repository**:

   ```bash
   git clone https://github.com/stacsirt/ProwlAPI---IP-reputation-check
   
   cd LupovisProwlAnalyzer


#Install the required Python packages using requirements.txt.

'pip install -r requirements.txt'

#API Key

API Key: Obtain an API key from Lupovis Prowl.

#Reporting
The analyzer generates two types of reports:

Long Report (long.html): Provides a detailed view of the analysis result.
Short Report (short.html): Shows a concise summary using taxonomies.

#License
This project is licensed under the AGPL-V3 License.

#Author
Name: Lyle Docherty
