### Email visualisation
Starting with version 2.0, this analyzer allows analysts to have an overview of the HTML rendered email. The program creates a screenshot of html parts of the message, inline and attachment parts.
By default, this option is **not** enabled. To proceed, the Analyzer requires the program `wkhtmltoimage` beeing installed on the system. 

#### Requirements
`wkhtmltopdf` program is required. DEB and RPM packages exist.
Once installed, in Cortex, configure the Analyzer accordingly : 

- set the parameter `email_visualisation` to true.
- If needed, replace the default value of the `wkhtmltoimage` program path in the parameter `wkhtmltoimage_path`.

