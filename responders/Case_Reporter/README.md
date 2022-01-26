### README

#### Installation

Copy this folder to the path where you store your Cortex Responders (see your cortex configuration)

Install the prerequisites using python-pip:
```
python3 -m pip install -o /path/to/requirements.txt
```

Install wkhtmltopdf on your system. for debian like systems, use:
```
apt-get install wkhtmltopdf
```

#### Configuration

To customize your reports, a lot of parameters are available. Default values should please a majority of teams. 

You can sort every section of your report by changing the position value associated. put 0 to disable a section.

| Parameter | Description | Default value |
| --- | --- | --- |
| thehive_url | URL to the TheHive instance where the responder will be triggered. eg: https://myhive.com:9000 | NA |
| thehive_apikey | An API key that has permissions to read case and write on cases tasks | NA |
| export_format | Format of your reports. you can put either: "all", "pdf", "html" or "markdown" | pdf |
| temp_path | A folder where the generated reports will be temporary stored during the responder processing | /tmp/ |
| max_observables_tlp | A filter to define observables max tlp to include in the report. 1=white, 2=green, 3=amber, 4=red | 3 |
| section_information | Set at which position you want this section in the generated report. 0 = disable this section | 1 |
| section_description | Set at which position you want this section in the generated report. 0 = disable this section | 2 |
| section_customFields | Set at which position you want this section in the generated report. 0 = disable this section | 3 |
| section_summary | Set at which position you want this section in the generated report. 0 = disable this section | 4 |
| section_observables | Set at which position you want this section in the generated report. 0 = disable this section | 5 |
| section_ttps | Set at which position you want this section in the generated report. 0 = disable this section | 6 |
| section_tasks | Set at which position you want this section in the generated report. 0 = disable this section | 7 |
| section_tasklogs | Set at which position you want this section in the generated report. 0 = disable this section | 8 |
| branding_logo | Add your company logo to the reports. Base64 code of a png file. size near 80x80 or near is recommended | NA |

#### Usage

Trigger the responder on a TheHive Case. 
A dedicated task named "Case Report" will be created, and you report(s) will be added as task logs. 
Once the responder has uploaded the report(s), the task will be closed 