# Readme

Program that help checking and fixing the validity of the JSON file of a flavor.


```
usage: check_json_schema.py [-h] [-r] [-f FILE] [-s SCHEMA]

optional arguments:
  -h, --help            show this help message and exit
  -r, --report          Generate report for all JSON flavors of all Analyzers and responders
  -f FILE, --file FILE  Validate JSON of the Flavor definition file
  -s SCHEMA, --schema SCHEMA
                        JSON Schema of a flavor
```

## Examples


- Check all flavors found in analyzers and responders. From the Cortex-Analyzers folder:

```bash
python3 utils/flavors/check_json_schema.py -r

```

- Check a specific file:

```bash
python3 utils/flavors/check_json_schema.py -f analyzers/VirusTotal/VirusTotal_Scan.json -s utils/flavors/flavor_schema.json

❌ analyzers/VirusTotal/VirusTotal_Scan.json
deque([]): 'registration_required' is a required property
deque([]): 'subscription_required' is a required property
deque([]): 'free_subscription' is a required property
```

```bash
python3 utils/flavors/check_json_schema.py -f analyzers/SEKOIAIntelligenceCenter/IntelligenceCenter_Context.json -s utils/flavors/flavor_schema.json

✅ analyzers/SEKOIAIntelligenceCenter/IntelligenceCenter_Context.json
```

## Templates

If you want to start writing an Analyzer or a Responder, or a new flavor, you can start with the appropriate template: 
- `analyzer_flavor_template.json` for an new flavor of an analyser
- `responder_flavor_template.json` for a new flavor of a responder

## Running with virtualenv

### Create a Virtual Environment

To ensure a clean and isolated environment for running the script:

```bash
python3 -m venv env
```

### Activate the virtual environment

- On Linux/MacOS:
```
source env/bin/activate
```
- On Windows:
```
.\env\Scripts\activate
```

### Install Dependencies

Install the required package
```bash
pip install -r requirements.txt
```

### Run the script
Execute the script explicitly using the Python interpreter from the virtual environment:
```bash
env/bin/python3 utils/flavors/check_json_schema.py -r
```

When done running, deactivate the virtual environment when you're done by running:
```bash
deactivate
```