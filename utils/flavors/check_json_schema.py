#!/usr/bin/env python3

"""
Program that:
- checks JSON schema of flavors of Analyers and Responders
- Fixes JSON file with missing data

This program can be run on the whole repository or on a specific JSON file
"""

import json
from jsonschema import Draft7Validator, FormatChecker
import sys
import os
import argparse

def printJson(fjson:dict) -> str:
    print(json.dumps(fjson, indent=4))


def printSuccess(success:bool, filepath:str) -> str:
    if success:
        print("{} {}".format("\u2705",filepath))
    else:
        print("{} {}".format("\u274c",filepath))

def openJsonFile(filename:str) -> dict: 
    try:
        with open(filename, "r") as fjson:
            j = json.load(fjson)
        fjson.close()
        return j
    except OSError:
        print("Could not open/read file:", fjson)
        sys.exit()

def fixJsonFlavorFile(jsonfile:dict) -> dict:
    service_logo = { 
        "path": "",
        "caption": "logo"
    }

    screenshots = [
        {
            "path": "",
            "caption": ""
        }
    ]
    for I in [ 
            "registration_required",
            "subscription_required",
            "free_subscription",
            "service_homepage",
        ]:
        if I in jsonfile:
            break
        jsonfile[I] = "N/A"
    if "service_logo" not in jsonfile: 
        jsonfile["service_logo"] =  service_logo
    if "screenshots" not in jsonfile: 
        jsonfile["screenshots"] =  screenshots
    return jsonfile

def validateFlavorFormat(flavorfile: str, schemafile: str, fix: bool) -> str:
    flavorSchema = openJsonFile(schemafile)
    fjson = openJsonFile(flavorfile)
    formatchecker = FormatChecker()
    validator = Draft7Validator(flavorSchema, format_checker=formatchecker)
    errors = sorted(validator.iter_errors(fjson), key=lambda e: e.path)
    if not errors:
        printSuccess(True, flavorfile)
    else:
        printSuccess(False, flavorfile)
        for error in errors:
            print("{}: {}".format(error.path, error.message))
        if fix:
            print("Fixing {}".format(flavorfile))
            j = fixJsonFlavorFile(fjson)
            with open(flavorfile, 'w+') as fj:
                fj.write(json.dumps(j, indent=4))
            fj.close()


def run():
    parser = argparse.ArgumentParser()
    parser.add_argument("-r", "--report", help="Generate report for all JSON flavors of all Analyzers and responders", action="store_true", default=False)
    parser.add_argument("-x", "--fix", help="Adding new information required for documentation", action="store_true", default=False)
    parser.add_argument("-f", "--file", help="Validate JSON of the Flavor definition file")
    parser.add_argument("-s", "--schema", help="JSON Schema of a flavor", default="utils/flavors/flavor_schema.json")

    args = parser.parse_args()
    try:
        if os.path.isfile(args.schema) and args.schema.endswith(".json"):
            if args.report:
                path = ["analyzers", "responders"]
                for p in path:
                    for neuron in os.listdir(p):
                        # print(os.path.join(p,neuron))
                        for file in os.listdir(os.path.join(p,neuron)):
                            if file.endswith(".json"):
                                filepath = os.path.join(p,neuron,file)
                                validateFlavorFormat(filepath, args.schema, args.fix)

        
            if args.file:
                filepath = args.file
                try:
                    if os.path.isfile(filepath) and filepath.endswith(".json"):
                        validateFlavorFormat(filepath, args.schema, args.fix)
                    else:
                        print("Error: Check this is a file, json formatted, and it has .json extention\n {}".format(filepath))
                except Exception as e:
                    print(e)


    except Exception as e: 
        print(e)

if __name__ == '__main__':
    run()