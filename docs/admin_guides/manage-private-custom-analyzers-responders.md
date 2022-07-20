# How to manage your private or custom Analyzers or Responders

This guide propose a way to manage your own analyzers without publishing them or installing all dependencies on the host running Cortex.


## Configure Cortex

Make Cortex know of custom Analyzers and Responders.

Update the `/etc/cortex/application.conf` or ensure your configuration is similar to: 

```yaml
[..]
analyzer {
  # Absolute path where you have pulled the Cortex-Analyzers repository.
  urls = [
        "https://download.thehive-project.org/analyzers.json"
        "/tmp/analyzers"
        ]

[..]
}
[..]
responder.urls = [
  "https://download.thehive-project.org/responders.json"
  "/opt/Cortex-Analyzers/responders"

]
[..]
```

## Write your code

See:

* [How to create an Analyzer guide](../dev_guides/how-to-create-an-analyzer.md)
* [Analyzer definition file](../dev_guides/analyzers_definition.md)

To prepare your package you have to write your `Dockerfile`. We recommend starting with [this one](https://github.com/TheHive-Project/Cortex-Analyzers/blob/master/utils/docker/Dockerfile_template) and update it, especially if additional programs on the system are required (the list could be added in a `programs.txt` file). 

As a result, your program should be at least:

```tree
Analyzer/
├── analyzer.json  #required
├── analyzer.py    #required
├── README.md            #optional
├── programs.txt         #optional
├── Dockerfile           #required
└── requirements.txt     #required
```


## Build your docker images

#### Configure the program

A program helps you to manage the build of your private analyzers/responders. You can find it [there](https://github.com/TheHive-Project/Cortex-Analyzers/blob/master/utils/docker/build-customimage.sh).

Download it, and edit the file to adjust few variables: 

```bash
#############################
#  VARIABLES TO CUSTOMISE   #
############################# 
## Set the path for custom analyzers (configured in Cortex)
analyzerspath="/opt/customneurons/analyzers"
## Set the path for custom responders (configured in Cortex)
responderspath="/opt/customneurons/responders"
# Set the path for docker images archives
dockerimagearchives="/opt/backup-images"
# Set a name for the docker image repository 
dockerimagerepositoryname="customimage"
```

4 variables should be set: 

* `analyzerspath`, the path for custom analyzers (it should be the same as in the Cortex configuration)
* `responderspath`, the path for custom responders (it should be the same as in the Cortex configuration)
* `dockerimagearchives`, the path for docker images archives. Indeed, once built, the program save the docker images in a dedicated folder
* `dockerimagerepositoryname`, a name for the docker image repository, used in docker image names or tags. `customimage` is used by default

One updated, save the file.

#### Run the program

Before running it, there are few requirements: 

* `jq` (from https://stedolan.github.io/jq/) should be installed in the system. For example, if using Ubuntu or Debian, run the following command: `apt install jq`
* _Python3 + json lib_ should be available on the system
* the Python library `json-spec` should be installed (`pip3 install json-spec`)

#### Build your image

The program has several options.

```
Build docker images for Custom analyzers and responders
  
   Syntax: build-customimage.sh [options]
   
   options:
   -h          Print this Help.
   -t type     Type: 'analyzer' or 'responder' 
   -b path     Path of analyzer or responder json file
```

To run it successfully, you need to identify the type of neuron to build, `analyzer` or `responder` and specify the path of the JSON file of the neuron

For example:

```
./build-customimage.sh -t analyzer -b /home/jerome/Devel/PrivateAnalyzer/analyzer.json
```

This will:

* check if a _Dockerfile` exist in the folder and create a default one if not
* Build the Docker image and name it `customimage-analyzer:latest`
* Save this image in _/opt/backup-images/customimage-analyzer.tar_
* Modify the _analyzer.json_ file accordingly and save it in _/opt/customneurons/analyzers/PrivateAnalyzer/analyzer.json_

## Refresh Cortex

Open Cortex web console, log in as `orgadmin`, and refresh Analyzers. 

![](../../images/cortex-refresh-analyzers.png)

Then your analyzer should appear and be ready to be configured and used as a Docker image.