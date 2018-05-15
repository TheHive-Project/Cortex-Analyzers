#!/usr/bin/env bash
for analyzer in $(ls -1 analyzers); do
	echo "[*] Preparing ${analyzer}"
	if [ ! -d analyzers-docker/${analyzer} ]; then
		echo "    Directory does not exist, creating it."
		mkdir analyzers-docker/${analyzer}
	fi
	if [ ! -e analyzers-docker/${analyzer}/Dockerfile ]; then
	    echo "    Creating generic Dockerfile for analyzer."
	    echo "FROM cortex-base-python3" > analyzers-docker/${analyzer}/Dockerfile
	    echo "ADD ./analyzers/${analyzer} /analyzer" >> analyzers-docker/${analyzer}/Dockerfile
	    echo "WORKDIR /analyzer" >> analyzers-docker/${analyzer}/Dockerfile
	    echo "RUN pip3 install --no-cache-dir -r requirements.txt" >> analyzers-docker/${analyzer}/Dockerfile
	fi
	echo "[*] Checking analyzer flavours for ${analyzer}."
	for flavour in $(ls -1 analyzers/${analyzer}/*.json); do
	    flavour=$(echo ${flavour} | rev | cut -d'/' -f1 | rev)
	    if [ ! -e analyzers-docker/${analyzer}/${flavour} ]; then
            echo "[*] Preparing ${flavour}."
            command=$(cat analyzers/${analyzer}/${flavour} | jq '.command'|cut -d'/' -f2|cut -d'"' -f1)
            analyzerlower=$(echo ${analyzer} | tr "[:upper:]" "[:lower:]")
            cp analyzers/${analyzer}/${flavour} analyzers-docker/${analyzer}/${flavour}
            cat analyzers-docker/${analyzer}/${flavour} | jq '.command = "docker run -i cortex-analyzers-'${analyzerlower}' python '${command}'"' > analyzers-docker/${analyzer}/${flavour}.tmp
            rm analyzers-docker/${analyzer}/${flavour}
            mv analyzers-docker/${analyzer}/${flavour}.tmp analyzers-docker/${analyzer}/${flavour}
	    fi
	done
done
