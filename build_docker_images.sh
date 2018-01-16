# Vars
VER=1.0.0

# Docker base images
echo "Building base images..."
docker build -t cortex-base-python2:$VER contrib/docker/cortex-base-python2
docker build -t cortex-base-python2:latest contrib/docker/cortex-base-python2
docker build -t cortex-base-python3:$VER contrib/docker/cortex-base-python3
docker build -t cortex-base-python3:latest contrib/docker/cortex-base-python3

echo "Building analyzer images..."
for analyzer in `ls -1 analyzers/`; do
  lower=`echo $analyzer | tr "[:upper:]" "[:lower:]"`
  echo "Building cortex-analyzers-$lower"
  OUTPUT="docker build -t cortex-analyzers-$lower analyzers/$analyzer"
  if [ $? != 0 ]; then
    /bin/echo -e "\e[91m$OUTPUT\e[0m"
    /bin/echo -e "\e[7mError while building image for $analyzer.\e[0m"
    exit 1
  fi
done

