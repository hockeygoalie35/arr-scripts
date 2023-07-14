#!/usr/bin/with-contenv bash
SMA_PATH="/usr/local/sma"

echo "*** install packages ***" && \
apk add -U --upgrade --no-cache \
  tidyhtml \
  musl-locales \
  musl-locales-lang \
  flac \
  jq \
  git \
  gcc \
  ffmpeg \
  imagemagick \
  opus-tools \
  python3-dev \
  libc-dev \
  py3-pip \
  npm \
  yt-dlp && \
echo "*** install freyr client ***" && \
apk add --no-cache -X http://dl-cdn.alpinelinux.org/alpine/edge/testing atomicparsley && \
npm install -g miraclx/freyr-js &&\
echo "*** install beets ***" && \
apk add --no-cache -X http://dl-cdn.alpinelinux.org/alpine/edge/community beets && \
echo "*** install python packages ***" && \
pip install --upgrade --no-cache-dir \
  yq \
  pyacoustid \
  requests \
  pylast \
  mutagen \
  r128gain \
  tidal-dl \
  deemix && \
echo "************ setup SMA ************" && \
echo "************ setup directory ************" && \
mkdir -p ${SMA_PATH} && \
echo "************ download repo ************" && \
git clone https://github.com/mdhiggins/sickbeard_mp4_automator.git ${SMA_PATH} && \
mkdir -p ${SMA_PATH}/config && \
echo "************ create logging file ************" && \
mkdir -p ${SMA_PATH}/config && \
touch ${SMA_PATH}/config/sma.log && \
chgrp users ${SMA_PATH}/config/sma.log && \
chmod g+w ${SMA_PATH}/config/sma.log && \
echo "************ install pip dependencies ************" && \
python3 -m pip install --upgrade pip && \	
pip3 install -r ${SMA_PATH}/setup/requirements.txt

mkdir -p /custom-services.d
echo "Download QueueCleaner service..."
curl https://raw.githubusercontent.com/RandomNinjaAtk/arr-scripts/main/universal/services/QueueCleaner -o /custom-services.d/QueueCleaner
echo "Done"

echo "Download AutoConfig service..."
curl https://raw.githubusercontent.com/RandomNinjaAtk/arr-scripts/main/lidarr/AutoConfig.service.bash -o /custom-services.d/AutoConfig
echo "Done"

echo "Download Video service..."
curl https://raw.githubusercontent.com/RandomNinjaAtk/arr-scripts/main/lidarr/Video.service.bash -o /custom-services.d/Video
echo "Done"

echo "Download Audio service..."
curl https://raw.githubusercontent.com/RandomNinjaAtk/arr-scripts/main/lidarr/Audio.service.bash -o /custom-services.d/Audio
echo "Done"

echo "Download AutoArtistAdder service..."
curl https://raw.githubusercontent.com/RandomNinjaAtk/arr-scripts/main/lidarr/AutoArtistAdder.bash -o /custom-services.d/AutoArtistAdder
echo "Done"

mkdir -p /config/extended
echo "Download PlexNotify script..."
curl https://raw.githubusercontent.com/RandomNinjaAtk/arr-scripts/main/lidarr/PlexNotify.bash -o /config/extended/PlexNotify.bash 
echo "Done"

echo "Download MetadataPostProcess script..."
curl https://raw.githubusercontent.com/RandomNinjaAtk/arr-scripts/main/lidarr/MetadataPostProcess.bash -o /config/extended/MetadataPostProcess.bash
echo "Done"

echo "Download BeetsPostProcessor script..."
curl https://raw.githubusercontent.com/RandomNinjaAtk/arr-scripts/main/lidarr/BeetsPostProcessor.bash -o /config/extended/BeetsPostProcessor.bash
echo "Done"

echo "Download SMA config..."
curl https://raw.githubusercontent.com/RandomNinjaAtk/arr-scripts/main/lidarr/sma.ini -o /config/extended/sma.ini 
echo "Done"

echo "Download Beets config..."
curl "https://raw.githubusercontent.com/RandomNinjaAtk/arr-scripts/main/lidarr/beets-config.yaml" -o /config/extended/beets-config.yaml
echo "Done"

echo "Download Deemix config..."
curl "https://raw.githubusercontent.com/RandomNinjaAtk/arr-scripts/main/lidarr/deemix_config.json" -o /config/extended/deemix_config.json
echo "Done"

echo "Download Tidal config..."
curl "https://raw.githubusercontent.com/RandomNinjaAtk/arr-scripts/main/lidarr/tidal-dl.json" -o /config/extended/tidal-dl.json
echo "Done"

if [ ! -f /config/extended.conf ]; then
	echo "Download Extended config..."
	curl https://raw.githubusercontent.com/RandomNinjaAtk/arr-scripts/main/lidarr/extended.conf -o /config/extended.conf
	chmod 777 /config/extended.conf
	echo "Done"
fi

chmod 777 -R /config/extended

exit
