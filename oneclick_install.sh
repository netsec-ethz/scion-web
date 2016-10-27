#!/bin/bash
set -e

# ssh -T git@github.com

sudo apt-get install git

git clone git@github.com:netsec-ethz/scion.git
cd scion
git submodule init ./sub/web/
git submodule update ./sub/web/
./deps.sh all
sudo cp ./docker/zoo.cfg /etc/zookeeper/conf/zoo.cfg
./scion.sh topology
cd ./sub/web/
git checkout master
pip3 install --user --require-hashes -r requirements.txt
cp web_scion/settings/private.dist.py web_scion/settings/private.py
python3 ./manage.py migrate
python3 ./manage.py test
python3 ./manage.py runserver
