FROM scion:latest

ENV HOME /home/scion
ENV GOPATH $HOME/go
ENV SC $GOPATH/src/github.com/scionproto/scion
ENV SCIONWEB $GOPATH/src/github.com/netsec-ethz/scion-web
ENV PYTHONPATH $SC/python:$SC
WORKDIR $SCIONWEB

COPY --chown=scion:scion . .

RUN pip3 install --user --require-hashes -r requirements.txt

RUN cp ./web_scion/settings/private.dist.py ./web_scion/settings/private.py

RUN ./manage.py migrate

# what is this for?
# RUN python3 scripts/reload_data.py

EXPOSE 8000

# WORKDIR /home/scion/scion.git
# WORKDIR $SC

USER scion
ENV PATH ~/.local/bin:$PATH

# ENTRYPOINT /bin/bash ./supervisor/supervisor.sh reload \
#     && /bin/bash ./supervisor/supervisor.sh start management_daemon \
#     && python3 web_scion/manage.py runserver 0.0.0.0:8000

ENTRYPOINT python3 ./manage.py runserver 0.0.0.0:8000
