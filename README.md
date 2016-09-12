## Installation

#### One click install

If you have trouble following the manual installation below, make sure your keys are set up for github.com and run oneclick_install.sh in the location where you want your installation.
Run `ssh -T git@github.com' if you are not sure about your keys.
Feedback about the script is welcome.

#### Manual installation

1. Go to to this repos top folder (which would be sub/web if you checked it out as a submodule of the main scion repo), install the dependencies
    If you got this as a submodule from the main repository at https://github.com/netsec-ethz/scion, make sure this is the version you want as the main repo could reference an old version of this.

    `pip3 install --user -r requirements.txt`

2. Copy the private settings file, update it if necessary

    `cp web_scion/settings/private.dist.py web_scion/settings/private.py`

2. Run migrations

    `./manage.py migrate`

    Optional: test the installation

    `./manage.py test`

3. Get the database ready
    Option 1: run `python3 ./scripts/reload_data.py users` if you want to start from a clean slate and not import an existing topology

    Option 2: Populate the database from the topology files
    `python3 ./scripts/reload_data.py` which reloads all the topologies in the main gen folder

4. Run the server

    `./manage.py runserver`


####OPTIONAL
##### Installing with Docker

1. Build the full SCION image (from the SCION root directory):

    `./docker.sh build`

2. Build and run the web image:

    `./web_scion/docker/run_docker.sh`

##### Using PostgreSQL

By default an SQLite database is used, and it works fine if the number of ASes is relatively small (lower than 100). One can switch to using PostgreSQL for improved performance and flexibility.

1. Install additional system dependencies

    `sudo apt-get install python3-psycopg2`

2. Update the DATABASES hash in `web_scion/settings/private.py` ('ENGINE' must be `django.db.backends.postgresql_psycopg2`)

3. Run the PostgreSQL docker image

    `./scripts/start_postgres_docker.sh`

## Usage

 Open the web panel after starting the test server: `http://localhost:8000/`

 Admin panel is located at `http://localhost:8000/admin` (login: admin, password: admin).

 Don't forget to run the management daemon if you want to manage server elements:

    ./supervisor/supervisor.sh start management_daemon


#### Feature overview

* Creating a topology from the web interface

* Connecting new ASes and connection requests

Adding new ASes to the network is implemented via the concept of connection requests. Assume you want to create a new AS and to connect it to AS 1. To do that, you open the 'Connection requests' tab of AS 1 and click the 'New request' button. Then you fill the form, providing some information about the prospective AS (purpose, location), including the router (or AS host) details: IP, port. There is an option to specify "external" IP and port if they differ from local values, for example, if the AS host is behind the NAT.

After the connection request is sent, it is listed in two places: on the 'Submitted request' page for the request sender, and on the 'Connection request' tab of AS 1 (the 'Received requests' section). The administrator of AS 1 can now review the submitted request on the latter web page. Then, he can approve or decline the request by clicking the corresponding button. If the request is approved, then the request sender can download the generated package from the 'Submitted request' page. After it, he just needs to upload the package to the AS host, extract it, and run the 'web_scion/scripts/deploy.sh' script, which will execute all essential deployment steps.

AS can also be marked as 'open' (see the `is_open` AS attribute), which means that every sent request is approved automatically.

* Ansible integration

* Two-factor authentication

Enable 2FA by adding this line to the `settings/private.py` file:

```
ENABLED_2FA = TWO_FACTOR_PATCH_ADMIN = True

```

Also update `TWILIO_*` and `TWO_FACTOR_SMS_GATEWAY` variables with proper values.

#### Common problems

If something doesn't work (no element status displayed, topology cannot be retrieved, etc.), do the following:

1. Check that the management daemon is running at the AD host (`./supervisor/supervisor.sh status`).
2. If the AD is deployed on a virtual or remote machine (not on localhost/127.0.0.1), ensure that the management daemon of that AD is listening on the 0.0.0.0 address, and not 127.0.0.1 (check the `[program:management_daemon]` section in `supervisor/supervisord.conf`).
3. Check that the md_host attribute of the AD points to the correct host where the management daemon is deployed. You can check it on the AD administration page (/admin/as_manager/ad/<AS_ID>/).
4. Check that the web panel can open the TLS connection to the port 9010 of the AD host.
5. Software updates don't work? Check that the corresponding RPC function (`self.send_update`) is registered in the `ManagementDaemon.__init__()` function. Thing to keep in mind: this is a highly experimental feature and should be used with care before additional security reviews are done, otherwise this can result in remote code execution vulnerabilities.

Don't forget to restart the management daemon(s) after any modifications are done to the source code.

If you have issues with missing tables, check that you have run all the migrations and have the latest models.
Run manage.py makemigrations
and manage.py migrate

#### Code structure

There are two directories (relative to the SCION sub/web directory) that contain all essential components of the testbed management system:

* `web_scion/` -- contains the web management application (Django web app). All the settings are located in `web_scion/web_scion/settings/`, useful scripts -- under `web_scion/scripts`
* the actual web module (views, models) -- under `web_scion/as_manager`.

#### Current limitations

1. ISD is a foreign key for the AS model, so currently an AS can only belong to a single ISD.
2. All ASs are using the same certificate for authentication (`ad_management/certs/ad.pem`).
