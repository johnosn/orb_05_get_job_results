"""
Collect Job Results from Cisco Orbital.

Description
-----------
    Send a request to Cisco Orbital for the JSON results of a specified
    job id.

Version 0.5 Update
------------------
    Incremental data logging added

Version 0.4 Update
------------------
    Added new and accumulated results count to logging
    Error handling for when results are None

Version 0.3 Update
------------------
    Allow for collectioning non-full page results
    Change output location

Version 0.2 Update
------------------
    Allow for the script to process multiple jobs

Version 0.1 Initial
-------------------
    Authentication to Orbital
    Retrieve results from a defined Orbital job id
    Write results to a JSON output file
    Store cursor for use in next pull attempt

"""

import configparser
import logging
from logging.config import fileConfig
import json
from time import sleep
import requests
from requests.auth import HTTPBasicAuth


__version__ = "0.5"
__status__ = "Development"
__date__ = "February 17, 2021"


class Orbital:
    """
    Class for various Orbital API methods.

    Attributes
    ----------
        cfg_file:       Configuration file path
        url:            Orbital API base url
        client:         Orbital client id
        secret:         Orbital client secret
        limit:          Orbital API Results limit
        session:        Orbital API HTTPS session
        access_token:   Orbital OAuth2 token

    Methods
    -------
        read_auth_token:    Read the authorization token from the stored file
        gen_auth_token:     Request a new auth token from the Orbital API
        check_auth:         Validate that the auth token is still valid
        read_cursor:        Read the current cursor position from disk
        write_cursor:       Write the current cursor position from disk
        fetch_results:      Gathers results from the API
        write_results:      Writes results data to the output file
        get_results:        Manages harvesting all results

    """

    # Set the config file path
    cfg_file = r'.\config\api.cfg'

    # Read the config file
    config = configparser.ConfigParser()
    config.read(cfg_file)

    # Parse settings from config file and assign to class attributes
    url = config.get('ORB', 'api_base_url')
    client = config.get('ORB', 'api_client')
    secret = config.get("ORB", 'api_secret')
    limit = config.get('ORB', 'api_limit')
    job_ids = config.items("ORB_JOBS")

    # Create an Orbital session
    session = requests.session()
    access_token = ''
    cursor = ''

    @classmethod
    def read_auth_token(cls):
        """Read authentication token from disk location."""
        # Set logging references
        mthd = 'ORBITAL.READ_AUTH_TOKEN:'

        # Try to open token file
        LOG.debug('%s Attempting to read access token from disk.', mthd)

        # Attempt to read the access token from the file
        try:
            with open('.\\config\\orb_token', 'r') as token_file:
                cls.access_token = token_file.read()
                LOG.debug('%s Retrieved %s...', mthd, cls.access_token[0:20])

        # Attempt to generate an access token if one is not found
        except FileNotFoundError:
            LOG.debug('%s Orbital token file not found', mthd)
            cls.gen_auth_token()

    @classmethod
    def gen_auth_token(cls):
        """Generate a new Orbital authentication token."""
        # Set logging references
        mthd = 'ORBITAL.GEN_AUTH_TOKEN:'

        # Request Auth Token
        LOG.debug('%s Attempting to generate access token', mthd)
        url = cls.url + 'oauth2/token'
        payload = 'grant_type=client_credentials'
        headers = {'Content-Type': "application/x-www-form-urlencoded",
                   'Accept': "application/json"}
        response = cls.session.post(url,
                                    data=payload,
                                    headers=headers,
                                    auth=HTTPBasicAuth(cls.client,
                                                       cls.secret)
                                    )

        # Check server response
        try:
            response.raise_for_status()
        except requests.exceptions.HTTPError as err:
            LOG.error('%s Response Error: %s', mthd, err)

        # Parse auth token
        response_json = response.json()
        cls.access_token = 'Bearer ' + response_json['token']
        LOG.debug('%s Recieved access token: %s...',
                  mthd, cls.access_token[0:20])

        # Save auth token to disk
        LOG.debug('%s Writting access token to disk', mthd)
        with open('.\\config\\orb_token', 'w') as token_file:
            token_file.write(cls.access_token)

    @classmethod
    def check_auth(cls):
        """Check if authentication token is valid."""
        # Set logging references
        mthd = 'ORBITAL.CHECK_AUTH:'

        # Request token status
        LOG.debug('%s Checking authentication token', mthd)
        url = cls.url + 'ok'
        headers = {'Authorization': cls.access_token}
        response = cls.session.get(url, headers=headers)

        # Check server response
        try:
            response.raise_for_status()
        except requests.exceptions.HTTPError as err:
            LOG.error('%s Response Error: %s', mthd, err)

        # Parse response message
        response_json = response.json()

        # Get a new authentication token if not OK
        try:
            message = response_json['message']
            if message == 'OK':
                LOG.debug('%s Authentication token is OK', mthd)
            else:
                LOG.error('%s Recieved error %s, requesting new token',
                          mthd,
                          message)
                cls.gen_auth_token()
        except KeyError:
            LOG.debug('%s Recieved error, requesting new token', mthd)
            cls.gen_auth_token()

    @classmethod
    def read_cursor(cls, job_id):
        """Read cursor location for the job from disk."""
        # Set logging references
        mthd = 'ORBITAL.READ_CURSOR:'

        # Try to open token file
        LOG.debug('%s Attempting to read last cursor location from disk', mthd)

        # Attempt to read the access token from the file
        try:
            with open(r'.\output\cursor\cursor_' + job_id + '.txt',
                      'r') as cursor_file:
                cls.cursor = cursor_file.read()
                LOG.debug('%s Retrieved %s', mthd, cls.cursor)

        # Attempt to generate an access token if one is not found
        except FileNotFoundError:
            cls.cursor = 0
            LOG.debug('%s Orbital job cursor file not found, using %s',
                      mthd, cls.cursor)

    @classmethod
    def write_cursor(cls, job_id):
        """Update the location in the cursor file."""
        # Set logging references and varaibles
        mthd = 'ORBITAL.WRITE_CURSOR:'

        # Write cursor location to disk
        LOG.debug('%s write cursor position for %s as %s',
                  mthd, job_id, str(cls.cursor))
        with open(r'.\output\cursor\cursor_' + job_id + '.txt',
                  'w') as cursor_file:
            cursor_file.write(str(cls.cursor))
            cursor_file.close()

    @classmethod
    def fetch_results(cls, job_id):
        """Fetch results for a provided job id from the API."""
        # Set logging references and varaibles
        mthd = 'ORBITAL.FETCH_RESULTS:'

        url = "{0}jobs/{1}/results".format(cls.url, job_id)

        # Check if authentication token is still valid
        LOG.debug('%s Check OAuth token', mthd)
        Orbital.check_auth()

        # Gather data from the results api
        LOG.debug('%s Checking for results from job id %s using cursor %s',
                  mthd, job_id, cls.cursor)
        headers = {'Authorization': cls.access_token,
                   'Content-Type': 'application/json'}
        payload = {'limit': cls.limit,
                   'cursor': cls.cursor}
        response = cls.session.get(url, headers=headers, params=payload)

        # Check server response
        try:
            response.raise_for_status()
        except requests.exceptions.HTTPError as err:
            LOG.error('%s Response Error: %s', mthd, err)

        # Get the 'X-Orbital-Request-Id'
        LOG.debug('%s Received X-Orbital-Request-Id %s dated %s',
                  mthd, response.headers['X-Orbital-Request-Id'],
                  response.headers['Date'])

        return response

    @classmethod
    def write_results(cls, job_id, results):
        """Write results to the output file."""
        # Set logging references and varaibles
        mthd = 'ORBITAL.WRITE_RESULTS:'

        # Check for new results
        LOG.debug('%s check size of results for job id %s', mthd, job_id)
        if not (results is None) and len(results) > 0:

            # Open previous results
            LOG.debug('%s check previous results for job id %s', mthd, job_id)
            out_path = '.\\output\\job_data\\' + job_id + '.json'
            try:
                with open(out_path, 'r') as pr_file:
                    prev_results = json.load(pr_file)
                    LOG.debug('%s Opened the jobs previous results', mthd)
                    pr_file.close()

            except FileNotFoundError:
                prev_results = []
                LOG.debug('%s Previous results were not found', mthd)

            # Append new results to previous
            updated_results = prev_results + results

            # Write results to disk
            LOG.debug('%s write results for job id %s', mthd, job_id)
            attempts = 4
            for i in range(attempts):
                try:
                    with open(out_path, 'w') as out_file:
                        json.dump(updated_results, out_file)
                        out_file.close()
                except PermissionError as err:
                    LOG.error('%s PermissionError for job id %s on attempt %s',
                              mthd, job_id, str(i))
                    LOG.error('%s %s', mthd, err)
                    sleep(20)
                    if i < attempts - 1:
                        continue
                else:
                    break
            else:
                LOG.error('%s Exceeded max write errors for job id %s',
                          mthd, job_id)

        else:
            LOG.debug('%s No additional results were returned', mthd)

    @classmethod
    def get_results(cls, job_id):
        """Get results for a provided job id."""
        # Set logging references and varaibles
        mthd = 'ORBITAL.GET_RESULTS:'
        cls.read_cursor(job_id)
        cls.read_auth_token()

        LOG.debug('%s Begining to collect data for job id %s', mthd, job_id)

        next_value = int(cls.cursor)
        LOG.debug('%s Begining at cursor location %s', mthd, str(next_value))

        # Start Getting results
        while True:
            # Get results data
            LOG.debug('%s call fetch_results for job id %s', mthd, job_id)
            response = cls.fetch_results(job_id)
            r_json = response.json()

            # Locate results in the JSON file
            results = r_json['results']

            prev_value = next_value
            try:
                next_value = int(r_json['next'])
            except KeyError:
                next_value = prev_value + (int(cls.limit)/2)
            diff = (next_value - prev_value)

            # CHECK IF LAST ITTERATION
            if diff == int(cls.limit):
                LOG.debug('%s updating results for job id %s', mthd, job_id)
                # Append results and set the next cursor location
                LOG.debug('%s call write_results for job id %s', mthd, job_id)
                cls.write_results(job_id, results)
                cls.cursor = int(r_json['next'])
                LOG.debug('%s call write_cursor for job id %s', mthd, job_id)
                cls.write_cursor(job_id)

            # Check if there were any new results
            else:
                LOG.debug('%s last results for job id %s', mthd, job_id)
                # Append the results
                LOG.debug('%s call write_results for job id %s', mthd, job_id)
                cls.write_results(job_id, results)
                cls.cursor = int(r_json['next'])
                LOG.debug('%s call write_cursor for job id %s', mthd, job_id)
                cls.write_cursor(job_id)
                break


def main():
    """Gather data for incident, ci, and user and print out the results."""
    # Set logging references
    mthd = 'MAIN:'

    # Start logging events
    LOG.info('%s Script initiated', mthd)

    for value in Orbital.job_ids:
        # Check Orbital results
        Orbital.get_results(value[1])

    # End logging events
    LOG.info('%s Script ended', mthd)


# startup the script and initialize main
if __name__ == "__main__":

    # Setup Logging
    fileConfig(r'.\config\logging.cfg',
               defaults={'logfilename': r'.\output\logs\script.log'})
    LOG = logging.getLogger('script_logger')
    LOG.setLevel(logging.INFO)  # set to logging.DEBUG for more detailed logs

    # Execute main function
    main()
