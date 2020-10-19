"""
Collect Job Results from Cisco Orbital.

Description
-----------
    Send a request to Cisco Orbital for the JSON results of a specified
    job id.

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
import sys
import json
import requests
from requests.auth import HTTPBasicAuth

__version__ = "0.3"
__status__ = "Development"
__date__ = "October 19, 2020"

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
        read_job_cursor:    Read the current position to pull job data
        get_results:        Get results from an Orbital job

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
    job_cursor = ''

    @classmethod
    def read_auth_token(cls):
        """
        Read authentication token from disk location.

        Parameters
        ----------
            None.

        Returns
        -------
            None.

        """
        # Set logging references
        mthd = 'ORBITAL.READ_AUTH_TOKEN:'

        # Try to open token file
        LOG.debug('%s Attempting to read access token from disk.', mthd)

        # Attempt to read the access token from the file
        try:
            with open('.\\config\\orb_token', 'r') as token_file:
                cls.access_token = token_file.read()
                LOG.info('%s Retrieved %s...', mthd, cls.access_token[0:20])

        # Attempt to generate an access token if one is not found
        except FileNotFoundError:
            LOG.debug('%s Orbital token file not found', mthd)
            cls.gen_auth_token()

    @classmethod
    def gen_auth_token(cls):
        """
        Generate a new Orbital authentication token.

        Parameters
        ----------
            None.

        Returns
        -------
            None.

        """
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
        HttpResponse.status(response)

        # Parse auth token
        response_json = response.json()
        cls.access_token = 'Bearer ' + response_json['token']
        LOG.info('%s Recieved access token: %s...',
                 mthd,
                 cls.access_token[0:20])

        # Save auth token to disk
        LOG.debug('%s Writting access token to disk', mthd)
        with open('.\\config\\orb_token', 'w') as token_file:
            token_file.write(cls.access_token)

    @classmethod
    def check_auth(cls):
        """
        Check if authentication token is valid.

        Parameters
        ----------
            None.

        Returns
        -------
            None.

        """
        # Set logging references
        mthd = 'ORBITAL.CHECK_AUTH:'

        # Request token status
        LOG.debug('%s Checking authentication token', mthd)
        url = cls.url + 'ok'
        headers = {'Authorization': cls.access_token}
        response = cls.session.get(url, headers=headers)

        # Check server response
        # HttpResponse.status(response)

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
            LOG.error('%s Recieved error, requesting new token', mthd)
            cls.gen_auth_token()

    @classmethod
    def read_job_cursor(cls, job_id):
        """
        Read cursor location for the job from disk.

        Parameters
        ----------
            None.

        Returns
        -------
            None.

        """
        # Set logging references
        mthd = 'ORBITAL.READ_JOB_CURSOR:'

        # Try to open token file
        LOG.debug('%s Attempting to read last cursor location from disk', mthd)

        # Attempt to read the access token from the file
        try:
            with open(r'.\output\cursor\cursor_' + job_id + '.txt',
                      'r') as cursor_file:
                cls.job_cursor = cursor_file.read()
                LOG.info('%s Retrieved %s', mthd, cls.job_cursor)

        # Attempt to generate an access token if one is not found
        except FileNotFoundError:
            cls.job_cursor = 0
            LOG.debug('%s Orbital job cursor file not found, using %s',
                      mthd, cls.job_cursor)

    @classmethod
    def get_results(cls, job_id):
        """
        Get results for a provided job id.

        Parameters
        ----------
            none:

        Returns
        -------
            results json.

        """
        # Set logging references and varaibles
        mthd = 'ORBITAL.GET_RESULTS:'
        results_data = []
        cls.read_job_cursor(job_id)

        LOG.info('%s Begining to collect data for job id %s', mthd, job_id)

        job_cursor_init = cls.job_cursor

        # Start Getting results
        while True:
            url = "{0}jobs/{1}/results".format(cls.url, job_id)

            # Check if authentication token is still valid
            Orbital.check_auth()

            # Gather data from the results api
            LOG.debug('%s Checking for results from job id %s using cursor %s',
                      mthd, job_id, cls.job_cursor)
            headers = {'Authorization': cls.access_token,
                       'Content-Type': 'application/json'}
            payload = {'limit': cls.limit,
                       'cursor': cls.job_cursor}
            response = cls.session.get(url, headers=headers, params=payload)

            # Check server response
            HttpResponse.status(response)

            # Get the 'X-Orbital-Request-Id'
            req_id = response.headers['X-Orbital-Request-Id']
            received = response.headers['Date']
            LOG.debug('%s Received X-Orbital-Request-Id %s dated %s',
                      mthd, req_id, received)

            # Get
            response_json = response.json()

            # Locate results in the JSON file
            json_results = response_json['results']

            # Determine if last results
            len_new = len(results_data) + len(json_results)
            len_if_more = len(results_data) + int(cls.limit)

            # Check if there were any new results
            if len_if_more > len_new:
                # Append the results
                results_data += json_results

                # Determine last cursor location
                job_cursor_init = int(job_cursor_init)
                result_length = int(len(results_data))
                job_cursor_end = job_cursor_init + result_length

                # Write cursor location to disk
                with open(r'.\output\cursor\cursor_' + job_id + '.txt',
                          'w') as cursor_file:
                    cursor_file.write(str(job_cursor_end))

                LOG.info('%s Received API response for job id %s',
                         mthd, job_id)

                # Return the results
                return results_data

            # Append results and set the next cursor location
            results_data += json_results
            cls.job_cursor = int(response_json['next'])


class HttpResponse:
    """Test HTTP response to determine success/failure."""

    @staticmethod
    def status(response):
        """
        Check if a HTTP 200 response was received from the server, quit if not.

        Parameters
        ----------
        response : String
            HTTP response data.

        Returns
        -------
        None.

        """
        # Set logging references
        mthd = 'HTTPRESPONSE.STATUS:'

        # Create log message
        code = response.status_code
        reason = response.reason
        log_msg = "{0} Found HTTP {1} {2}".format(mthd, code, reason)

        # Check if success
        if response.status_code // 100 != 2:

            # Log error
            LOG.error(log_msg)
            sys.exit(log_msg)

        else:
            LOG.debug(log_msg)


def main():
    """
    Gather data for incident, ci, and user and print out the results.

    Returns
    -------
    None.

    """
    # Set logging references
    mthd = 'MAIN:'

    # Start logging events
    LOG.info('%s Script initiated', mthd)

    for key, job_id in Orbital.job_ids:

        # Get Orbital Authentication Token
        Orbital.read_auth_token()

        # Check Orbital results
        results = Orbital.get_results(job_id)

        # Check for new results
        if len(results) > 0:

            # Open previous results
            try:
                with open('.\\output\\job_data\\' + job_id + '.json', 'r') as pr_file:
                    prev_results = json.load(pr_file)
                    LOG.info('%s Opened the jobs previous results', mthd)

            except FileNotFoundError:
                prev_results = []
                LOG.debug('%s Previous results were not found', mthd)

            # Append new results to previous
            updated_results = prev_results + results

            # Write results to disk
            with open('.\\output\\job_data\\' + job_id + '.json', 'w') as out_file:
                json.dump(updated_results, out_file)

            LOG.debug('%s wrote last cursor position for %s as %s',
                      mthd, job_id, updated_results)

        else:
            LOG.info('%s No additional results were returned', mthd)

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
