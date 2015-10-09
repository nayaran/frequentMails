import json
import flask
import httplib2
import pprint
import apiclient
import oauth2client
import oauth2client.client
import logging
import itertools

from collections import OrderedDict
from oauth2client.client import AccessTokenRefreshError
from oauth2client.client import TokenRevokeError

logging.basicConfig(level=logging.DEBUG,
                    format='%(levelname)-8s %(message)s',
                    )


from oauth2client.client import FlowExchangeError

app = flask.Flask(__name__)

CLIENT_SECRET_FILE = 'client_secrets.json'
SCOPES = ['https://www.googleapis.com/auth/userinfo.email',
          'https://www.googleapis.com/auth/userinfo.profile',
          'https://www.googleapis.com/auth/gmail.readonly']

GMAIL_API_NAME = 'gmail'
GMAIL_API_VERSION = 'v1'

USER_INFO_API_NAME = 'oauth2'
USER_INFO_API_VERSION = 'v2'
LIMIT = 7

def get_user_info(credentials):
  '''
  Send a request to the UserInfo API to retrieve the user's information.

  Args:
    credentials: oauth2client.client.OAuth2Credentials instance to authorize the
                 request.
  Returns:
    [user's name, user's email]
  '''
  # create http object to handle http request
  http = httplib2.Http()

  # add credentials to the authentication header
  http_auth = credentials.authorize(http)

  # build the google api service object for calling the api
  user_info_service = build_service(USER_INFO_API_NAME, USER_INFO_API_VERSION, http)
  user_info = None

  # execute the api
  try:
    user_info = user_info_service.userinfo().get().execute()
  except AccessTokenRefreshError:
    logging.debug('Access token refresh error, redirecting to auth server')
    return flask.redirect(flask.url_for('handle_callback'))

  logging.debug('returning from get_user_info')
  return [user_info.get('name'), user_info.get('email')]

def process_messages(service, userId, mailsList):

  # stores message meatdata
  headers = []

  # stores the final dictionary to be returned
  report = {}


  # fetching messages metadata from supplied message id lists
  logging.debug('fetching messages metadata from supplied message id lists')
  for mail in mailsList:

    try:
      message = service.users().messages().get(userId=userId, id=mail['id'], format='metadata').execute()
      # store the fetched metadata in headers
      headers.extend([message['payload']['headers']])

    except AccessTokenRefreshError:
      logging.debug('Access token refresh error, redirecting to auth server')
      return flask.redirect(flask.url_for('handle_callback'))

  # process the list of messages metadata to generate the report
  logging.debug('processing the list of messages metadata to generate the report')
  for mail in headers:
    # traverse the list of headers
    for item in mail:
      # traverse the items in each header

      if item['name'] in ['To', 'Cc', 'Bcc']:
        # if the item is 'to', process it

        # fetch the list of recipients
        recipients = item['value']

        # extract individual recipients, count the occurences
        # and store in a dictionary
        for name in recipients.split(','):
          try:
            report[name.strip()] += 1
          except KeyError:
            report[name.strip()] = 1

  # create a sorted dictionary, based on the count
  report = OrderedDict(sorted(report.items(), key=lambda value: value[1], reverse=True))

  # truncate the report to contain only LIMIT items
  report = OrderedDict(itertools.islice(report.items(), LIMIT))

  logging.debug('generated the report')

  return report



def get_user_emails(credentials, query, userId):
  '''
  Returns the emails of the user filtered by the query
  '''
  # the final report dictionary
  report = OrderedDict()

  # fetch user's information using get_user_info
  logging.debug('fetching user info-> name, email')
  user_info = get_user_info(credentials)

  # add user info to the report
  # if type(user_info) == 'list':
  report['name'] = user_info[0]
  report['email'] = user_info[1]

  # fetch emails report

  # create http object to handle http request
  http = httplib2.Http()

  # add credentials to the authentication header
  http_auth = credentials.authorize(http)

  # build the gmail service object for calling the api
  gmail_service_object = build_service(GMAIL_API_NAME, GMAIL_API_VERSION, http_auth)

  # execute the api
  try:
    result = gmail_service_object.users().messages().list(userId=userId,
                                               q=query).execute()
  except AccessTokenRefreshError:
    logging.debug('Access token refresh error, redirecting to auth server')
    return flask.redirect(flask.url_for('handle_callback'))
  logging.debug('fetched %d emails matching the query %s', result['resultSizeEstimate'], query)
  # process the emails to generate the report
  mails = result['messages']
  mail_report = process_messages(gmail_service_object, userId, mails)

  # update the report with the emails report
  report.update(mail_report)

  # return the report
  return report

def build_service(service_name, version, http):
  '''
  A generic method to build the google client library's service object
  '''
  service = apiclient.discovery.build(service_name, version, http)

  return service


@app.route('/', methods=['GET', 'POST'])
def index():
  '''
  The main method, binds together the whole application
  Authenticates and completes the OAuth2 setps if not already done and returns the emails
  '''

  # check if the credentials are already there in the session
  if 'credentials' not in flask.session:

    # if not found, redirect the user to authentication server
    flask.flash('You need to log in!')
    return flask.render_template('reports.html', entries='')

  # retrieve the credentials from the session
  credentials = oauth2client.client.OAuth2Credentials.from_json(flask.session['credentials'])

  # check if we need to again get the access taken
  if credentials.access_token_expired:
    # token expired, so redirect the user to authentication server
    logging.debug('Access token expired, redirecting to auth server')
    return flask.redirect(flask.url_for('handle_callback'))

  else:

    error = ''
    if flask.request.method == 'POST':

      # user has provided the input
      # extract details from user submitted form

      # business logic


      if flask.request.form['fromDate'] == "":
            error = 'Invalid Date'

      else:
            afterDate = flask.request.form['fromDate']
            logging.debug('afterDate - %s', afterDate)
            # construct the query
            query = 'in:sent after:2014/01/01 before:2014/01/30'

            # retrive the report
            report = get_user_emails(credentials, query, 'me')

            # jsonify and return the report
            # return flask.Response(json.dumps(report), mimetype='application/json')
            #report = json.dumps(report)
            return flask.render_template('reports.html', report=report)

    # authorization complete
    logging.debug('User authorization successful :)')

    # redirect to user input page

    flask.flash('You were logged in successfully!')
    return flask.render_template('user_input.html', error=error)



@app.route('/handle_callback')
def handle_callback():
  '''
  Handles the redirection to authentication server if needed
  Handles the redirection back from the authentication server after user consent
  Performs the OAuth2 authorization steps
  '''
  logging.debug('inside handl_callback')

  # create a client flow to assist in the authorization process
  flow = oauth2client.client.flow_from_clientsecrets(
      CLIENT_SECRET_FILE,
      scope = SCOPES,
      redirect_uri = flask.url_for('handle_callback', _external=True))

  # check if its the initial hit or if the user agreed to give permissions to the app
  if 'code' not in flask.request.args:
    # either the user disagreed or its the initial call

    # get the authorization server url
    auth_uri = flow.step1_get_authorize_url()

    # redirect the user to the authorization server
    return flask.redirect(auth_uri)

  else:
    # user agreed to give permission
    # complete the rest of the authorization steps

    # get the authorization code sent by the authorization server after users consent
    auth_code = flask.request.args.get('code')

    # exchange the auth code for the access token
    credentials = flow.step2_exchange(auth_code)

    # put the credentials in the session for future use
    flask.session['credentials'] = credentials.to_json()

    # redirect the user to the home page for executing the business logic
    return flask.redirect(flask.url_for('index'))


@app.route('/revoke')
def revoke():
  # retrieve the credentials from the session
  credentials = oauth2client.client.OAuth2Credentials.from_json(flask.session['credentials'])
  flask.flash('You were successfully logged out!')
  try:
    credentials.revoke(httplib2.Http())
    logging.debug('clearing the session after revoking the access')
    flask.session.clear()
    return flask.redirect(flask.url_for('index'))
  except TokenRevokeError:
    return flask.redirect(flask.url_for('index'))


if __name__ == '__main__':
  '''
  The main method, starts the server
  '''
  import uuid
  app.secret_key = str(uuid.uuid4())
  app.debug = False
  app.run(host='0.0.0.0')
