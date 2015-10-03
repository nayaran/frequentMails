import json
import flask
import httplib2
import pprint
import apiclient
import oauth2client
import oauth2client.client


from oauth2client.client import FlowExchangeError

app = flask.Flask(__name__)

CLIENT_SECRET_FILE = 'client_secrets.json'
SCOPES = ['https://www.googleapis.com/auth/userinfo.email',
          'https://www.googleapis.com/auth/userinfo.profile',
          'https://www.googleapis.com/auth/gmail.readonly']

GMAIL_API_NAME = 'gmail'
GMAIL_API_VERSION = 'v1'

def get_user_emails(credentials, query, userId):
  '''
  Returns the emails of the user filtered by the query
  '''

  # create http object to handle http request
  http = httplib2.Http()

  # add credentials to the authentication header
  http_auth = credentials.authorize(http)

  # build the gmail service object for calling the api
  gmail_service_object = build_service(GMAIL_API_NAME, GMAIL_API_VERSION, http_auth)

  # execute the api
  result = gmail_service_object.users().messages().list(userId=userId,
                                               q=query).execute()

  # return the emails returned
  return result

def build_service(service_name, version, http):
  '''
  A generic method to build the google client library's service object
  '''
  service = apiclient.discovery.build(service_name, version, http)

  return service



@app.route('/')
def index():
  '''
  The main method, binds together the whole application
  Authenticates and completes the OAuth2 setps if not already done and returns the emails
  '''

  # check if the credentials are already there in the session
  if 'credentials' not in flask.session:

    # if not found, redirect the user to authentication server
    return flask.redirect(flask.url_for('handle_callback'))

  # retrieve the credentials from the session
  credentials = oauth2client.client.OAuth2Credentials.from_json(flask.session['credentials'])

  # check if we need to again get the access taken
  if credentials.access_token_expired:
    # token expired, so redirect the user to authentication server
    return flask.redirect(flask.url_for('handle_callback'))

  else:

    # authorization complete
    # business logic

    message = ['Yo! OAuth2 authorization complete!!']

    return json.dumps(message)


@app.route('/handle_callback')
def handle_callback():
  '''
  Handles the redirection to authentication server if needed
  Handles the redirection back from the authentication server after user consent
  Performs the OAuth2 authorization steps
  '''

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


if __name__ == '__main__':
  '''
  The main method, starts the server
  '''
  import uuid
  app.secret_key = str(uuid.uuid4())
  app.debug = True
  app.run()
