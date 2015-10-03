import json
import flask
import httplib2
import pprint
import apiclient
import oauth2client
import oauth2client.client


from oauth2client.client import FlowExchangeError


app = flask.Flask(__name__)


def get_user_emails(credentials, query):
  pass


def build_service(service_name, version, http):

  service = apiclient.discovery.build(service_name, version, http)

  return service


@app.route('/')
def index():
  if 'credentials' not in flask.session:
    return flask.redirect(flask.url_for('oauth2callback'))

  credentials = oauth2client.client.OAuth2Credentials.from_json(flask.session['credentials'])

  if credentials.access_token_expired:
    return flask.redirect(flask.url_for('oauth2callback'))
  else:
    message = ['Yo! OAuth2 authorization complete!!']
    return json.dumps(message)


@app.route('/oauth2callback')
def oauth2callback():
  flow =oauth2client.client.flow_from_clientsecrets(
      'client_secrets.json',
      scope=['https://www.googleapis.com/auth/userinfo.email',
              'https://www.googleapis.com/auth/userinfo.profile',
              'https://www.googleapis.com/auth/gmail.readonly'],

      redirect_uri = flask.url_for('oauth2callback', _external=True))

  if 'code' not in flask.request.args:
    auth_uri = flow.step1_get_authorize_url()
    return flask.redirect(auth_uri)

  else:
    auth_code = flask.request.args.get('code')
    credentials = flow.step2_exchange(auth_code)
    flask.session['credentials'] = credentials.to_json()
    return flask.redirect(flask.url_for('index'))


if __name__ == '__main__':
  import uuid
  app.secret_key = str(uuid.uuid4())
  app.debug = True
  app.run()
