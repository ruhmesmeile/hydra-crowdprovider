var express = require('express');
var router = express.Router();
var url = require('url');
var hydra = require('../services/hydra');
var CrowdClient = require('atlassian-crowd-client');

// Sets up csrf protection
var csrf = require('csurf');
var csrfProtection = csrf({ cookie: true });

// Load credentials
const crowdBaseUrl = process.env.CROWD_BASEURL;
const crowdApplication = process.env.CROWD_APPLICATION;
const crowdPassword = process.env.CROWD_PASSWORD;

// Set up Crowd client
var crowd = new CrowdClient({
  baseUrl: crowdBaseUrl,
  application: {
    name: crowdApplication,
    password: crowdPassword
  }
});

router.get('/', csrfProtection, function (req, res, next) {
  // Parses the URL query
  var query = url.parse(req.url, true).query;

  // The challenge is used to fetch information about the login request from ORY Hydra.
  var challenge = query.login_challenge;

  hydra.getLoginRequest(challenge)
  // This will be called if the HTTP request was successful
    .then(function (response) {
      // If hydra was already able to authenticate the user, skip will be true and we do not need to re-authenticate
      // the user.
      if (response.skip) {
        // You can apply logic here, for example update the number of times the user logged in.
        // ...

        // Now it's time to grant the login request. You could also deny the request if something went terribly wrong
        // (e.g. your arch-enemy logging in...)
        return hydra.acceptLoginRequest(challenge, {
          // All we need to do is to confirm that we indeed want to log in the user.
          subject: response.subject
        }).then(function (response) {
          // All we need to do now is to redirect the user back to hydra!
          res.redirect(response.redirect_to);
        });
      }

      if (req.cookies['crowd.token_key']) {
        return crowd.session.getUser(req.cookies['crowd.token_key']).then(function (user) {
          // Seems like the user authenticated! Let's tell hydra...
          return hydra.acceptLoginRequest(challenge, {
            // Subject is an alias for user ID. A subject can be a random string, a UUID, an email address, ....
            subject: user.username,

            // This tells hydra to remember the browser and automatically authenticate the user in future requests. This will
            // set the "skip" parameter in the other route to true on subsequent requests!
            remember: Boolean(req.body.remember),

            // When the session expires, in seconds. Set this to 0 so it will never expire.
            remember_for: 3600,

            // Sets which "level" (e.g. 2-factor authentication) of authentication the user has. The value is really arbitrary
            // and optional. In the context of OpenID Connect, a value of 0 indicates the lowest authorization level.
            // acr: '0',
          })
          .then(function (response) {
            // All we need to do now is to redirect the user back to hydra!
            res.redirect(response.redirect_to);
          })
          // This will handle any error that happens when making HTTP calls to hydra
          .catch(function (error) {
            next(error);
          });
        })
        .catch(function () {
          // If authentication can't be skipped we MUST show the login UI.
          res.render('login', {
            csrfToken: req.csrfToken(),
            challenge: challenge,
          });
        });
      } else {
        // If authentication can't be skipped we MUST show the login UI.
        res.render('login', {
          csrfToken: req.csrfToken(),
          challenge: challenge,
        });
      }
    })
    // This will handle any error that happens when making HTTP calls to hydra
    .catch(function (error) {
      next(error);
    });
});

router.post('/', csrfProtection, function (req, res, next) {
  // The challenge is now a hidden input field, so let's take it from the request body instead
  var challenge = req.body.challenge;

  // Authenticate to Crowd:
  return crowd.session.create(req.body.username, req.body.password).then(function (session) {
    // Fetch the user profile:
    return crowd.session.getUser(session.token).then(function (user) {
      // Seems like the user authenticated! Let's tell hydra...
      return hydra.acceptLoginRequest(challenge, {
        // Subject is an alias for user ID. A subject can be a random string, a UUID, an email address, ....
        subject: user.username,

        // This tells hydra to remember the browser and automatically authenticate the user in future requests. This will
        // set the "skip" parameter in the other route to true on subsequent requests!
        remember: Boolean(req.body.remember),

        // When the session expires, in seconds. Set this to 0 so it will never expire.
        remember_for: 3600,

        // Sets which "level" (e.g. 2-factor authentication) of authentication the user has. The value is really arbitrary
        // and optional. In the context of OpenID Connect, a value of 0 indicates the lowest authorization level.
        // acr: '0',
      })
      .then(function (response) {
        // TODO: use better / more logical 'maxAge'
        res.cookie('crowd.token_key', session.token, {
          maxAge: 240000,
          path: '/',
          secure: false,
          httpOnly: true,
          domain: process.env.CROWD_COOKIE_DOMAIN,
          encode: String
        });

        // All we need to do now is to redirect the user back to hydra!
        res.redirect(response.redirect_to);
      })
      // This will handle any error that happens when making HTTP calls to hydra
      .catch(function (error) {
        next(error);
      });
    });
  })
  .catch(function () {
    res.render('login', {
      csrfToken: req.csrfToken(),
      challenge: challenge,
      error: 'The username / password combination is not correct'
    });
    return;
  });
});

module.exports = router;
