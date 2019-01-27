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

  // The challenge is used to fetch information about the consent request from ORY Hydra.
  var challenge = query.consent_challenge;

  hydra.getConsentRequest(challenge)
  // This will be called if the HTTP request was successful
    .then(function (response) {
      if (req.cookies['crowd.token_key']) {
        return crowd.session.getUser(req.cookies['crowd.token_key']).then(function (user) {
          // Now it's time to grant the consent request. You could also deny the request if something went terribly wrong
          return hydra.acceptConsentRequest(challenge, {
            // We can grant all scopes that have been requested - hydra already checked for us that no additional scopes
            // are requested accidentally.
            grant_scope: response.requested_scope,

            // ORY Hydra checks if requested audiences are allowed by the client, so we can simply echo this.
            grant_access_token_audience: response.requested_access_token_audience,

            // The session allows us to set session data for id and access tokens
            session: {
              // This data will be available when introspecting the token. Try to avoid sensitive information here,
              // unless you limit who can introspect tokens.
              // access_token: { foo: 'bar' },

              // This data will be available in the ID token.
              id_token: {
                "sub": user.username,
                "name": user.displayname,
                "email": user.email,
                "given_name": user.firstname,
                "family_name": user.lastname,
                "preferred_username": user.username,
                "email_verified": true,
                "zoneinfo": "Europe/Berlin",
                "locale": "de-DE"
              }
            }
          }).then(function (response) {
            res.cookie('crowd.token_key', req.cookies['crowd.token_key'], {
              maxAge: 240000,
              path: '/',
              secure: false,
              httpOnly: true,
              domain: process.env.CROWD_COOKIE_DOMAIN,
              encode: String
            });

            // All we need to do now is to redirect the user back to hydra!
            res.redirect(response.redirect_to);
          });
        });
      } else if (response.skip) {
        // If a user has granted this application the requested scope, hydra will tell us to not show the UI.
        // You can apply logic here, for example grant another scope, or do whatever...
        // ...

        // Now it's time to grant the consent request. You could also deny the request if something went terribly wrong
        return hydra.acceptConsentRequest(challenge, {
          // We can grant all scopes that have been requested - hydra already checked for us that no additional scopes
          // are requested accidentally.
          grant_scope: response.requested_scope,

          // ORY Hydra checks if requested audiences are allowed by the client, so we can simply echo this.
          grant_access_token_audience: response.requested_access_token_audience,

          // The session allows us to set session data for id and access tokens
          session: {
            // This data will be available when introspecting the token. Try to avoid sensitive information here,
            // unless you limit who can introspect tokens.
            // access_token: { foo: 'bar' },

            // This data will be available in the ID token.
            // id_token: { baz: 'bar' },
          }
        }).then(function (response) {
          // All we need to do now is to redirect the user back to hydra!
          res.redirect(response.redirect_to);
        });
      } else {
        // If consent can't be skipped we MUST show the consent UI.
        res.render('consent', {
          csrfToken: req.csrfToken(),
          challenge: challenge,
          // We have a bunch of data available from the response, check out the API docs to find what these values mean
          // and what additional data you have available.
          requested_scope: response.requested_scope,
          user: response.subject,
          client: response.client,
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

  // Let's see if the user decided to accept or reject the consent request..
  if (req.body.submit === 'Deny access') {
    // Looks like the consent request was denied by the user
    return hydra.rejectConsentRequest(challenge, {
      error: 'access_denied',
      error_description: 'The resource owner denied the request'
    })
      .then(function (response) {
        // All we need to do now is to redirect the browser back to hydra!
        res.redirect(response.redirect_to);
      })
      // This will handle any error that happens when making HTTP calls to hydra
      .catch(function (error) {
        next(error);
      });
  }

  var grant_scope = req.body.grant_scope
  if (!Array.isArray(grant_scope)) {
    grant_scope = [grant_scope]
  }

  // Seems like the user authenticated! Let's tell hydra...
  hydra.getConsentRequest(challenge)
  // This will be called if the HTTP request was successful
    .then(function (response) {
      if (req.cookies['crowd.token_key']) {
        return crowd.session.getUser(req.cookies['crowd.token_key']).then(function (user) {
          return hydra.acceptConsentRequest(challenge, {
            // We can grant all scopes that have been requested - hydra already checked for us that no additional scopes
            // are requested accidentally.
            grant_scope: grant_scope,

            // The session allows us to set session data for id and access tokens
            session: {
              // This data will be available when introspecting the token. Try to avoid sensitive information here,
              // unless you limit who can introspect tokens.
              // access_token: { foo: 'bar' },

              // This data will be available in the ID token.
              id_token: {
                "sub": user.username,
                "name": user.displayname,
                "email": user.email,
                "given_name": user.firstname,
                "family_name": user.lastname,
                "preferred_username": user.username,
                "email_verified": true,
                "zoneinfo": "Europe/Berlin",
                "locale": "de-DE"
              }
            },

            // ORY Hydra checks if requested audiences are allowed by the client, so we can simply echo this.
            grant_access_token_audience: response.requested_access_token_audience,

            // This tells hydra to remember this consent request and allow the same client to request the same
            // scopes from the same user, without showing the UI, in the future.
            remember: Boolean(req.body.remember),

            // When this "remember" sesion expires, in seconds. Set this to 0 so it will never expire.
            remember_for: 3600,
          })
          .then(function (response) {
            // All we need to do now is to redirect the user back to hydra!
            res.redirect(response.redirect_to);
          })
        });
      } else {
        // TODO: this error handling sucks, we simply never resolve the request (browser hangs for user on crowdprovider.ruhmesmeile.machine)
        return;
      }
    })
    // This will handle any error that happens when making HTTP calls to hydra
    .catch(function (error) {
      next(error);
    });
});

module.exports = router;
