# Hydra login-consent-provider for Atlassian Crowd

Implementation based on https://github.com/ory/hydra-login-consent-node
Utilizing: https://github.com/ghengeveld/atlassian-crowd-client

# Local testing
```
docker run -it --rm --name login-consent-hydra -p 4444:4444 -p 4445:4445 \
    -e OAUTH2_SHARE_ERROR_DEBUG=1 \
    -e LOG_LEVEL=debug \
    -e OAUTH2_CONSENT_URL=http://localhost:3000/consent \
    -e OAUTH2_LOGIN_URL=http://localhost:3000/login \
    -e OAUTH2_ISSUER_URL=http://hydra.machine:4444 \
    -e DATABASE_URL=memory \
    oryd/hydra:v1.0.0-rc.6_oryOS.10 serve all \
    --token-url http://hydra.machine:4444/oauth2/token \
    --auth-url http://hydra.machine:4444/oauth2/auth \
    --dangerous-force-http

docker run --link login-consent-hydra:hydra oryd/hydra:v1.0.0-rc.6_oryOS.10 clients create \
    --endpoint http://hydra.machine:4445 \
    --id test-client \
    --secret test-secret \
    --response-types code,id_token \
    --grant-types refresh_token,authorization_code \
    --scope openid,offline \
    --callbacks http://hydra.machine:4446/callback

docker run -p 4446:4446 --link login-consent-hydra:hydra oryd/hydra:v1.0.0-rc.6_oryOS.10 token user \
    --token-url http://hydra.machine:4444/oauth2/token \
    --auth-url http://hydra.machine:4444/oauth2/auth \
    --scope openid,offline \
    --client-id test-client \
    --client-secret test-secret \
    --redirect http://hydra.machine:4446
```
