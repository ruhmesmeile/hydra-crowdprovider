SHELL = /usr/bin/env bash

########################################
# Configuration
########################################

ARGS = $(filter-out $@,$(MAKECMDGOALS))
MAKEFLAGS += --silent
PROJECTKEY ?= ssoauth


########################################
# List Commands
########################################

list:
	sh -c "echo; $(MAKE) -p no_targets__ | awk -F':' '/^[a-zA-Z0-9][^\$$#\/\\t=]*:([^=]|$$)/ {split(\$$1,A,/ /);for(i in A)print A[i]}' | grep -v '__\$$' | grep -v 'Makefile'| sort"


########################################
# Docker machine states
########################################

up:
	docker-compose -p $(PROJECTKEY) up -d

build:
	docker-compose -p $(PROJECTKEY) up -d --build

start:
	docker-compose -p $(PROJECTKEY) start

stop:
	docker-compose -p $(PROJECTKEY) stop

state:
	docker-compose -p $(PROJECTKEY) ps

rebuild:
	docker-compose -p $(PROJECTKEY) stop
	docker-compose -p $(PROJECTKEY) rm -v --force
	docker-compose -p $(PROJECTKEY) pull
	docker-compose -p $(PROJECTKEY) build --pull --no-cache
	docker-compose -p $(PROJECTKEY) up -d --force-recreate

reset:
	docker-compose -p $(PROJECTKEY) stop
	docker-compose -p $(PROJECTKEY) rm -v --force app
	docker-compose -p $(PROJECTKEY) rm -v --force app mysql
	docker volume rm -f $(PROJECTKEY)_storage-mysql
	docker-compose -p $(PROJECTKEY) pull
	docker-compose -p $(PROJECTKEY) build --pull --no-cache
	docker-compose -p $(PROJECTKEY) up -d --force-recreate


########################################
# Create hydra client for Crowd
# see: https://www.ory.sh/docs/hydra/configure-deploy#deploy-ory-hydra
########################################

create-client:
	docker run \
    --link hydra:hydra \
    --network ssoauth_ssoauthnet \
    oryd/hydra:v1.0.0-rc.6_oryOS.10 \
      clients create \
        --endpoint https://hydraadmin.ruhmesmeile.machine \
        --id test-client \
        --secret test-secret \
        --response-types code,id_token \
        --grant-types refresh_token,authorization_code \
        --scope openid,offline \
        --token-endpoint-auth-method client_secret_post \
        --callbacks https://nextcloud.ruhmesmeile.machine/apps/sociallogin/custom_oidc/nextcloud \
				--fake-tls-termination y \
				--skip-tls-verify y

remove-client:
	docker run \
    --link hydra:hydra \
    --network ssoauth_ssoauthnet \
    oryd/hydra:v1.0.0-rc.6_oryOS.10 \
      clients delete test-client \
        --endpoint https://hydraadmin.ruhmesmeile.machine \
        --fake-tls-termination y \
        --skip-tls-verify y

hydrate-sql:
	docker run \
    --network ssoauth_ssoauthnet \
    oryd/hydra:v1.0.0-rc.6_oryOS.10 \
      migrate sql postgres://hydradb:betatester@postgresql/hydradb\?sslmode=disable


########################################
# General
########################################

bash: shell

bash-tech: shell-tech

bash-review: shell-review

shell:
	docker-compose -p $(PROJECTKEY) exec --user application app /bin/bash

root:
	docker-compose -p $(PROJECTKEY) exec --user root app /bin/bash

logs:
	docker-compose -p $(PROJECTKEY) logs -f $(ARGS)


########################################
# Argument fix workaround
########################################
%:
	@:
