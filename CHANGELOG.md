# Changelog

## 1.30.2-2

 - Fix non jwt `acess_token` check when there is no `refresh_token`
 - Add `SSO_AUTH_ONLY_NOT_SESSION` to use SSO only for auth not the session lifecycle.

## 1.30.2-1

 - Update [oidc_web_builds](https://github.com/Timshel/oidc_web_builds) version to `v2024.1.2-4` which move the org invite patch to the `button` release (which is expected to be merged in VW).
 - Remove the `sso_acceptall_invites` setting
 - Allow to override log level for specific target

## 1.30.1-11

 - Encode redirect url parameters and add `debug` logging.

## 1.30.1-10

 - Keep old prevalidate endpoint for Mobile apps

## 1.30.1-9

 - Add non jwt access_token support

## 1.30.1-8

 - Prevalidate endpoint change in Bitwarden WebVault [web-v2024.1.2](https://github.com/bitwarden/clients/tree/web-v2024.1.2/apps/web)
 - Add support for `experimental` front-end which stop sending the Master password hash to the server
 - Fix the in docker images

## 1.30.1-7

 - Switch user invitation status to `Confirmed` on when user login not before (cf https://github.com/Timshel/vaultwarden/issues/17)
 - Return a 404 when user has no `public_key`, will prevent confirming the user in case previous fix is insufficient.

## 1.30.1-6

 - Ensure the token endpoint always return a `refresh_token` (cf https://github.com/Timshel/vaultwarden/issues/16)
