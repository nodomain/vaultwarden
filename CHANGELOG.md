# Changelog

## 1.30.1-9

 - Add non jwt access_token support

## 1.30.1-8

 - Prevalidate endpoint change in Bitwarden WebVault [web-v2024.1.2](https://github.com/bitwarden/clients/tree/web-v2024.1.2/apps/web)
 - Add support for `experimental` front-end which stop sending the Master password hash to the server
 - Fix the [oidc_web_builds](https://github.com/Timshel/oidc_web_builds) version to `v2024.1.2-3` in docker images

## 1.30.1-7

 - Switch user invitation status to `Confirmed` on when user login not before (cf https://github.com/Timshel/vaultwarden/issues/17)
 - Return a 404 when user has no `public_key`, will prevent confirming the user in case previous fix is insufficient.

## 1.30.1-6

 - Ensure the token endpoint always return a `refresh_token` (cf https://github.com/Timshel/vaultwarden/issues/16)
