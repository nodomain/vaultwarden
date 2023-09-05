import { test, expect } from '@playwright/test';
import dotenv from 'dotenv';
import dotenvExpand from 'dotenv-expand';

const { exec, execSync } = require('node:child_process');

var myEnv = dotenv.config({ path: '../oidc/keycloak/.env' })
dotenvExpand.expand(myEnv)

test.beforeAll('Setup', async ({ browser }) => {
  test.setTimeout(5 * 60 * 1000);

  exec('DOCKER_BUILDKIT=1 cd ../oidc/keycloak && docker-compose --profile VaultWarden up --force-recreate -V');

  var ready = false;
  var context;

  do {
    try {
      context = await browser.newContext();
      const page = await context.newPage();
      await page.waitForTimeout(5000);
      await page.goto('/');
      const result = await page.goto('http://127.0.0.1:8080/realms/test');
      ready = result.status() === 200;
    } catch(e) {
      if( !e.message.includes("NS_ERROR_CONNECTION_REFUSED") ){
        throw e;
      }
    } finally {
      await context.close();
    }
  } while(!ready);
});

test.afterAll('Teardown', async () => {
  test.setTimeout(60 * 1000);
  execSync('cd ../oidc/keycloak && docker-compose down');
});

test('SSO first login', async ({ page }) => {
  // Landing page
  await page.goto('/');
  await page.getByLabel(/Email address/).fill(process.env.TEST_USER_MAIL);
  await page.getByRole('button', { name: 'Continue' }).click();

  // Unlock page
  await page.getByRole('link', { name: /Enterprise single sign-on/ }).click();

  // Keycloak Login page
  await expect(page.getByRole('heading', { name: 'Sign in to your account' })).toBeVisible();
  await page.getByLabel(/Username/).fill(process.env.TEST_USER);
  await page.getByLabel('Password').fill(process.env.TEST_USER_PASSWORD);
  await page.waitForTimeout(1000); // Hack otherwise the click is not triggered when running headless
  await page.getByRole('button', { name: 'Sign In' }).click();

  // Back to Vault create account
  await expect(page).toHaveTitle(/Set master password/);
  await page.getByLabel('Master password', { exact: true }).fill('Master password');
  await page.getByLabel('Re-type master password').fill('Master password');
  await page.getByRole('button', { name: 'Submit' }).click();

  // We are now in the default vault page
  await expect(page).toHaveTitle(/Vaults/);
});

test('SSO second login', async ({ page }) => {
  // Landing page
  await page.goto('/');
  await page.getByLabel(/Email address/).fill(process.env.TEST_USER_MAIL);
  await page.getByRole('button', { name: 'Continue' }).click();

  // Unlock page
  await page.getByRole('link', { name: /Enterprise single sign-on/ }).click();

  // Keycloak Login page
  await expect(page.getByRole('heading', { name: 'Sign in to your account' })).toBeVisible();
  await page.getByLabel(/Username/).fill(process.env.TEST_USER);
  await page.getByLabel('Password').fill(process.env.TEST_USER_PASSWORD);
  await page.waitForTimeout(1000); // Hack otherwise the click is not triggered when running headless
  await page.getByRole('button', { name: 'Sign In' }).click();

  // Back to Vault unlock page
  await expect(page).toHaveTitle('Vaultwarden Web');
  await page.getByLabel('Master password').fill('Master password');
  await page.getByRole('button', { name: 'Unlock' }).click();

  // We are now in the default vault page
  await expect(page).toHaveTitle(/Vaults/);
});
