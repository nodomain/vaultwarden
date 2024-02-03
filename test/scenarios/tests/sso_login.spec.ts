import { test, expect } from '@playwright/test';
const utils = require('../global-utils');

utils.loadEnv();

var proc;

test.beforeAll('Setup', async ({ browser }) => {
    proc = await utils.startVaultWarden(browser);
});

test.afterAll('Teardown', async () => {
    utils.stopVaultWarden(proc);
});

test('Account creation using SSO', async ({ page }) => {
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
    await page.getByRole('button', { name: 'Sign In' }).click();

    // Back to Vault create account
    await expect(page).toHaveTitle(/Set master password/);
    await page.getByLabel('Master password', { exact: true }).fill('Master password');
    await page.getByLabel('Re-type master password').fill('Master password');
    await page.getByRole('button', { name: 'Submit' }).click();

    // We are now in the default vault page
    await expect(page).toHaveTitle(/Vaults/);
});

test('SSO login', async ({ page }) => {
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
    await page.getByRole('button', { name: 'Sign In' }).click();

    // Back to Vault unlock page
    await expect(page).toHaveTitle('Vaultwarden Web');
    await page.getByLabel('Master password').fill('Master password');
    await page.getByRole('button', { name: 'Unlock' }).click();

    // We are now in the default vault page
    await expect(page).toHaveTitle(/Vaults/);
});

test('Non SSO login', async ({ page }) => {
    // Landing page
    await page.goto('/');
    await page.getByLabel(/Email address/).fill(process.env.TEST_USER_MAIL);
    await page.getByRole('button', { name: 'Continue' }).click();

    // Unlock page
    await page.getByLabel('Master password').fill('Master password');
    await page.getByRole('button', { name: 'Log in with master password' }).click();

    // We are now in the default vault page
    await expect(page).toHaveTitle(/Vaults/);
});


test('Non SSO login Failure', async ({ page }) => {
    proc = await utils.restartVaultWarden(proc, page.context().browser(), {
        SSO_ONLY: true
    });

    // Landing page
    await page.goto('/');
    await page.getByLabel(/Email address/).fill(process.env.TEST_USER_MAIL);
    await page.getByRole('button', { name: 'Continue' }).click();

    // Unlock page
    await page.getByLabel('Master password').fill('Master password');
    await page.getByRole('button', { name: 'Log in with master password' }).click();

    // An error should appear
    await page.getByLabel('SSO sign-in is required')
});

test('SSO login Failure', async ({ page }) => {
    proc = await utils.restartVaultWarden(proc, page.context().browser(), {
        SSO_ENABLED: false
    });

    // Landing page
    await page.goto('/');
    await page.getByLabel(/Email address/).fill(process.env.TEST_USER_MAIL);
    await page.getByRole('button', { name: 'Continue' }).click();

    // Unlock page
    await page.getByRole('link', { name: /Enterprise single sign-on/ }).click();

    // SSO identifier page
    await page.getByLabel('SSO identifier').fill('Random');
    await page.getByRole('button', { name: 'Log in' }).click();

    // An error should appear
    await page.getByLabel('SSO sign-in is not available')
});
