import { type FullConfig } from '@playwright/test';
import dotenv from 'dotenv';
import dotenvExpand from 'dotenv-expand';
const { exec } = require('node:child_process');

var myEnv = dotenv.config({ path: 'test.env' });
dotenvExpand.expand(myEnv);
var kcPath = process.env.KC_SETUP_PATH;

async function globalTeardown(config: FullConfig) {
    console.log("Keycloak stopping");
    exec(`ENV=test KC_SETUP_PATH=${kcPath} docker-compose -f ${kcPath}/docker-compose.yml  --project-directory . down`);
}

export default globalTeardown;
