import { type Browser } from '@playwright/test';
import dotenv from 'dotenv';
import dotenvExpand from 'dotenv-expand';

const fs = require("fs");
const { spawn } = require('node:child_process');

function loadEnv(){
    var myEnv = dotenv.config({ path: 'test.env' });
    dotenvExpand.expand(myEnv);
}

async function waitFor(url: String, browser: Browser) {
    var ready = false;
    var context;

    do {
        try {
            context = await browser.newContext();
            const page = await context.newPage();
            await page.waitForTimeout(500);
            const result = await page.goto(url);
            ready = result.status() === 200;
        } catch(e) {
            if( !e.message.includes("NS_ERROR_CONNECTION_REFUSED") ){
                throw e;
            }
        } finally {
            await context.close();
        }
    } while(!ready);
}

async function startVaultWarden(browser: Browser, env = {}, reset: Boolean = true) {
    if( reset ){
        fs.rmSync("data/db.sqlite3", { force: true });
        fs.rmSync("data/db.sqlite3-shm", { force: true });
        fs.rmSync("data/db.sqlite3-wal", { force: true });
    }

    const vw_log = fs.openSync("data/logs/vaultwarden.log", "a");
    var proc = spawn("../../target/release/vaultwarden", {
        env: { ...process.env, ...env },
        stdio: [process.stdin, vw_log, vw_log]
    });

    await waitFor("/", browser);

    console.log(`VaultWarden running on: ${process.env.DOMAIN}`);

    return proc;
}

async function stopVaultWarden(proc) {
    console.log(`VaultWarden stopping`);
    proc.kill();
}

async function restartVaultWarden(proc, browser: Browser, env) {
    stopVaultWarden(proc);
    return startVaultWarden(browser, env, false);
}


export { loadEnv, waitFor, startVaultWarden, stopVaultWarden, restartVaultWarden };
