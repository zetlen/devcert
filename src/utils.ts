import { execSync, ExecSyncOptions } from 'child_process';
import tmp from 'tmp';
import createDebug from 'debug';
import { chmodSync as chmod } from 'fs';
import path from 'path';
import sudoPrompt from 'sudo-prompt';

import {
  configPath,
} from './constants';

const debug = createDebug('devcert:util');

export function generateCACertificate(caSelfSignConfig: string, rootKeyPath: string, rootCertPath: string) {
  openssl(`req -new -x509 -config "${ caSelfSignConfig }" -key "${ rootKeyPath }" -out "${ rootCertPath }"`);
}

export function generateCertificateSigningRequest(configpath: string, domainKeyPath: string, csrFile: string) {
  openssl(`req -new -config "${ configpath }" -key "${ domainKeyPath }" -out "${ csrFile }"`);
}

export function generateCertificateWithCA(domainCertConfigPath: string, csrFile: string, domainCertPath: string, caKeyPath: string, caCertPath: string): void {
    openssl(`ca -config "${ domainCertConfigPath }" -in "${ csrFile }" -out "${ domainCertPath }" -keyfile "${ caKeyPath }" -cert "${ caCertPath }" -days 7000 -batch`)
}
// Generate a cryptographic key, used to sign certificates or certificate signing requests.
export function generateKey(filename: string): void {
  debug(`generateKey: ${ filename }`);
  openssl(`genrsa -out "${ filename }" 2048`);
  chmod(filename, 400);
}


function openssl(cmd: string) {
  return run(`openssl ${ cmd }`, {
    stdio: 'pipe',
    env: Object.assign({
      RANDFILE: path.join(configPath('.rnd'))
    }, process.env)
  });
}

export function run(cmd: string, options: ExecSyncOptions = {}) {
  debug(`exec: \`${ cmd }\``);
  return execSync(cmd, options);
}

export function waitForUser() {
  return new Promise((resolve) => {
    process.stdin.resume();
    process.stdin.on('data', resolve);
  });
}

export function reportableError(message: string) {
  return new Error(`${message} | This is a bug in devcert, please report the issue at https://github.com/davewasmer/devcert/issues`);
}

export function mktmp() {
  // discardDescriptor because windows complains the file is in use if we create a tmp file
  // and then shell out to a process that tries to use it
  return tmp.fileSync({ discardDescriptor: true }).name;
}

export function sudo(cmd: string): Promise<string | null> {
  return new Promise((resolve, reject) => {
    sudoPrompt.exec(cmd, { name: 'devcert' }, (err: Error | null, stdout: string | null, stderr: string | null) => {
      let error = err || (typeof stderr === 'string' && stderr.trim().length > 0 && new Error(stderr)) ;
      error ? reject(error) : resolve(stdout);
    });
  });
}
