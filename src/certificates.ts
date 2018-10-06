// import path from 'path';
import createDebug from 'debug';
import { sync as mkdirp } from 'mkdirp';
import { pathForDomain, withDomainSigningRequestConfig, withDomainCertificateConfig } from './constants';
import { generateKey, generateCertificateWithCA, generateCertificateSigningRequest } from './utils';
import { withCertificateAuthorityCredentials } from './certificate-authority';

const debug = createDebug('devcert:certificates');

/**
 * Generate a domain certificate signed by the devcert root CA. Domain
 * certificates are cached in their own directories under
 * CONFIG_ROOT/domains/<domain>, and reused on subsequent requests. Because the
 * individual domain certificates are signed by the devcert root CA (which was
 * added to the OS/browser trust stores), they are trusted.
 */
export default async function generateDomainCertificate(domain: string): Promise<void> {
  mkdirp(pathForDomain(domain));

  debug(`Generating private key for ${ domain }`);
  let domainKeyPath = pathForDomain(domain, 'private-key.key');
  generateKey(domainKeyPath);

  debug(`Generating certificate signing request for ${ domain }`);
  let csrFile = pathForDomain(domain, `certificate-signing-request.csr`);
  withDomainSigningRequestConfig(domain, (configpath) => {
    generateCertificateSigningRequest(configpath, domainKeyPath, csrFile);
  });

  debug(`Generating certificate for ${ domain } from signing request and signing with root CA`);
  let domainCertPath = pathForDomain(domain, `certificate.crt`);

  await withCertificateAuthorityCredentials(({ caKeyPath, caCertPath }) => {
    withDomainCertificateConfig(domain, (domainCertConfigPath) => {
      generateCertificateWithCA(domainCertConfigPath, csrFile, domainCertPath, caKeyPath, caCertPath);
    });
  });
}

