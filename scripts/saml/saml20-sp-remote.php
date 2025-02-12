<?php
/**
 * SAML 2.0 remote SP metadata for simpleSAMLphp.
 *
 * See: https://simplesamlphp.org/docs/stable/simplesamlphp-reference-sp-remote
 */

/*
 * Example simpleSAMLphp SAML 2.0 SP
 */
$metadata['https://saml2sp.example.org'] = array(
	'AssertionConsumerService' => 'https://saml2sp.example.org/simplesaml/module.php/saml/sp/saml2-acs.php/default-sp',
	'SingleLogoutService' => 'https://saml2sp.example.org/simplesaml/module.php/saml/sp/saml2-logout.php/default-sp',
);

$metadata['cloudfoundry-saml-login'] = array(
    'AssertionConsumerService' => 'http://localhost:8080/uaa/saml/SSO/alias/cloudfoundry-saml-login',
    'SingleLogoutService' => 'http://localhost:8080/uaa/saml/SingleLogout/alias/cloudfoundry-saml-login',
    'NameIDFormat' => 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified',
    'simplesaml.nameidattribute' => 'uid',
);

$metadata['login.10.244.0.34.xip.io'] = array(
    'AssertionConsumerService' => 'http://login.10.244.0.34.xip.io/saml/SSO/alias/login.10.244.0.34.xip.io',
    'SingleLogoutService' => 'http://login.10.244.0.34.xip.io/saml/SSO/alias/login.10.244.0.34.xip.io',
    'NameIDFormat' => 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
    'simplesaml.nameidattribute' => 'emailAddress',
);

$metadata['login.identity.cf-app.com'] = array(
    'AssertionConsumerService' => 'https://login.identity.cf-app.com/saml/SSO/alias/login.identity.cf-app.com',
    'SingleLogoutService' => 'https://login.identity.cf-app.com/saml/SingleLogout/alias/login.identity.cf-app.com',
    'NameIDFormat' => 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
    'simplesaml.nameidattribute' => 'emailAddress',
);

$metadata['http://52.1.233.136:8080'] = array(
    'AssertionConsumerService' => 'http://52.1.233.136:8080/saml/SSO/alias/52.1.233.136',
    'SingleLogoutService' => 'http://52.1.233.136:8080/saml/SSO/alias/52.1.233.136',
    'NameIDFormat' => 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
    'simplesaml.nameidattribute' => 'emailAddress',
);

$metadata['uaa-bosh'] = array(
    'AssertionConsumerService' => 'https://uaa.uaa-bosh.cf-app.com:8443/saml/SSO/alias/uaa-bosh',
    'SingleLogoutService' => 'https://uaa.uaa-bosh.cf-app.com:8443/saml/SSO/alias/uaa-bosh',
    'NameIDFormat' => 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
    'simplesaml.nameidattribute' => 'emailAddress',
);

$metadata['testzone1.login.10.244.0.34.xip.io'] = array(
    'AssertionConsumerService' => 'http://testzone1.login.10.244.0.34.xip.io/saml/SSO/alias/testzone1.login.10.244.0.34.xip.io',
    'SingleLogoutService' => 'http://testzone1.login.10.244.0.34.xip.io/saml/SSO/alias/testzone1.login.10.244.0.34.xip.io',
    'NameIDFormat' => 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
    'simplesaml.nameidattribute' => 'emailAddress',
);

$metadata['testzone1.cloudfoundry-saml-login'] = array(
    'AssertionConsumerService' => 'http://testzone1.localhost:8080/uaa/saml/SSO/alias/testzone1.cloudfoundry-saml-login',
    'SingleLogoutService' => 'http://testzone1.localhost:8080/uaa/saml/SSO/alias/testzone1.cloudfoundry-saml-login',
    'NameIDFormat' => 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
    'simplesaml.nameidattribute' => 'emailAddress',
);

$metadata['testzone2.cloudfoundry-saml-login'] = array(
    'AssertionConsumerService' => 'http://testzone2.localhost:8080/uaa/saml/SSO/alias/testzone2.cloudfoundry-saml-login',
    'SingleLogoutService' => 'http://testzone2.localhost:8080/uaa/saml/SingleLogout/alias/testzone2.cloudfoundry-saml-login',
    'NameIDFormat' => 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
    'simplesaml.nameidattribute' => 'emailAddress',
);

$metadata['testzone3.cloudfoundry-saml-login'] = array(
    'AssertionConsumerService' => 'http://testzone3.localhost:8080/uaa/saml/SSO/alias/invalid',
    'SingleLogoutService' => 'http://testzone3.localhost:8080/uaa/saml/SSO/alias/invalid',
    'NameIDFormat' => 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
    'simplesaml.nameidattribute' => 'emailAddress',
);

$metadata['testzone4.cloudfoundry-saml-login'] = array(
    'AssertionConsumerService' => 'http://testzone4.localhost:8080/uaa/saml/SSO/alias/testzone4.cloudfoundry-saml-login',
    'SingleLogoutService' => 'http://testzone4.localhost:8080/uaa/saml/SSO/alias/testzone4.cloudfoundry-saml-login',
    'NameIDFormat' => 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified',
    'simplesaml.nameidattribute' => 'uid',
);

$metadata['oidcloginit.cloudfoundry-saml-login'] = array(
    'AssertionConsumerService' => 'http://oidcloginit.localhost:8080/uaa/saml/SSO/alias/oidcloginit.cloudfoundry-saml-login',
    'SingleLogoutService' => 'http://oidcloginit.localhost:8080/uaa/saml/SSO/alias/oidcloginit.cloudfoundry-saml-login',
    'NameIDFormat' => 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified',
    'simplesaml.nameidattribute' => 'uid',
);


$metadata['https://oidc10.uaa-acceptance.cf-app.com'] = array(
    'AssertionConsumerService' => 'https://oidc10.uaa-acceptance.cf-app.com/saml/SSO/alias/oidc10.uaa-acceptance.cf-app.com',
    'SingleLogoutService' => 'https://oidc10.uaa-acceptance.cf-app.com/saml/SSO/alias/oidc10.uaa-acceptance.cf-app.com',
    'NameIDFormat' => 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
    'simplesaml.nameidattribute' => 'emailAddress',
);

$metadata['login.uaa-acceptance-74.cf-app.com'] = array(
    'AssertionConsumerService' => 'https://login.uaa-acceptance-74.cf-app.com/saml/SSO/alias/login.uaa-acceptance-74.cf-app.com',
    'SingleLogoutService' => 'https://login.uaa-acceptance-74.cf-app.com/saml/SSO/alias/login.uaa-acceptance-74.cf-app.com',
    'NameIDFormat' => 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
    'simplesaml.nameidattribute' => 'emailAddress',
);

$metadata['spring.security.saml.sp.id'] = array(
    'AssertionConsumerService' => 'http://localhost:8080/sample-sp/saml/sp/SSO/alias/boot-sample-sp',
    'SingleLogoutService' => 'http://localhost:8080/sample-sp/saml/sp/logout/alias/boot-sample-sp',
    'NameIDFormat' => 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
    'simplesaml.nameidattribute' => 'emailAddress',
    'certData' => 'MIICgTCCAeoCCQCuVzyqFgMSyDANBgkqhkiG9w0BAQsFADCBhDELMAkGA1UEBhMC
VVMxEzARBgNVBAgMCldhc2hpbmd0b24xEjAQBgNVBAcMCVZhbmNvdXZlcjEdMBsG
A1UECgwUU3ByaW5nIFNlY3VyaXR5IFNBTUwxCzAJBgNVBAsMAnNwMSAwHgYDVQQD
DBdzcC5zcHJpbmcuc2VjdXJpdHkuc2FtbDAeFw0xODA1MTQxNDMwNDRaFw0yODA1
MTExNDMwNDRaMIGEMQswCQYDVQQGEwJVUzETMBEGA1UECAwKV2FzaGluZ3RvbjES
MBAGA1UEBwwJVmFuY291dmVyMR0wGwYDVQQKDBRTcHJpbmcgU2VjdXJpdHkgU0FN
TDELMAkGA1UECwwCc3AxIDAeBgNVBAMMF3NwLnNwcmluZy5zZWN1cml0eS5zYW1s
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDRu7/EI0BlNzMEBFVAcbx+lLos
vzIWU+01dGTY8gBdhMQNYKZ92lMceo2CuVJ66cUURPym3i7nGGzoSnAxAre+0YIM
+U0razrWtAUE735bkcqELZkOTZLelaoOztmWqRbe5OuEmpewH7cx+kNgcVjdctOG
y3Q6x+I4qakY/9qhBQIDAQABMA0GCSqGSIb3DQEBCwUAA4GBAAeViTvHOyQopWEi
XOfI2Z9eukwrSknDwq/zscR0YxwwqDBMt/QdAODfSwAfnciiYLkmEjlozWRtOeN+
qK7UFgP1bRl5qksrYX5S0z2iGJh0GvonLUt3e20Ssfl5tTEDDnAEUMLfBkyaxEHD
RZ/nbTJ7VTeZOSyRoVn5XHhpuJ0B',
    'assertion.encryption' => TRUE,
    'nameid.encryption' => TRUE,
);

$metadata['http://localhost:8080/sample-sp'] = array(
    'AssertionConsumerService' => 'http://localhost:8080/sample-sp/saml2/SSO/alias/localhost',
    'SingleLogoutService' => 'http://localhost:8080/sample-sp/saml/sp/logout/alias/localhost',
    'NameIDFormat' => 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
    'simplesaml.nameidattribute' => 'emailAddress',
    'certData' => 'MIICgTCCAeoCCQCuVzyqFgMSyDANBgkqhkiG9w0BAQsFADCBhDELMAkGA1UEBhMC
VVMxEzARBgNVBAgMCldhc2hpbmd0b24xEjAQBgNVBAcMCVZhbmNvdXZlcjEdMBsG
A1UECgwUU3ByaW5nIFNlY3VyaXR5IFNBTUwxCzAJBgNVBAsMAnNwMSAwHgYDVQQD
DBdzcC5zcHJpbmcuc2VjdXJpdHkuc2FtbDAeFw0xODA1MTQxNDMwNDRaFw0yODA1
MTExNDMwNDRaMIGEMQswCQYDVQQGEwJVUzETMBEGA1UECAwKV2FzaGluZ3RvbjES
MBAGA1UEBwwJVmFuY291dmVyMR0wGwYDVQQKDBRTcHJpbmcgU2VjdXJpdHkgU0FN
TDELMAkGA1UECwwCc3AxIDAeBgNVBAMMF3NwLnNwcmluZy5zZWN1cml0eS5zYW1s
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDRu7/EI0BlNzMEBFVAcbx+lLos
vzIWU+01dGTY8gBdhMQNYKZ92lMceo2CuVJ66cUURPym3i7nGGzoSnAxAre+0YIM
+U0razrWtAUE735bkcqELZkOTZLelaoOztmWqRbe5OuEmpewH7cx+kNgcVjdctOG
y3Q6x+I4qakY/9qhBQIDAQABMA0GCSqGSIb3DQEBCwUAA4GBAAeViTvHOyQopWEi
XOfI2Z9eukwrSknDwq/zscR0YxwwqDBMt/QdAODfSwAfnciiYLkmEjlozWRtOeN+
qK7UFgP1bRl5qksrYX5S0z2iGJh0GvonLUt3e20Ssfl5tTEDDnAEUMLfBkyaxEHD
RZ/nbTJ7VTeZOSyRoVn5XHhpuJ0B',
    'assertion.encryption' => FALSE,
    'nameid.encryption' => FALSE,
);

$metadata['http://localhost:8080/saml2/service-provider-metadata/simplesamlphp'] = array(
    'AssertionConsumerService' => 'http://localhost:8080/login/saml2/sso/simplesamlphp',
    'SingleLogoutService' => 'http://localhost:8080/saml2/logout/simplesamlphp',
    'NameIDFormat' => 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
    'simplesaml.nameidattribute' => 'emailAddress',
    'certData' => 'MIICgTCCAeoCCQCuVzyqFgMSyDANBgkqhkiG9w0BAQsFADCBhDELMAkGA1UEBhMC
VVMxEzARBgNVBAgMCldhc2hpbmd0b24xEjAQBgNVBAcMCVZhbmNvdXZlcjEdMBsG
A1UECgwUU3ByaW5nIFNlY3VyaXR5IFNBTUwxCzAJBgNVBAsMAnNwMSAwHgYDVQQD
DBdzcC5zcHJpbmcuc2VjdXJpdHkuc2FtbDAeFw0xODA1MTQxNDMwNDRaFw0yODA1
MTExNDMwNDRaMIGEMQswCQYDVQQGEwJVUzETMBEGA1UECAwKV2FzaGluZ3RvbjES
MBAGA1UEBwwJVmFuY291dmVyMR0wGwYDVQQKDBRTcHJpbmcgU2VjdXJpdHkgU0FN
TDELMAkGA1UECwwCc3AxIDAeBgNVBAMMF3NwLnNwcmluZy5zZWN1cml0eS5zYW1s
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDRu7/EI0BlNzMEBFVAcbx+lLos
vzIWU+01dGTY8gBdhMQNYKZ92lMceo2CuVJ66cUURPym3i7nGGzoSnAxAre+0YIM
+U0razrWtAUE735bkcqELZkOTZLelaoOztmWqRbe5OuEmpewH7cx+kNgcVjdctOG
y3Q6x+I4qakY/9qhBQIDAQABMA0GCSqGSIb3DQEBCwUAA4GBAAeViTvHOyQopWEi
XOfI2Z9eukwrSknDwq/zscR0YxwwqDBMt/QdAODfSwAfnciiYLkmEjlozWRtOeN+
qK7UFgP1bRl5qksrYX5S0z2iGJh0GvonLUt3e20Ssfl5tTEDDnAEUMLfBkyaxEHD
RZ/nbTJ7VTeZOSyRoVn5XHhpuJ0B',
    'assertion.encryption' => FALSE,
    'nameid.encryption' => FALSE,
    'validate.authnrequest' => TRUE,
    'redirect.sign' => TRUE,

);


$metadata['http://localhost:8080/saml2/service-provider-metadata/simplesamlphp2'] = array(
    'AssertionConsumerService' => 'http://localhost:8080/login/saml2/sso/simplesamlphp2',
    'SingleLogoutService' => 'http://localhost:8080/saml2/logout/simplesamlphp2',
    'NameIDFormat' => 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified',
    'simplesaml.nameidattribute' => 'eduPersonPrincipalName',
    'certData' => 'MIICgTCCAeoCCQCuVzyqFgMSyDANBgkqhkiG9w0BAQsFADCBhDELMAkGA1UEBhMC
VVMxEzARBgNVBAgMCldhc2hpbmd0b24xEjAQBgNVBAcMCVZhbmNvdXZlcjEdMBsG
A1UECgwUU3ByaW5nIFNlY3VyaXR5IFNBTUwxCzAJBgNVBAsMAnNwMSAwHgYDVQQD
DBdzcC5zcHJpbmcuc2VjdXJpdHkuc2FtbDAeFw0xODA1MTQxNDMwNDRaFw0yODA1
MTExNDMwNDRaMIGEMQswCQYDVQQGEwJVUzETMBEGA1UECAwKV2FzaGluZ3RvbjES
MBAGA1UEBwwJVmFuY291dmVyMR0wGwYDVQQKDBRTcHJpbmcgU2VjdXJpdHkgU0FN
TDELMAkGA1UECwwCc3AxIDAeBgNVBAMMF3NwLnNwcmluZy5zZWN1cml0eS5zYW1s
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDRu7/EI0BlNzMEBFVAcbx+lLos
vzIWU+01dGTY8gBdhMQNYKZ92lMceo2CuVJ66cUURPym3i7nGGzoSnAxAre+0YIM
+U0razrWtAUE735bkcqELZkOTZLelaoOztmWqRbe5OuEmpewH7cx+kNgcVjdctOG
y3Q6x+I4qakY/9qhBQIDAQABMA0GCSqGSIb3DQEBCwUAA4GBAAeViTvHOyQopWEi
XOfI2Z9eukwrSknDwq/zscR0YxwwqDBMt/QdAODfSwAfnciiYLkmEjlozWRtOeN+
qK7UFgP1bRl5qksrYX5S0z2iGJh0GvonLUt3e20Ssfl5tTEDDnAEUMLfBkyaxEHD
RZ/nbTJ7VTeZOSyRoVn5XHhpuJ0B',
    'assertion.encryption' => TRUE,
    'nameid.encryption' => TRUE,
);
/*
 * This example shows an example config that works with Google Apps for education.
 * What is important is that you have an attribute in your IdP that maps to the local part of the email address
 * at Google Apps. In example, if your google account is foo.com, and you have a user that has an email john@foo.com, then you
 * must set the simplesaml.nameidattribute to be the name of an attribute that for this user has the value of 'john'.
 */
$metadata['google.com'] = array(
	'AssertionConsumerService' => 'https://www.google.com/a/g.feide.no/acs',
	'NameIDFormat' => 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
	'simplesaml.nameidattribute' => 'uid',
	'simplesaml.attributes' => FALSE,
);
