/*
 * ****************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 * ****************************************************************************
 */

package org.cloudfoundry.identity.uaa.zone.event;

import org.cloudfoundry.identity.uaa.provider.saml.idp.SamlServiceProvider;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.junit.Before;
import org.junit.Test;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;

import static org.junit.Assert.assertEquals;


public class ServiceProviderModifiedEventTest {

    private SamlServiceProvider provider;

    @Before
    public void setup() {
        String name = new RandomValueStringGenerator().generate();
        String requestBody = "{\n" +
            "  \"name\" : \"" + name + "\",\n" +
            "  \"entityId\" : \""+ name +".cloudfoundry-saml-login\",\n" +
            "  \"active\" : true,\n" +
            "  \"config\" : \"{\\\"metaDataLocation\\\" : \\\"<?xml version=\\\\\\\"1.0\\\\\\\" encoding=\\\\\\\"UTF-8\\\\\\\"?><md:EntityDescriptor xmlns:md=\\\\\\\"urn:oasis:names:tc:SAML:2.0:metadata\\\\\\\" ID=\\\\\\\"" + name + ".cloudfoundry-saml-login\\\\\\\" entityID=\\\\\\\"" + name + ".cloudfoundry-saml-login\\\\\\\"><ds:Signature xmlns:ds=\\\\\\\"http://www.w3.org/2000/09/xmldsig#\\\\\\\"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm=\\\\\\\"http://www.w3.org/2001/10/xml-exc-c14n#\\\\\\\"/><ds:SignatureMethod Algorithm=\\\\\\\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\\\\\\\"/><ds:Reference URI=\\\\\\\"#" + name + ".cloudfoundry-saml-login\\\\\\\"><ds:Transforms><ds:Transform Algorithm=\\\\\\\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\\\\\\\"/><ds:Transform Algorithm=\\\\\\\"http://www.w3.org/2001/10/xml-exc-c14n#\\\\\\\"/></ds:Transforms><ds:DigestMethod Algorithm=\\\\\\\"http://www.w3.org/2000/09/xmldsig#sha1\\\\\\\"/><ds:DigestValue>zALgjEFJ7jJSwn2AOBH5H8CX93U=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>Rp5XH8eT0ek/vlFGzHgIFOeESchOwSYZ9oh4JA9WqQ0jJtvNQ9IttY2QY9XK3n6TbbtPcEKVgljyTfwD5ymp+oMKfIYQC9JsN8mPADN5rjLFgC+xGceWLbcjoNsCJ7x2ZjyWRblSxoOU5qnzxEA3k3Bu+OkV+ZXcSbmgMWoQACg=</ds:SignatureValue><ds:KeyInfoService><ds:X509Data><ds:X509Certificate>MIIDSTCCArKgAwIBAgIBADANBgkqhkiG9w0BAQQFADB8MQswCQYDVQQGEwJhdzEOMAwGA1UECBMF\\\\nYXJ1YmExDjAMBgNVBAoTBWFydWJhMQ4wDAYDVQQHEwVhcnViYTEOMAwGA1UECxMFYXJ1YmExDjAM\\\\nBgNVBAMTBWFydWJhMR0wGwYJKoZIhvcNAQkBFg5hcnViYUBhcnViYS5hcjAeFw0xNTExMjAyMjI2\\\\nMjdaFw0xNjExMTkyMjI2MjdaMHwxCzAJBgNVBAYTAmF3MQ4wDAYDVQQIEwVhcnViYTEOMAwGA1UE\\\\nChMFYXJ1YmExDjAMBgNVBAcTBWFydWJhMQ4wDAYDVQQLEwVhcnViYTEOMAwGA1UEAxMFYXJ1YmEx\\\\nHTAbBgkqhkiG9w0BCQEWDmFydWJhQGFydWJhLmFyMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKB\\\\ngQDHtC5gUXxBKpEqZTLkNvFwNGnNIkggNOwOQVNbpO0WVHIivig5L39WqS9u0hnA+O7MCA/KlrAR\\\\n4bXaeVVhwfUPYBKIpaaTWFQR5cTR1UFZJL/OF9vAfpOwznoD66DDCnQVpbCjtDYWX+x6imxn8HCY\\\\nxhMol6ZnTbSsFW6VZjFMjQIDAQABo4HaMIHXMB0GA1UdDgQWBBTx0lDzjH/iOBnOSQaSEWQLx1sy\\\\nGDCBpwYDVR0jBIGfMIGcgBTx0lDzjH/iOBnOSQaSEWQLx1syGKGBgKR+MHwxCzAJBgNVBAYTAmF3\\\\nMQ4wDAYDVQQIEwVhcnViYTEOMAwGA1UEChMFYXJ1YmExDjAMBgNVBAcTBWFydWJhMQ4wDAYDVQQL\\\\nEwVhcnViYTEOMAwGA1UEAxMFYXJ1YmExHTAbBgkqhkiG9w0BCQEWDmFydWJhQGFydWJhLmFyggEA\\\\nMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEEBQADgYEAYvBJ0HOZbbHClXmGUjGs+GS+xC1FO/am\\\\n2suCSYqNB9dyMXfOWiJ1+TLJk+o/YZt8vuxCKdcZYgl4l/L6PxJ982SRhc83ZW2dkAZI4M0/Ud3o\\\\nePe84k8jm3A7EvH5wi5hvCkKRpuRBwn3Ei+jCRouxTbzKPsuCVB+1sNyxMTXzf0=</ds:X509Certificate></ds:X509Data></ds:KeyInfoService></ds:Signature><md:SPSSODescriptor AuthnRequestsSigned=\\\\\\\"true\\\\\\\" WantAssertionsSigned=\\\\\\\"true\\\\\\\" protocolSupportEnumeration=\\\\\\\"urn:oasis:names:tc:SAML:2.0:protocol\\\\\\\"><md:KeyDescriptor use=\\\\\\\"signing\\\\\\\"><ds:KeyInfoService xmlns:ds=\\\\\\\"http://www.w3.org/2000/09/xmldsig#\\\\\\\"><ds:X509Data><ds:X509Certificate>MIIDSTCCArKgAwIBAgIBADANBgkqhkiG9w0BAQQFADB8MQswCQYDVQQGEwJhdzEOMAwGA1UECBMF\\\\nYXJ1YmExDjAMBgNVBAoTBWFydWJhMQ4wDAYDVQQHEwVhcnViYTEOMAwGA1UECxMFYXJ1YmExDjAM\\\\nBgNVBAMTBWFydWJhMR0wGwYJKoZIhvcNAQkBFg5hcnViYUBhcnViYS5hcjAeFw0xNTExMjAyMjI2\\\\nMjdaFw0xNjExMTkyMjI2MjdaMHwxCzAJBgNVBAYTAmF3MQ4wDAYDVQQIEwVhcnViYTEOMAwGA1UE\\\\nChMFYXJ1YmExDjAMBgNVBAcTBWFydWJhMQ4wDAYDVQQLEwVhcnViYTEOMAwGA1UEAxMFYXJ1YmEx\\\\nHTAbBgkqhkiG9w0BCQEWDmFydWJhQGFydWJhLmFyMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKB\\\\ngQDHtC5gUXxBKpEqZTLkNvFwNGnNIkggNOwOQVNbpO0WVHIivig5L39WqS9u0hnA+O7MCA/KlrAR\\\\n4bXaeVVhwfUPYBKIpaaTWFQR5cTR1UFZJL/OF9vAfpOwznoD66DDCnQVpbCjtDYWX+x6imxn8HCY\\\\nxhMol6ZnTbSsFW6VZjFMjQIDAQABo4HaMIHXMB0GA1UdDgQWBBTx0lDzjH/iOBnOSQaSEWQLx1sy\\\\nGDCBpwYDVR0jBIGfMIGcgBTx0lDzjH/iOBnOSQaSEWQLx1syGKGBgKR+MHwxCzAJBgNVBAYTAmF3\\\\nMQ4wDAYDVQQIEwVhcnViYTEOMAwGA1UEChMFYXJ1YmExDjAMBgNVBAcTBWFydWJhMQ4wDAYDVQQL\\\\nEwVhcnViYTEOMAwGA1UEAxMFYXJ1YmExHTAbBgkqhkiG9w0BCQEWDmFydWJhQGFydWJhLmFyggEA\\\\nMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEEBQADgYEAYvBJ0HOZbbHClXmGUjGs+GS+xC1FO/am\\\\n2suCSYqNB9dyMXfOWiJ1+TLJk+o/YZt8vuxCKdcZYgl4l/L6PxJ982SRhc83ZW2dkAZI4M0/Ud3o\\\\nePe84k8jm3A7EvH5wi5hvCkKRpuRBwn3Ei+jCRouxTbzKPsuCVB+1sNyxMTXzf0=</ds:X509Certificate></ds:X509Data></ds:KeyInfoService></md:KeyDescriptor><md:KeyDescriptor use=\\\\\\\"encryption\\\\\\\"><ds:KeyInfoService xmlns:ds=\\\\\\\"http://www.w3.org/2000/09/xmldsig#\\\\\\\"><ds:X509Data><ds:X509Certificate>MIIDSTCCArKgAwIBAgIBADANBgkqhkiG9w0BAQQFADB8MQswCQYDVQQGEwJhdzEOMAwGA1UECBMF\\\\nYXJ1YmExDjAMBgNVBAoTBWFydWJhMQ4wDAYDVQQHEwVhcnViYTEOMAwGA1UECxMFYXJ1YmExDjAM\\\\nBgNVBAMTBWFydWJhMR0wGwYJKoZIhvcNAQkBFg5hcnViYUBhcnViYS5hcjAeFw0xNTExMjAyMjI2\\\\nMjdaFw0xNjExMTkyMjI2MjdaMHwxCzAJBgNVBAYTAmF3MQ4wDAYDVQQIEwVhcnViYTEOMAwGA1UE\\\\nChMFYXJ1YmExDjAMBgNVBAcTBWFydWJhMQ4wDAYDVQQLEwVhcnViYTEOMAwGA1UEAxMFYXJ1YmEx\\\\nHTAbBgkqhkiG9w0BCQEWDmFydWJhQGFydWJhLmFyMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKB\\\\ngQDHtC5gUXxBKpEqZTLkNvFwNGnNIkggNOwOQVNbpO0WVHIivig5L39WqS9u0hnA+O7MCA/KlrAR\\\\n4bXaeVVhwfUPYBKIpaaTWFQR5cTR1UFZJL/OF9vAfpOwznoD66DDCnQVpbCjtDYWX+x6imxn8HCY\\\\nxhMol6ZnTbSsFW6VZjFMjQIDAQABo4HaMIHXMB0GA1UdDgQWBBTx0lDzjH/iOBnOSQaSEWQLx1sy\\\\nGDCBpwYDVR0jBIGfMIGcgBTx0lDzjH/iOBnOSQaSEWQLx1syGKGBgKR+MHwxCzAJBgNVBAYTAmF3\\\\nMQ4wDAYDVQQIEwVhcnViYTEOMAwGA1UEChMFYXJ1YmExDjAMBgNVBAcTBWFydWJhMQ4wDAYDVQQL\\\\nEwVhcnViYTEOMAwGA1UEAxMFYXJ1YmExHTAbBgkqhkiG9w0BCQEWDmFydWJhQGFydWJhLmFyggEA\\\\nMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEEBQADgYEAYvBJ0HOZbbHClXmGUjGs+GS+xC1FO/am\\\\n2suCSYqNB9dyMXfOWiJ1+TLJk+o/YZt8vuxCKdcZYgl4l/L6PxJ982SRhc83ZW2dkAZI4M0/Ud3o\\\\nePe84k8jm3A7EvH5wi5hvCkKRpuRBwn3Ei+jCRouxTbzKPsuCVB+1sNyxMTXzf0=</ds:X509Certificate></ds:X509Data></ds:KeyInfoService></md:KeyDescriptor><md:SingleLogoutService Binding=\\\\\\\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\\\\\\\" Location=\\\\\\\"http://" + name + ".localhost:8080/uaa/saml/SingleLogout/alias/" + name + ".cloudfoundry-saml-login\\\\\\\"/><md:SingleLogoutService Binding=\\\\\\\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\\\\\\\" Location=\\\\\\\"http://" + name + ".localhost:8080/uaa/saml/SingleLogout/alias/" + name + ".cloudfoundry-saml-login\\\\\\\"/><md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat><md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat><md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</md:NameIDFormat><md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</md:NameIDFormat><md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName</md:NameIDFormat><md:AssertionConsumerService Binding=\\\\\\\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\\\\\\\" Location=\\\\\\\"http://" + name + ".localhost:8080/uaa/saml/SSO/alias/" + name + ".cloudfoundry-saml-login\\\\\\\" index=\\\\\\\"0\\\\\\\" isDefault=\\\\\\\"true\\\\\\\"/></md:SPSSODescriptor></md:EntityDescriptor>\\\",\\\"metadataTrustCheck\\\" : true }\"" +
            "}";
        provider = JsonUtils.readValue(requestBody, SamlServiceProvider.class);

    }
    @Test
    public void serviceProviderCreated() {
        evaludateAuditEventData(ServiceProviderModifiedEvent.serviceProviderCreated(provider));
    }

    @Test
    public void serviceProviderModified() {
        evaludateAuditEventData(ServiceProviderModifiedEvent.serviceProviderModified(provider));
    }

    public void evaludateAuditEventData(ServiceProviderModifiedEvent event) {
        assertEquals(
            String.format(ServiceProviderModifiedEvent.dataFormat,
                          provider.getId(),
                          provider.getName(),
                          provider.getEntityId()),
            event.getAuditEvent().getData()
        );
    }

}