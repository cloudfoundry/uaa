/**
 *******************************************************************************
 * Cloud Foundry
 * Copyright (c) [2009-2015] Pivotal Software, Inc. All Rights Reserved.
 * <p/>
 * This product is licensed to you under the Apache License, Version 2.0 (the "License").
 * You may not use this product except in compliance with the License.
 * <p/>
 * This product includes a number of subcomponents with
 * separate copyright notices and license terms. Your use of these
 * subcomponents is subject to the terms and conditions of the
 * subcomponent's license, as noted in the LICENSE file.
 *****************************************************************************
 */
package org.cloudfoundry.identity.uaa.zone;

import com.fasterxml.jackson.core.type.TypeReference;
import org.cloudfoundry.identity.uaa.AbstractIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.KeystoneIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.authentication.Origin;
import org.cloudfoundry.identity.uaa.ldap.LdapIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.login.saml.SamlIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.junit.Test;

import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

public class IdentityProviderTests {

    @Test
    public void test_backwards_compatible_json_where_config_is_a_string() {
        List<IdentityProvider> providers =
            JsonUtils.readValue(
                BACKWARDS_COMPATIBLE_LIST_OF_IDPS,
                new TypeReference<List<IdentityProvider>>() {}
            );
        assertEquals(7, providers.size());
    }

    @Test
    public void configIsAlwaysValidWhenOriginIsOtherThanUaa() {
        IdentityProvider identityProvider = new IdentityProvider().setOriginKey(Origin.LDAP).setConfig(new LdapIdentityProviderDefinition());
        assertTrue(identityProvider.configIsValid());
    }

    @Test
    public void uaaConfigMustContainAllPasswordPolicyFields() {
        assertValidity(true, JsonUtils.readValue("",UaaIdentityProviderDefinition.class));
        assertValidity(true, JsonUtils.readValue("{\"passwordPolicy\": null}",UaaIdentityProviderDefinition.class));
        assertValidity(false,JsonUtils.readValue( "{\"passwordPolicy\": {}}",UaaIdentityProviderDefinition.class));
        assertValidity(false,JsonUtils.readValue( "{\"passwordPolicy\":{\"minLength\":6}}",UaaIdentityProviderDefinition.class));
        assertValidity(false,JsonUtils.readValue( "{\"passwordPolicy\":{\"minLength\":6,\"maxLength\":128}}",UaaIdentityProviderDefinition.class));
        assertValidity(false,JsonUtils.readValue( "{\"passwordPolicy\":{\"minLength\":6,\"maxLength\":128,\"requireUpperCaseCharacter\":1}}",UaaIdentityProviderDefinition.class));
        assertValidity(false,JsonUtils.readValue( "{\"passwordPolicy\":{\"minLength\":6,\"maxLength\":128,\"requireUpperCaseCharacter\":1,\"requireLowerCaseCharacter\":1}}",UaaIdentityProviderDefinition.class));
        assertValidity(false,JsonUtils.readValue( "{\"passwordPolicy\":{\"minLength\":6,\"maxLength\":128,\"requireUpperCaseCharacter\":1,\"requireLowerCaseCharacter\":1,\"requireDigit\":1}}",UaaIdentityProviderDefinition.class));
        assertValidity(false,JsonUtils.readValue( "{\"passwordPolicy\":{\"minLength\":6,\"maxLength\":128,\"requireUpperCaseCharacter\":1,\"requireLowerCaseCharacter\":1,\"requireDigit\":1,\"requireSpecialCharacter\":0}}",UaaIdentityProviderDefinition.class));
        assertValidity(true, JsonUtils.readValue("{\"passwordPolicy\":{\"minLength\":6,\"maxLength\":128,\"requireUpperCaseCharacter\":1,\"requireLowerCaseCharacter\":1,\"requireDigit\":1,\"requireSpecialCharacter\":0,\"expirePasswordInMonths\":0}}",UaaIdentityProviderDefinition.class));
    }

    @Test
    public void uaaConfigDoesNotAllowNegativeNumbersForPasswordPolicy() {
        assertValidity(false, JsonUtils.readValue("{\"passwordPolicy\":{\"minLength\":-6,\"maxLength\":128,\"requireUpperCaseCharacter\":1,\"requireLowerCaseCharacter\":1,\"requireDigit\":1,\"requireSpecialCharacter\":0,\"expirePasswordInMonths\":0}}", UaaIdentityProviderDefinition.class));
        assertValidity(false, JsonUtils.readValue("{\"passwordPolicy\":{\"minLength\":6,\"maxLength\":-128,\"requireUpperCaseCharacter\":1,\"requireLowerCaseCharacter\":1,\"requireDigit\":1,\"requireSpecialCharacter\":0,\"expirePasswordInMonths\":0}}", UaaIdentityProviderDefinition.class));
        assertValidity(false, JsonUtils.readValue("{\"passwordPolicy\":{\"minLength\":6,\"maxLength\":128,\"requireUpperCaseCharacter\":-1,\"requireLowerCaseCharacter\":1,\"requireDigit\":1,\"requireSpecialCharacter\":0,\"expirePasswordInMonths\":0}}", UaaIdentityProviderDefinition.class));
        assertValidity(false, JsonUtils.readValue("{\"passwordPolicy\":{\"minLength\":6,\"maxLength\":128,\"requireUpperCaseCharacter\":1,\"requireLowerCaseCharacter\":-1,\"requireDigit\":1,\"requireSpecialCharacter\":0,\"expirePasswordInMonths\":0}}", UaaIdentityProviderDefinition.class));
        assertValidity(false, JsonUtils.readValue("{\"passwordPolicy\":{\"minLength\":6,\"maxLength\":128,\"requireUpperCaseCharacter\":1,\"requireLowerCaseCharacter\":1,\"requireDigit\":-1,\"requireSpecialCharacter\":0,\"expirePasswordInMonths\":0}}", UaaIdentityProviderDefinition.class));
        assertValidity(false, JsonUtils.readValue("{\"passwordPolicy\":{\"minLength\":6,\"maxLength\":128,\"requireUpperCaseCharacter\":1,\"requireLowerCaseCharacter\":1,\"requireDigit\":1,\"requireSpecialCharacter\":-1,\"expirePasswordInMonths\":0}}", UaaIdentityProviderDefinition.class));
        assertValidity(false, JsonUtils.readValue("{\"passwordPolicy\":{\"minLength\":6,\"maxLength\":128,\"requireUpperCaseCharacter\":1,\"requireLowerCaseCharacter\":1,\"requireDigit\":1,\"requireSpecialCharacter\":0,\"expirePasswordInMonths\":-1}}", UaaIdentityProviderDefinition.class));
    }

    @Test
    public void uaaConfigMustContainAllLockoutPolicyFieldsIfSpecified() throws Exception {
        assertValidity(true, JsonUtils.readValue("", UaaIdentityProviderDefinition.class));
        assertValidity(true, JsonUtils.readValue("{\"lockoutPolicy\": null}", UaaIdentityProviderDefinition.class));
        assertValidity(false,JsonUtils.readValue( "{\"lockoutPolicy\": {}}", UaaIdentityProviderDefinition.class));
        assertValidity(false,JsonUtils.readValue( "{\"lockoutPolicy\":{\"lockoutPeriodSeconds\":900}}", UaaIdentityProviderDefinition.class));
        assertValidity(false,JsonUtils.readValue( "{\"lockoutPolicy\":{\"lockoutPeriodSeconds\":900,\"lockoutAfterFailures\":128}}", UaaIdentityProviderDefinition.class));
        assertValidity(true, JsonUtils.readValue("{\"lockoutPolicy\":{\"lockoutPeriodSeconds\":900,\"lockoutAfterFailures\":128,\"countFailuresWithin\":1800}}", UaaIdentityProviderDefinition.class));
    }

    @Test
    public void uaaConfigDoesNotAllNegativeNumbersForLockoutPolicy() throws Exception {
        assertValidity(false, JsonUtils.readValue("{\"lockoutPolicy\":{\"lockoutPeriodSeconds\":-6,\"lockoutAfterFailures\":128,\"countFailuresWithin\":1}}", UaaIdentityProviderDefinition.class));
        assertValidity(false, JsonUtils.readValue("{\"lockoutPolicy\":{\"lockoutPeriodSeconds\":6,\"lockoutAfterFailures\":-128,\"countFailuresWithin\":1}}", UaaIdentityProviderDefinition.class));
        assertValidity(false, JsonUtils.readValue("{\"lockoutPolicy\":{\"lockoutPeriodSeconds\":6,\"lockoutAfterFailures\":128,\"countFailuresWithin\":-1}}", UaaIdentityProviderDefinition.class));
    }

    @Test
    public void test_serialize_uaa() {
        UaaIdentityProviderDefinition definition = new UaaIdentityProviderDefinition();
        IdentityProvider identityProvider = new IdentityProvider().setOriginKey(Origin.UAA).setConfig(definition);
        test_serialization(identityProvider);
    }

    @Test
    public void test_serialize_saml() {
        SamlIdentityProviderDefinition definition = new SamlIdentityProviderDefinition();
        definition.setMetaDataLocation("http://test.org");
        definition.setIdpEntityAlias(Origin.SAML);
        definition.setZoneId(IdentityZone.getUaa().getId());
        IdentityProvider identityProvider =
            new IdentityProvider()
                .setOriginKey(definition.getIdpEntityAlias())
                .setConfig(definition)
                .setIdentityZoneId(definition.getZoneId());
        test_serialization(identityProvider);
    }

    protected IdentityProvider test_serialization(IdentityProvider identityProvider) {
        String json = JsonUtils.writeValueAsString(identityProvider);
        IdentityProvider identityProvider2 = JsonUtils.readValue(json, IdentityProvider.class);
        assertNotNull(identityProvider2);
        assertEquals(identityProvider.getConfig(), identityProvider2.getConfig());
        return identityProvider2;
    }

    @Test
    public void test_serialize_ldap() {
        LdapIdentityProviderDefinition definition = new LdapIdentityProviderDefinition();
        IdentityProvider identityProvider = new IdentityProvider().setOriginKey(Origin.LDAP).setConfig(definition);
        test_serialization(identityProvider);
    }

    @Test
    public void test_serialize_keystone() {
        KeystoneIdentityProviderDefinition definition = new KeystoneIdentityProviderDefinition();
        IdentityProvider identityProvider = new IdentityProvider().setOriginKey(Origin.LDAP).setConfig(definition);
        test_serialization(identityProvider);
    }

    @Test
    public void test_serialize_other_origin() {
        AbstractIdentityProviderDefinition definition = new AbstractIdentityProviderDefinition();
        IdentityProvider identityProvider = new IdentityProvider().setOriginKey("other").setConfig(definition);
        IdentityProvider other = test_serialization(identityProvider);
        assertEquals("unknown", other.getType());
        assertEquals("other", other.getOriginKey());
        assertTrue(other.getConfig() instanceof AbstractIdentityProviderDefinition);
    }

    private void assertValidity(boolean expected, AbstractIdentityProviderDefinition config) {
        IdentityProvider identityProvider = new IdentityProvider().setOriginKey(Origin.UAA).setConfig(config);
        assertEquals(expected, identityProvider.configIsValid());
    }

    public static final String BACKWARDS_COMPATIBLE_LIST_OF_IDPS =
        "[\n" +
            "  {\n" +
            "    \"id\": \"2bfcef9b-33df-4c76-843f-e0e6b484a60a\",\n" +
            "    \"originKey\": \"keystone\",\n" +
            "    \"name\": \"keystone\",\n" +
            "    \"type\": \"keystone\",\n" +
            "    \"config\": null,\n" +
            "    \"version\": 1208,\n" +
            "    \"created\": 946684800000,\n" +
            "    \"active\": false,\n" +
            "    \"identityZoneId\": \"uaa\",\n" +
            "    \"last_modified\": 1447811837000\n" +
            "  },\n" +
            "  {\n" +
            "    \"id\": \"72209e6f-6434-491f-a170-398755bdc06d\",\n" +
            "    \"originKey\": \"ldap\",\n" +
            "    \"name\": \"UAA LDAP Provider\",\n" +
            "    \"type\": \"ldap\",\n" +
            "    \"config\": \"{\\\"emailDomain\\\":null,\\\"externalGroupsWhitelist\\\":[],\\\"attributeMappings\\\":{},\\\"ldapProfileFile\\\":\\\"ldap/ldap-search-and-bind.xml\\\",\\\"baseUrl\\\":\\\"ldap://52.20.5.106:389/\\\",\\\"referral\\\":null,\\\"skipSSLVerification\\\":false,\\\"userDNPattern\\\":null,\\\"userDNPatternDelimiter\\\":null,\\\"bindUserDn\\\":\\\"cn=admin,dc=test,dc=com\\\",\\\"bindPassword\\\":\\\"password\\\",\\\"userSearchBase\\\":\\\"dc=test,dc=com\\\",\\\"userSearchFilter\\\":\\\"cn={0}\\\",\\\"passwordAttributeName\\\":null,\\\"passwordEncoder\\\":null,\\\"localPasswordCompare\\\":null,\\\"mailAttributeName\\\":\\\"mail\\\",\\\"mailSubstitute\\\":\\\"\\\",\\\"mailSubstituteOverridesLdap\\\":false,\\\"ldapGroupFile\\\":\\\"ldap/ldap-groups-map-to-scopes.xml\\\",\\\"groupSearchBase\\\":\\\"ou=scopes,dc=test,dc=com\\\",\\\"groupSearchFilter\\\":\\\"member={0}\\\",\\\"groupsIgnorePartialResults\\\":null,\\\"autoAddGroups\\\":true,\\\"groupSearchSubTree\\\":true,\\\"maxGroupSearchDepth\\\":1,\\\"groupRoleAttribute\\\":\\\"spring.security.ldap.dn\\\"}\",\n" +
            "    \"version\": 932,\n" +
            "    \"created\": 946684800000,\n" +
            "    \"active\": true,\n" +
            "    \"identityZoneId\": \"uaa\",\n" +
            "    \"last_modified\": 1447811837000\n" +
            "  },\n" +
            "  {\n" +
            "    \"id\": \"69efc352-cb8d-4e85-9a43-86ddff9b4c91\",\n" +
            "    \"originKey\": \"login-server\",\n" +
            "    \"name\": \"login-server\",\n" +
            "    \"type\": \"login-server\",\n" +
            "    \"config\": null,\n" +
            "    \"version\": 0,\n" +
            "    \"created\": 946684800000,\n" +
            "    \"active\": true,\n" +
            "    \"identityZoneId\": \"uaa\",\n" +
            "    \"last_modified\": 1438372376000\n" +
            "  },\n" +
            "  {\n" +
            "    \"id\": \"58773443-0857-4f13-9dd9-0dc15fdeef06\",\n" +
            "    \"originKey\": \"okta-preview\",\n" +
            "    \"name\": \"UAA SAML Identity Provider[okta-preview]\",\n" +
            "    \"type\": \"saml\",\n" +
            "    \"config\": \"{\\\"emailDomain\\\":null,\\\"externalGroupsWhitelist\\\":[],\\\"attributeMappings\\\":{},\\\"metaDataLocation\\\":\\\"<?xml version=\\\\\\\"1.0\\\\\\\" encoding=\\\\\\\"UTF-8\\\\\\\"?><md:EntityDescriptor xmlns:md=\\\\\\\"urn:oasis:names:tc:SAML:2.0:metadata\\\\\\\" entityID=\\\\\\\"http://www.okta.com/k2lw4l5bPODCMIIDBRYZ\\\\\\\"><md:IDPSSODescriptor WantAuthnRequestsSigned=\\\\\\\"true\\\\\\\" protocolSupportEnumeration=\\\\\\\"urn:oasis:names:tc:SAML:2.0:protocol\\\\\\\"><md:KeyDescriptor use=\\\\\\\"signing\\\\\\\"><ds:KeyInfo xmlns:ds=\\\\\\\"http://www.w3.org/2000/09/xmldsig#\\\\\\\"><ds:X509Data><ds:X509Certificate>MIICmTCCAgKgAwIBAgIGAUPATqmEMA0GCSqGSIb3DQEBBQUAMIGPMQswCQYDVQQGEwJVUzETMBEG\\\\nA1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNU2FuIEZyYW5jaXNjbzENMAsGA1UECgwET2t0YTEU\\\\nMBIGA1UECwwLU1NPUHJvdmlkZXIxEDAOBgNVBAMMB1Bpdm90YWwxHDAaBgkqhkiG9w0BCQEWDWlu\\\\nZm9Ab2t0YS5jb20wHhcNMTQwMTIzMTgxMjM3WhcNNDQwMTIzMTgxMzM3WjCBjzELMAkGA1UEBhMC\\\\nVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcMDVNhbiBGcmFuY2lzY28xDTALBgNVBAoM\\\\nBE9rdGExFDASBgNVBAsMC1NTT1Byb3ZpZGVyMRAwDgYDVQQDDAdQaXZvdGFsMRwwGgYJKoZIhvcN\\\\nAQkBFg1pbmZvQG9rdGEuY29tMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCeil67/TLOiTZU\\\\nWWgW2XEGgFZ94bVO90v5J1XmcHMwL8v5Z/8qjdZLpGdwI7Ph0CyXMMNklpaR/Ljb8fsls3amdT5O\\\\nBw92Zo8ulcpjw2wuezTwL0eC0wY/GQDAZiXL59npE6U+fH1lbJIq92hx0HJSru/0O1q3+A/+jjZL\\\\n3tL/SwIDAQABMA0GCSqGSIb3DQEBBQUAA4GBAI5BoWZoH6Mz9vhypZPOJCEKa/K+biZQsA4Zqsuk\\\\nvvphhSERhqk/Nv76Vkl8uvJwwHbQrR9KJx4L3PRkGCG24rix71jEuXVGZUsDNM3CUKnARx4MEab6\\\\nGFHNkZ6DmoT/PFagngecHu+EwmuDtaG0rEkFrARwe+d8Ru0BN558abFb</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat><md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</md:NameIDFormat><md:SingleSignOnService Binding=\\\\\\\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\\\\\\\" Location=\\\\\\\"https://pivotal.oktapreview.com/app/pivotal_pivotalcfstaging_1/k2lw4l5bPODCMIIDBRYZ/sso/saml\\\\\\\"/><md:SingleSignOnService Binding=\\\\\\\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\\\\\\\" Location=\\\\\\\"https://pivotal.oktapreview.com/app/pivotal_pivotalcfstaging_1/k2lw4l5bPODCMIIDBRYZ/sso/saml\\\\\\\"/></md:IDPSSODescriptor></md:EntityDescriptor>\\\\n\\\",\\\"idpEntityAlias\\\":\\\"okta-preview\\\",\\\"zoneId\\\":\\\"uaa\\\",\\\"nameID\\\":\\\"urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress\\\",\\\"assertionConsumerIndex\\\":0,\\\"metadataTrustCheck\\\":false,\\\"showSamlLink\\\":true,\\\"socketFactoryClassName\\\":\\\"org.apache.commons.httpclient.protocol.DefaultProtocolSocketFactory\\\",\\\"linkText\\\":null,\\\"iconUrl\\\":null,\\\"addShadowUserOnLogin\\\":true}\",\n" +
            "    \"version\": 48,\n" +
            "    \"created\": 1447100573000,\n" +
            "    \"active\": true,\n" +
            "    \"identityZoneId\": \"uaa\",\n" +
            "    \"last_modified\": 1447811837000\n" +
            "  },\n" +
            "  {\n" +
            "    \"id\": \"a937f8da-f47b-4b94-ae51-5bb23a590a69\",\n" +
            "    \"originKey\": \"simplesamlphp-url\",\n" +
            "    \"name\": \"UAA SAML Identity Provider[simplesamlphp-url]\",\n" +
            "    \"type\": \"saml\",\n" +
            "    \"config\": \"{\\\"emailDomain\\\":null,\\\"externalGroupsWhitelist\\\":[],\\\"attributeMappings\\\":{\\\"user.attribute.terribleBosses\\\":\\\"manager\\\",\\\"user.attribute.employeeCostCenter\\\":\\\"costCenter\\\"},\\\"metaDataLocation\\\":\\\"http://simplesamlphp.identity.cf-app.com/saml2/idp/metadata.php\\\",\\\"idpEntityAlias\\\":\\\"simplesamlphp-url\\\",\\\"zoneId\\\":\\\"uaa\\\",\\\"nameID\\\":\\\"urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress\\\",\\\"assertionConsumerIndex\\\":0,\\\"metadataTrustCheck\\\":false,\\\"showSamlLink\\\":true,\\\"socketFactoryClassName\\\":\\\"org.apache.commons.httpclient.protocol.DefaultProtocolSocketFactory\\\",\\\"linkText\\\":\\\"Log in with Simple SAML PHP URL\\\",\\\"iconUrl\\\":null,\\\"addShadowUserOnLogin\\\":true}\",\n" +
            "    \"version\": 46,\n" +
            "    \"created\": 1447168745000,\n" +
            "    \"active\": true,\n" +
            "    \"identityZoneId\": \"uaa\",\n" +
            "    \"last_modified\": 1447811837000\n" +
            "  },\n" +
            "  {\n" +
            "    \"id\": \"eb82ad76-376e-4215-bb0f-de4677155ade\",\n" +
            "    \"originKey\": \"siteminder\",\n" +
            "    \"name\": \"UAA SAML Identity Provider[siteminder]\",\n" +
            "    \"type\": \"saml\",\n" +
            "    \"config\": \"{\\\"emailDomain\\\":null,\\\"externalGroupsWhitelist\\\":[],\\\"attributeMappings\\\":{},\\\"metaDataLocation\\\":\\\"<EntityDescriptor ID=\\\\\\\"SM12ee056541c362b8f15798057ce414c41a171e78918f\\\\\\\" entityID=\\\\\\\"smidp\\\\\\\" xmlns=\\\\\\\"urn:oasis:names:tc:SAML:2.0:metadata\\\\\\\"> <IDPSSODescriptor WantAuthnRequestsSigned=\\\\\\\"false\\\\\\\" ID=\\\\\\\"SM173c0aeddaa7107821386517c5e013881d30838546d\\\\\\\" protocolSupportEnumeration=\\\\\\\"urn:oasis:names:tc:SAML:2.0:protocol\\\\\\\"> <KeyDescriptor use=\\\\\\\"signing\\\\\\\"> <ns1:KeyInfo Id=\\\\\\\"SM124c08e62ad97957101aea86e4fb3430dd6779d8ee4\\\\\\\" xmlns:ns1=\\\\\\\"http://www.w3.org/2000/09/xmldsig#\\\\\\\"> <ns1:X509Data> <ns1:X509IssuerSerial> <ns1:X509IssuerName>CN=siteminder,OU=security,O=ca,L=islandia,ST=new york,C=US</ns1:X509IssuerName> <ns1:X509SerialNumber>1389887106</ns1:X509SerialNumber> </ns1:X509IssuerSerial> <ns1:X509Certificate>MIICRzCCAbCgAwIBAgIEUtf+gjANBgkqhkiG9w0BAQQFADBoMQswCQYDVQQGEwJVUzERMA8GA1UECBMIbmV3IHlvcmsxETAPBgNVBAcTCGlzbGFuZGlhMQswCQYDVQQKEwJjYTERMA8GA1UECxMIc2VjdXJpdHkxEzARBgNVBAMTCnNpdGVtaW5kZXIwHhcNMTQwMTE2MTU0NTA2WhcNMjQwMTE0MTU0NTA2WjBoMQswCQYDVQQGEwJVUzERMA8GA1UECBMIbmV3IHlvcmsxETAPBgNVBAcTCGlzbGFuZGlhMQswCQYDVQQKEwJjYTERMA8GA1UECxMIc2VjdXJpdHkxEzARBgNVBAMTCnNpdGVtaW5kZXIwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAOap0m7c+LSOAoGLUD3TAdS7BcJFns6HPSGAYK9NBY6MxITKElqVWHaVoaqxHCQxdQsF9oZvhPAmiNsbIRniKA+cypUov8U0pNIRPPBfl7p9ojGPZf5OtotnUnEN2ZcYuZwxRnKPfpfEs5fshSvcZIa34FCSCw8L0sRDoWFIucBjAgMBAAEwDQYJKoZIhvcNAQEEBQADgYEAFbsuhxBm3lUkycfZZuNYft1j41k+FyLLTyXyPJKmc2s2RPOYtLQyolNB214ZCIZzVSExyfo959ZBvdWz+UinpFNPd8cEc0nuXOmfW/XBEgT0YS1vIDUzfeVRyZLj2u4BdBGwmK5oYRbgHxViFVnn3C6UN5rcg5mZl0FBXJ31Zuk=</ns1:X509Certificate> <ns1:X509SubjectName>CN=siteminder,OU=security,O=ca,L=islandia,ST=new york,C=US</ns1:X509SubjectName> </ns1:X509Data> </ns1:KeyInfo> </KeyDescriptor> <NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</NameIDFormat> <SingleSignOnService Binding=\\\\\\\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\\\\\\\" Location=\\\\\\\"https://vp6.casecurecenter.com/affwebservices/public/saml2sso\\\\\\\"/> <SingleSignOnService Binding=\\\\\\\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\\\\\\\" Location=\\\\\\\"https://vp6.casecurecenter.com/affwebservices/public/saml2sso\\\\\\\"/> </IDPSSODescriptor> </EntityDescriptor>\\\",\\\"idpEntityAlias\\\":\\\"siteminder\\\",\\\"zoneId\\\":\\\"uaa\\\",\\\"nameID\\\":\\\"urn:oasis:names:tc:SAML:2.0:nameid-format:persistent\\\",\\\"assertionConsumerIndex\\\":0,\\\"metadataTrustCheck\\\":false,\\\"showSamlLink\\\":true,\\\"socketFactoryClassName\\\":\\\"org.apache.commons.httpclient.protocol.DefaultProtocolSocketFactory\\\",\\\"linkText\\\":\\\"SiteMinder\\\",\\\"iconUrl\\\":null,\\\"addShadowUserOnLogin\\\":true}\",\n" +
            "    \"version\": 2,\n" +
            "    \"created\": 1447811113000,\n" +
            "    \"active\": true,\n" +
            "    \"identityZoneId\": \"uaa\",\n" +
            "    \"last_modified\": 1447811837000\n" +
            "  },\n" +
            "  {\n" +
            "    \"id\": \"c0042c9e-1962-4f5c-a0ee-6282611eaec5\",\n" +
            "    \"originKey\": \"uaa\",\n" +
            "    \"name\": \"uaa\",\n" +
            "    \"type\": \"uaa\",\n" +
            "    \"config\": \"{\\\"emailDomain\\\":null,\\\"passwordPolicy\\\":{\\\"minLength\\\":0,\\\"maxLength\\\":255,\\\"requireUpperCaseCharacter\\\":0,\\\"requireLowerCaseCharacter\\\":0,\\\"requireDigit\\\":0,\\\"requireSpecialCharacter\\\":0,\\\"expirePasswordInMonths\\\":0},\\\"lockoutPolicy\\\":{\\\"lockoutPeriodSeconds\\\":300,\\\"lockoutAfterFailures\\\":5,\\\"countFailuresWithin\\\":3600},\\\"disableInternalUserManagement\\\":false}\",\n" +
            "    \"version\": 575,\n" +
            "    \"created\": 946684800000,\n" +
            "    \"active\": true,\n" +
            "    \"identityZoneId\": \"uaa\",\n" +
            "    \"last_modified\": 1447811837000\n" +
            "  }\n" +
            "]";
}
