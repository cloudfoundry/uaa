/*******************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2016] SAP SE. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.oauth.token;

import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.JTI;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.USER_TOKEN_REQUESTING_CLIENT_ID;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_SAML2_BEARER;
import static org.mockito.Matchers.anyString;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.security.oauth2.common.util.OAuth2Utils.CLIENT_ID;
import static org.springframework.security.oauth2.common.util.OAuth2Utils.GRANT_TYPE;

import java.io.ByteArrayInputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.io.UnsupportedEncodingException;
import java.security.Security;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.logging.LogFactory;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.oauth.DisallowedIdpException;
import org.cloudfoundry.identity.uaa.oauth.UaaOauth2Authentication;
import org.cloudfoundry.identity.uaa.oauth.client.ClientConstants;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.saml.LoginSamlAuthenticationProvider;
import org.cloudfoundry.identity.uaa.provider.saml.ZoneAwareMetadataGenerator;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UaaUserDatabase;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mockito.internal.util.reflection.Whitebox;
import org.opensaml.Configuration;
import org.opensaml.DefaultBootstrap;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.impl.AssertionMarshaller;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallerFactory;
import org.opensaml.xml.io.UnmarshallingException;
import org.opensaml.xml.parse.BasicParserPool;
import org.opensaml.xml.parse.XMLParserException;
import org.opensaml.xml.util.XMLHelper;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.DefaultOAuth2RefreshToken;
import org.springframework.security.oauth2.common.exceptions.InvalidClientException;
import org.springframework.security.oauth2.common.exceptions.InvalidGrantException;
import org.springframework.security.oauth2.common.exceptions.InvalidScopeException;
import org.springframework.security.oauth2.common.exceptions.UnauthorizedClientException;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.security.oauth2.provider.OAuth2RequestFactory;
import org.springframework.security.oauth2.provider.TokenRequest;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.security.oauth2.provider.token.AuthorizationServerTokenServices;
import org.springframework.security.saml.SAMLAuthenticationToken;
import org.springframework.security.saml.context.SAMLMessageContext;
import org.springframework.security.saml.metadata.MetadataGenerator;
import org.springframework.security.saml.metadata.MetadataManager;
import org.springframework.util.StringUtils;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

public class Saml2TokenGranterTest {
    private Saml2TokenGranter granter;
    private Saml2TokenGranter mockedgranter;
    private AuthorizationServerTokenServices tokenServices;
    private ClientDetailsService clientDetailsService;
    private OAuth2RequestFactory requestFactory;
    private UaaOauth2Authentication authentication;
    private TokenRequest tokenRequest;
    private UaaAuthentication userAuthentication;
    private Map<String,String> requestParameters;
    private BaseClientDetails requestingClient;
    private BaseClientDetails receivingClient;
    private BaseClientDetails passwordClient;
    private RevocableTokenProvisioning tokenStore;
    private LoginSamlAuthenticationProvider samlAuthenticationProvider;
    private IdentityProviderProvisioning identityProviderProvisioning;
    private ZoneAwareMetadataGenerator metazone;
    private MetadataManager metadata;
    private SAMLAuthenticationToken samltoken;
    private SAMLMessageContext samlcontext;
    private UaaUserDatabase uaaUserDatabase = mock(UaaUserDatabase.class);
    private final String samlAssertion = new String(
                      "PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz48c2FtbDI6QXNzZXJ0aW9uIHhtbG5zOnNhbWwyPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA" +
                      "6YXNzZXJ0aW9uIiBJRD0iXzhiNTNhMWUyLWU2MWItNGFmYi1iNThkLThlZDcxZGFjMGVlMCIgSXNzdWVJbnN0YW50PSIyMDE2LTEwLTI0VDEzOjU2OjI0LjE1MFoiIF" +
                      "ZlcnNpb249IjIuMCI-PHNhbWwyOklzc3Vlcj5yZW1vdGUuaWRwLm9yZzwvc2FtbDI6SXNzdWVyPjxzYW1sMjpTdWJqZWN0PjxzYW1sMjpOYW1lSUQgRm9ybWF0PSJ1c" +
                      "m46b2FzaXM6bmFtZXM6dGM6U0FNTDoxLjE6bmFtZWlkLWZvcm1hdDp1bnNwZWNpZmllZCI-VW5pdFRlc3RUZXN0VXNlcjwvc2FtbDI6TmFtZUlEPjxzYW1sMjpTdWJq" +
                      "ZWN0Q29uZmlybWF0aW9uIE1ldGhvZD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmNtOmJlYXJlciI-PHNhbWwyOlN1YmplY3RDb25maXJtYXRpb25EYXRhIE5" +
                      "vdE9uT3JBZnRlcj0iMjAxNi0xMC0yNFQxODowMToyNC4xODRaIiBSZWNpcGllbnQ9Imh0dHA6Ly9sb2NhbGhvc3Q6ODA4MC91YWEvb2F1dGgvdG9rZW4iLz48L3NhbW" +
                      "wyOlN1YmplY3RDb25maXJtYXRpb24-PC9zYW1sMjpTdWJqZWN0PjxzYW1sMjpDb25kaXRpb25zIE5vdEJlZm9yZT0iMjAxNi0xMC0yNFQxMzo1NjoyNC4xNTBaIiBOb" +
                      "3RPbk9yQWZ0ZXI9IjIwMTYtMTAtMjRUMTg6MDE6MjQuMTg0WiI-PHNhbWwyOkF1ZGllbmNlUmVzdHJpY3Rpb24-PHNhbWwyOkF1ZGllbmNlPmh0dHA6Ly9sb2NhbGhv" +
                      "c3Q6ODA4MC91YWEvb2F1dGgvdG9rZW48L3NhbWwyOkF1ZGllbmNlPjwvc2FtbDI6QXVkaWVuY2VSZXN0cmljdGlvbj48L3NhbWwyOkNvbmRpdGlvbnM-PHNhbWwyOkF" +
                      "0dHJpYnV0ZVN0YXRlbWVudD48c2FtbDI6QXR0cmlidXRlIE5hbWU9Ikdyb3VwcyI-PHNhbWwyOkF0dHJpYnV0ZVZhbHVlIHhtbG5zOnhzPSJodHRwOi8vd3d3LnczLm" +
                      "9yZy8yMDAxL1hNTFNjaGVtYSIgeG1sbnM6eHNpPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxL1hNTFNjaGVtYS1pbnN0YW5jZSIgeHNpOnR5cGU9InhzOnN0cmluZyI-Y" +
                      "2xpZW50LndyaXRlPC9zYW1sMjpBdHRyaWJ1dGVWYWx1ZT48c2FtbDI6QXR0cmlidXRlVmFsdWUgeG1sbnM6eHM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvWE1MU2No" +
                      "ZW1hIiB4bWxuczp4c2k9Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvWE1MU2NoZW1hLWluc3RhbmNlIiB4c2k6dHlwZT0ieHM6c3RyaW5nIj5jbGllbnQucmVhZDwvc2F" +
                      "tbDI6QXR0cmlidXRlVmFsdWU-PC9zYW1sMjpBdHRyaWJ1dGU-PC9zYW1sMjpBdHRyaWJ1dGVTdGF0ZW1lbnQ-PHNhbWwyOkF1dGhuU3RhdGVtZW50IEF1dGhuSW5zdG" +
                      "FudD0iMjAxNi0xMC0yNFQxNDowMToyNC4xODZaIiBTZXNzaW9uTm90T25PckFmdGVyPSIyMDE2LTEwLTI0VDE0OjA2OjI0LjE4NloiPjxzYW1sMjpBdXRobkNvbnRle" +
                      "HQ-PHNhbWwyOkF1dGhuQ29udGV4dENsYXNzUmVmPnVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphYzpjbGFzc2VzOlBhc3N3b3JkPC9zYW1sMjpBdXRobkNvbnRl" +
                      "eHRDbGFzc1JlZj48L3NhbWwyOkF1dGhuQ29udGV4dD48L3NhbWwyOkF1dGhuU3RhdGVtZW50Pjwvc2FtbDI6QXNzZXJ0aW9uPg");

    private final String metaDataXml = new String("<?xml version=\"1.0\" encoding=\"UTF-8\"?><ns3:EntityDescriptor " +
                      "xmlns:ns3=\"urn:oasis:names:tc:SAML:2.0:metadata\" xmlns=\"http://www.w3.org/2000/09/xmldsig#\" "+
                      "xmlns:ns2=\"http://www.w3.org/2001/04/xmlenc#\" xmlns:ns4=\"urn:oasis:names:tc:SAML:2.0:assertion\" " + 
                      "ID=\"S1c2972ba-759b-4970-a58d-f8d3323116e2\" entityID=\"remote.idp.org\"><ns3:IDPSSODescriptor WantAuthnRequestsSigned=\"true\" " +
                      "protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\"><ns3:KeyDescriptor use=\"signing\">" +
                      "<KeyInfo><KeyName>remote.idp.org</KeyName><X509Data><X509Certificate>" +
                      "MIIDHDCCAgSgAwIBAQIGAUpdkp0GMA0GCSqGSIb3DQEBBQUAME0xCzAJBgNVBAYTAkRFMQ8wDQYDVQQKEwZTQVAtU0UxLTArBgNVBAMTJHhz"+
                      "MnNlY3VyaXR5LmFjY291bnRzNDAwLm9uZGVtYW5kLmNvbTAeFw0xNDEyMTgxMzI0NTdaFw0yNDEyMTgxMzI0NTdaME0xCzAJBgNVBAYTAkRFM"+
                      "Q8wDQYDVQQKEwZTQVAtU0UxLTArBgNVBAMTJHhzMnNlY3VyaXR5LmFjY291bnRzNDAwLm9uZGVtYW5kLmNvbTCCASIwDQYJKoZIhvcNAQEBBQAD"+
                      "ggEPADCCAQoCggEBAI/V7202K97l25KwDNdM0Jjl5LeBmo/kimR2zitcv3iHb62YHvy3kilSIHHumbQuW+xdx3ydUwD8tpAkn7rEPj9e3oJepGuvp"+
                      "DLz4Q5bVp7q4AIH4wz57ejXJB8Wnbrey//rPZHdi/OBjvj8573Bxm3PJ7U47ZYC5sQ6voGYAiSiaoVjNzWIn1JC220E/nOHSupsvibTcrsntn3d"+
                      "nEfxuyEBNVK2Zu86rvQ7bYzeQPkdXi2JrU7kwt8Uh0Qi1ZLOjssyI81z9U3MsV1L28GVg+i6U4nXGqc7UXMHJDvwCR7M7QL7QtobD25dN5Ss5aB6"+
                      "kHkUhFlc0XILSuVYkcXB+1UCAwEAAYICAAAwDQYJKoZIhvcNAQEFBQADggEBAHHGlywA6IPX+aIObj/2ukNoXkN1XFr/TRBUhzCwyr+gvHQ2rC0m"+
                      "nWYxce1vOgkPLAtu+fQYGZInuVCnkNZUdlqlvHzF/pPVMlRK01wy+LBwsVhJlklU1rfw3cw0KhoCWx6mUc5RG/+wNKA/VNxz5yhueKt/u19IYUR56"+
                      "2zMbvQAct7wzuqZbT7B6NMdhhsi2iltj8X0sF26a4g+ZGMsdTVjcMwI3j2o0HHQgESBEIF9rCs4gQV6+FLwqX75nEP/mvQEoJMz92XFzo43RsTRvu"+
                      "yAMnkF2H2YxBYAN5fhYfXq+fQc90ejhyIj1AYkfEFFXmFtU/J9wbLhsj5bnrSEYCs=" +
                      "</X509Certificate></X509Data></KeyInfo></ns3:KeyDescriptor><ns3:KeyDescriptor use=\"encryption\"><KeyInfo><KeyName>" +
                      "remote.idp.org</KeyName><X509Data><X509Certificate>MIIDHDCCAgSgAwIBAQIGAUpdkp0GMA0GCSqGSIb3DQEBBQUAME0xCzAJBgNVBAYT"+
                      "AkRFMQ8wDQYDVQQKEwZTQVAtU0UxLTArBgNVBAMTJHhzMnNlY3VyaXR5LmFjY291bnRzNDAwLm9uZGVtYW5kLmNvbTAeFw0xNDEyMTgxMzI0NTdaFw0"+
                      "yNDEyMTgxMzI0NTdaME0xCzAJBgNVBAYTAkRFMQ8wDQYDVQQKEwZTQVAtU0UxLTArBgNVBAMTJHhzMnNlY3VyaXR5LmFjY291bnRzNDAwLm9uZGVtYW"+
                      "5kLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAI/V7202K97l25KwDNdM0Jjl5LeBmo/kimR2zitcv3iHb62YHvy3kilSIHHumbQuW+"+
                      "xdx3ydUwD8tpAkn7rEPj9e3oJepGuvpDLz4Q5bVp7q4AIH4wz57ejXJB8Wnbrey//rPZHdi/OBjvj8573Bxm3PJ7U47ZYC5sQ6voGYAiSiaoVjNzWIn1"+
                      "JC220E/nOHSupsvibTcrsntn3dnEfxuyEBNVK2Zu86rvQ7bYzeQPkdXi2JrU7kwt8Uh0Qi1ZLOjssyI81z9U3MsV1L28GVg+i6U4nXGqc7UXMHJDvwCR7"+
                      "M7QL7QtobD25dN5Ss5aB6kHkUhFlc0XILSuVYkcXB+1UCAwEAAYICAAAwDQYJKoZIhvcNAQEFBQADggEBAHHGlywA6IPX+aIObj/2ukNoXkN1XFr/TRBUh"+
                      "zCwyr+gvHQ2rC0mnWYxce1vOgkPLAtu+fQYGZInuVCnkNZUdlqlvHzF/pPVMlRK01wy+LBwsVhJlklU1rfw3cw0KhoCWx6mUc5RG/+wNKA/VNxz5yhueKt"+
                      "/u19IYUR562zMbvQAct7wzuqZbT7B6NMdhhsi2iltj8X0sF26a4g+ZGMsdTVjcMwI3j2o0HHQgESBEIF9rCs4gQV6+FLwqX75nEP/mvQEoJMz92XFzo4"+
                      "3RsTRvuyAMnkF2H2YxBYAN5fhYfXq+fQc90ejhyIj1AYkfEFFXmFtU/J9wbLhsj5bnrSEYCs=</X509Certificate>" +
                      "</X509Data></KeyInfo></ns3:KeyDescriptor><ns3:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" "+
                      "Location=\"https://remote.idp.org/saml2/idp/slo/remote.idp.org\"/><ns3:SingleLogoutService "+
                      "Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"https://remote.idp.org/saml2/idp/slo/remote.idp.org\"/>"+
                      "<ns3:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" "+
                      "Location=\"https://remote.idp.org/saml2/idp/sso/remote.idp.org\"/><ns3:SingleSignOnService "+
                      "Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"https://remote.idp.org/saml2/idp/sso/remote.idp.org\"/>"+
                      "</ns3:IDPSSODescriptor><ns3:SPSSODescriptor AuthnRequestsSigned=\"true\" "+
                      "protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\">"+
                      "<ns3:KeyDescriptor use=\"signing\"><KeyInfo><KeyName>remote.idp.org</KeyName><X509Data"+
                      "><X509Certificate>MIIDHDCCAgSgAwIBAQIGAUpdkp0GMA0GCSqGSIb3DQEBBQUAME0xCzAJBgNVBAYTAkRFMQ8wDQYDVQQKEwZTQVAtU0UxLTArBgNVB"+
                      "AMTJHhzMnNlY3VyaXR5LmFjY291bnRzNDAwLm9uZGVtYW5kLmNvbTAeFw0xNDEyMTgxMzI0NTdaFw0yNDEyMTgxMzI0NTdaME0xCzAJBgNVBAYTAkRFMQ8wDQ"+
                      "YDVQQKEwZTQVAtU0UxLTArBgNVBAMTJHhzMnNlY3VyaXR5LmFjY291bnRzNDAwLm9uZGVtYW5kLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggE"+
                      "BAI/V7202K97l25KwDNdM0Jjl5LeBmo/kimR2zitcv3iHb62YHvy3kilSIHHumbQuW+xdx3ydUwD8tpAkn7rEPj9e3oJepGuvpDLz4Q5bVp7q4AIH4wz57ejXJ"+
                      "B8Wnbrey//rPZHdi/OBjvj8573Bxm3PJ7U47ZYC5sQ6voGYAiSiaoVjNzWIn1JC220E/nOHSupsvibTcrsntn3dnEfxuyEBNVK2Zu86rvQ7bYzeQPkdXi2JrU7k"+
                      "wt8Uh0Qi1ZLOjssyI81z9U3MsV1L28GVg+i6U4nXGqc7UXMHJDvwCR7M7QL7QtobD25dN5Ss5aB6kHkUhFlc0XILSuVYkcXB+1UCAwEAAYICAAAwDQYJKoZIhvcN"+
                      "AQEFBQADggEBAHHGlywA6IPX+aIObj/2ukNoXkN1XFr/TRBUhzCwyr+gvHQ2rC0mnWYxce1vOgkPLAtu+fQYGZInuVCnkNZUdlqlvHzF/pPVMlRK01wy+LBwsVhJl"+
                      "klU1rfw3cw0KhoCWx6mUc5RG/+wNKA/VNxz5yhueKt/u19IYUR562zMbvQAct7wzuqZbT7B6NMdhhsi2iltj8X0sF26a4g+ZGMsdTVjcMwI3j2o0HHQgESBEIF9r"+
                      "Cs4gQV6+FLwqX75nEP/mvQEoJMz92XFzo43RsTRvuyAMnkF2H2YxBYAN5fhYfXq+fQc90ejhyIj1AYkfEFFXmFtU/J9wbLhsj5bnrSEYCs=</X509Certificate>"+
                      "</X509Data></KeyInfo></ns3:KeyDescriptor><ns3:KeyDescriptor use=\"encryption\"><KeyInfo><KeyName>remote.idp.org</KeyName>"+
                      "<X509Data><X509Certificate>MIIDHDCCAgSgAwIBAQIGAUpdkp0GMA0GCSqGSIb3DQEBBQUAME0xCzAJBgNVBAYTAkRFMQ8wDQYDVQQKEwZTQVAtU0UxL"+
                      "TArBgNVBAMTJHhzMnNlY3VyaXR5LmFjY291bnRzNDAwLm9uZGVtYW5kLmNvbTAeFw0xNDEyMTgxMzI0NTdaFw0yNDEyMTgxMzI0NTdaME0xCzAJBgNVBAYTA"+
                      "kRFMQ8wDQYDVQQKEwZTQVAtU0UxLTArBgNVBAMTJHhzMnNlY3VyaXR5LmFjY291bnRzNDAwLm9uZGVtYW5kLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPAD"+
                      "CCAQoCggEBAI/V7202K97l25KwDNdM0Jjl5LeBmo/kimR2zitcv3iHb62YHvy3kilSIHHumbQuW+xdx3ydUwD8tpAkn7rEPj9e3oJepGuvpDLz4Q5bVp7q4AI"+
                      "H4wz57ejXJB8Wnbrey//rPZHdi/OBjvj8573Bxm3PJ7U47ZYC5sQ6voGYAiSiaoVjNzWIn1JC220E/nOHSupsvibTcrsntn3dnEfxuyEBNVK2Zu86rvQ7bYze"+
                      "QPkdXi2JrU7kwt8Uh0Qi1ZLOjssyI81z9U3MsV1L28GVg+i6U4nXGqc7UXMHJDvwCR7M7QL7QtobD25dN5Ss5aB6kHkUhFlc0XILSuVYkcXB+1UCAwEAAYICA"+
                      "AAwDQYJKoZIhvcNAQEFBQADggEBAHHGlywA6IPX+aIObj/2ukNoXkN1XFr/TRBUhzCwyr+gvHQ2rC0mnWYxce1vOgkPLAtu+fQYGZInuVCnkNZUdlqlvHzF/pP"+
                      "VMlRK01wy+LBwsVhJlklU1rfw3cw0KhoCWx6mUc5RG/+wNKA/VNxz5yhueKt/u19IYUR562zMbvQAct7wzuqZbT7B6NMdhhsi2iltj8X0sF26a4g+ZGMsdTVjc"+
                      "MwI3j2o0HHQgESBEIF9rCs4gQV6+FLwqX75nEP/mvQEoJMz92XFzo43RsTRvuyAMnkF2H2YxBYAN5fhYfXq+fQc90ejhyIj1AYkfEFFXmFtU/J9wbLhsj5bnr"+
                      "SEYCs=</X509Certificate></X509Data></KeyInfo></ns3:KeyDescriptor><ns3:SingleLogoutService "+
                      "Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"https://remote.idp.org/saml2/idp/slo/remote.idp.org\"/>"+
                      "<ns3:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" "+
                      "Location=\"https://remote.idp.org/saml2/idp/slo/remote.idp.org\"/><ns3:AssertionConsumerService "+
                      "Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"https://remote.idp.org/saml2/idp/acs/remote.idp.org\" "+
                      "index=\"0\" isDefault=\"true\"/></ns3:SPSSODescriptor></ns3:EntityDescriptor>");

    private final String invalidMetaDataXml = new String("<?xml version=\"1.0\" encoding=\"UTF-8\"?><ns3:EntityDescriptor " +
            "xmlns:ns3=\"urn:oasis:names:tc:SAML:2.0:metadata\" xmlns=\"http://www.w3.org/2000/09/xmldsig#\" "+
            "xmlns:ns2=\"http://www.w3.org/2001/04/xmlenc#\" xmlns:ns4=\"urn:oasis:names:tc:SAML:2.0:assertion\" " + 
            "ID=\"S1c2972ba-759b-4970-a58d-f8d3323116e2\" entityID=\"remote.idp.org\"><ns3:IDPSSODescriptor WantAuthnRequestsSigned=\"true\" " +
            "protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\"><ns3:KeyDescriptor use=\"signing\">" +
            "<KeyInfo><KeyName>remote.idp.org</KeyName><X509Data><X509Certificate>" +
            "</X509Certificate></X509Data></KeyInfo></ns3:KeyDescriptor><ns3:KeyDescriptor use=\"encryption\"><KeyInfo><KeyName>" +
            "remote.idp.org</KeyName><X509Data><X509Certificate></X509Certificate>" +
            "</X509Data></KeyInfo></ns3:KeyDescriptor><ns3:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" "+
            "Location=\"https://remote.idp.org/saml2/idp/slo/remote.idp.org\"/><ns3:SingleLogoutService "+
            "Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"https://remote.idp.org/saml2/idp/slo/remote.idp.org\"/>"+
            "<ns3:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" "+
            "Location=\"https://remote.idp.org/saml2/idp/sso/remote.idp.org\"/><ns3:SingleSignOnService "+
            "Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"https://remote.idp.org/saml2/idp/sso/remote.idp.org\"/>"+
            "</ns3:IDPSSODescriptor><ns3:SPSSODescriptor AuthnRequestsSigned=\"true\" "+
            "protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\">"+
            "<ns3:KeyDescriptor use=\"signing\"><KeyInfo><KeyName>remote.idp.org</KeyName><X509Data"+
            "><X509Certificate></X509Certificate>"+
            "</X509Data></KeyInfo></ns3:KeyDescriptor><ns3:KeyDescriptor use=\"encryption\"><KeyInfo><KeyName>remote.idp.org</KeyName>"+
            "<X509Data><X509Certificate></X509Certificate></X509Data></KeyInfo></ns3:KeyDescriptor><ns3:SingleLogoutService "+
            "Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"https://remote.idp.org/saml2/idp/slo/remote.idp.org\"/>"+
            "<ns3:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" "+
            "Location=\"https://remote.idp.org/saml2/idp/slo/remote.idp.org\"/><ns3:AssertionConsumerService "+
            "Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"https://remote.idp.org/saml2/idp/acs/remote.idp.org\" "+
            "index=\"0\" isDefault=\"true\"/></ns3:SPSSODescriptor></ns3:EntityDescriptor>");

    private final String valid_plain_Assertion = new String("<?xml version=\"1.0\" encoding=\"UTF-8\"?>" +
            "<saml2:Assertion xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"_8b53a1e2-e61b-4afb-b58d-8ed71dac0ee0\" IssueInstant=\"2016-10-24T13:56:24.150Z\" Version=\"2.0\">" +
            "<saml2:Issuer>remote.idp.org</saml2:Issuer>" +
            "<saml2:Subject>" +
            "   <saml2:NameID Format=\"urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified\">UnitTestTestUser</saml2:NameID>" +
            "   <saml2:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\">" +
            "   <saml2:SubjectConfirmationData NotOnOrAfter=\"2016-10-24T18:01:24.184Z\" Recipient=\"http://localhost:8080/uaa/oauth/token\"/>" +
            "   </saml2:SubjectConfirmation>" +
            "</saml2:Subject>" +
            "<saml2:Conditions NotBefore=\"2016-10-24T13:56:24.150Z\" NotOnOrAfter=\"2016-10-24T18:01:24.184Z\">" +
            "   <saml2:AudienceRestriction>" +
            "   <saml2:Audience>http://localhost:8080/uaa/oauth/token</saml2:Audience>" +
            "   </saml2:AudienceRestriction>" +
            "</saml2:Conditions>" +
            "<saml2:AuthnStatement AuthnInstant=\"2016-10-24T14:01:24.186Z\" SessionNotOnOrAfter=\"2016-10-24T14:06:24.186Z\">" +
            "   <saml2:AuthnContext>" +
            "     <saml2:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml2:AuthnContextClassRef>" +
            "   </saml2:AuthnContext>" +
            "</saml2:AuthnStatement>" +
            "</saml2:Assertion>");

    @Before
    public void setup() {
        try { DefaultBootstrap.bootstrap();
        } catch (ConfigurationException e) { }
        tokenServices = mock(AuthorizationServerTokenServices.class);
        clientDetailsService = mock(ClientDetailsService.class);
        requestFactory = mock(OAuth2RequestFactory.class);
        authentication = mock(UaaOauth2Authentication.class);
        tokenStore = mock(RevocableTokenProvisioning.class);
        metazone = mock(ZoneAwareMetadataGenerator.class);
        metadata = mock(MetadataManager.class);
        samlcontext = mock(SAMLMessageContext.class);
        MockHttpServletRequest request = new MockHttpServletRequest();
        ServletRequestAttributes attrs = new ServletRequestAttributes(request);
        RequestContextHolder.setRequestAttributes(attrs);
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        samlAuthenticationProvider = mock(LoginSamlAuthenticationProvider.class);
        identityProviderProvisioning = mock(IdentityProviderProvisioning.class);

        userAuthentication = mock(UaaAuthentication.class);
        granter = new Saml2TokenGranter(
            tokenServices,
            clientDetailsService,
            requestFactory,
            tokenStore
        );
        EntityDescriptor s = getMetadata(metaDataXml);
        samltoken = new SAMLAuthenticationToken(samlcontext);
        metazone.setExtendedMetadata(new MetadataGenerator().generateExtendedMetadata());
        metadata.setDefaultExtendedMetadata(new MetadataGenerator().generateExtendedMetadata());
        metazone.setEntityId("remote.idp.org");
        granter.setMetadata(metadata);
        granter.setMetazone(metazone);
        try {
            when(metadata.getEntityDescriptor("remote.idp.org")).thenReturn(s);
            when(metadata.getEntityDescriptor((String)null)).thenReturn(s);
        } catch (MetadataProviderException e) { }
        granter.setSamlAuthenticationProvider(samlAuthenticationProvider);
        granter.setIdentityProviderProvisioning(identityProviderProvisioning);
        SecurityContextHolder.getContext().setAuthentication(authentication);

        requestingClient = new BaseClientDetails("requestingId",null,"uaa.user",GRANT_TYPE_SAML2_BEARER, null);
        receivingClient =  new BaseClientDetails("receivingId",null,"test.scope",GRANT_TYPE_SAML2_BEARER, null);
        passwordClient =  new BaseClientDetails("pwdId",null,"test.scope","password", null);
        when(clientDetailsService.loadClientByClientId(eq(requestingClient.getClientId()))).thenReturn(requestingClient);
        when(clientDetailsService.loadClientByClientId(eq(receivingClient.getClientId()))).thenReturn(receivingClient);
        requestParameters = new HashMap<>();
        requestParameters.put(USER_TOKEN_REQUESTING_CLIENT_ID, requestingClient.getClientId());
        requestParameters.put(GRANT_TYPE, GRANT_TYPE_SAML2_BEARER);
        requestParameters.put(CLIENT_ID, receivingClient.getClientId());
        requestParameters.put("assertion", samlAssertion);
        tokenRequest = new PublicTokenRequest();
        tokenRequest.setRequestParameters(requestParameters);
    }

    @After
    public void teardown() {
        SecurityContextHolder.clearContext();
    }

    @Test
    public void test_no_authentication() throws Exception {
        SecurityContextHolder.clearContext();
        granter.validateRequest(tokenRequest);
    }

    @Test
    public void test_not_authenticated() throws Exception {
        when(authentication.isAuthenticated()).thenReturn(false);
        granter.validateRequest(tokenRequest);
    }

    @Test
    public void test_not_a_user_authentication() throws Exception {
        when(authentication.isAuthenticated()).thenReturn(true);
        when(authentication.getUserAuthentication()).thenReturn(null);
        granter.validateRequest(tokenRequest);
    }

    @Test(expected = InvalidGrantException.class)
    public void test_no_grant_type() throws Exception {
        missing_parameter(GRANT_TYPE);
    }

    @Test(expected = InvalidGrantException.class)
    public void test_requesting_assertion_missing() throws Exception {
        missing_parameter("assertion");
    }

    @Test(expected = InvalidClientException.class)
    public void test_wrong_requesting_grant_type() {
        granter.validateGrantType("password", requestingClient);
        missing_parameter("non existent");
    }

    @Test(expected = InvalidClientException.class)
    public void test_wrong_receiving_grant_type() {
        granter.validateGrantType("password", receivingClient);
    }

    @Test(expected = InvalidClientException.class)
    public void test_wrong_client_grant_type() {
        granter.validateGrantType(GRANT_TYPE_SAML2_BEARER, passwordClient);
    }

    public void test_valid_grant_type() {
        granter.validateGrantType(GRANT_TYPE_SAML2_BEARER, receivingClient);
        missing_parameter("non existent");
    }

    @Test
    public void test_ensure_that_access_token_is_deleted_and_modified() {
        String tokenId = "access_token";
        DefaultOAuth2AccessToken token = new DefaultOAuth2AccessToken(tokenId);
        DefaultOAuth2RefreshToken refreshToken = new DefaultOAuth2RefreshToken("refresh_token");
        Map<String,Object> info = new HashMap(token.getAdditionalInformation());
        info.put(JTI, token.getValue());
        token.setAdditionalInformation(info);
        token.setRefreshToken(refreshToken);
        token.setExpiration(new Date());
    }

    @Test
    public void test_getAccessToken() {
        Collection me = AuthorityUtils.commaSeparatedStringToAuthorityList("openid,foo.bar,uaa.user,one.read");
        OAuth2Request myReq = new OAuth2Request(requestParameters, receivingClient.getClientId(), receivingClient.getAuthorities(), true, receivingClient.getScope(), receivingClient.getResourceIds(), null, null, null);
        requestingClient.setScope(StringUtils.commaDelimitedListToSet("openid,foo.bar"));
        when(userAuthentication.getAuthorities()).thenReturn(me);
        tokenRequest.setClientId(receivingClient.getClientId());
        when(authentication.isAuthenticated()).thenReturn(true);
        when(authentication.getUserAuthentication()).thenReturn(null);
        when(authentication.getUserAuthentication()).thenReturn(userAuthentication);
        when(userAuthentication.isAuthenticated()).thenReturn(true);
        when(samlAuthenticationProvider.authenticate(null)).thenReturn(userAuthentication);
        when(requestFactory.createOAuth2Request(receivingClient, tokenRequest)).thenReturn(myReq);
        Whitebox.setInternalState(granter, "requestFactory", requestFactory);
        granter.getAccessToken(receivingClient, tokenRequest);
    }

    @Test
    public void test_grant() {
        tokenRequest.setGrantType(requestParameters.get(GRANT_TYPE));
        granter.grant(GRANT_TYPE, tokenRequest);
    }

    @Test(expected = InvalidClientException.class)
    public void test_not_provided_grant_type() {
        BaseClientDetails myClient = new BaseClientDetails("receivingId",null,"test.scope","password", null);
        granter.validateGrantType(GRANT_TYPE_SAML2_BEARER, myClient);
    }

    @Test(expected = InvalidGrantException.class)
    public void test_invalid_saml_assertion() {
        requestParameters.put("assertion", "hallo");
        missing_parameter("non existent");
    }

    @Test(expected = InsufficientAuthenticationException.class)
    public void test_empty_saml_assertion() {
        requestParameters.put("assertion", "");
        missing_parameter("non existent");
    }

    @Test(expected = InsufficientAuthenticationException.class)
    public void test_metadataexception() throws MetadataProviderException {
        when(metadata.getExtendedMetadata("remote.idp.org")).thenThrow(new MetadataProviderException());
        missing_parameter("non existent");
    }

    @Test(expected = InsufficientAuthenticationException.class)
    public void test_invalid_saml_provider() throws MetadataProviderException {
        granter.setSamlAuthenticationProvider(null);
        missing_parameter("non existent");
    }

    @Test(expected = UnauthorizedClientException.class)
    public void test_oauth2_authentication_with_invalid_allowed_provider() {
        OAuth2Request myReq = new OAuth2Request(requestParameters, receivingClient.getClientId(), receivingClient.getAuthorities(), true, receivingClient.getScope(), receivingClient.getResourceIds(), null, null, null);
        UaaUser user = new UaaUser("testid", "testuser","","test@test.org",AuthorityUtils.commaSeparatedStringToAuthorityList("foo.bar,spam.baz,space.1.developer,space.2.developer,space.1.admin"),"givenname", "familyname", null, null, OriginKeys.UAA, null, true, IdentityZone.getUaa().getId(), "testid", new Date());
        UaaPrincipal uaaPrincipal = new UaaPrincipal(user);
        when(uaaUserDatabase.retrieveUserById(anyString())).thenReturn(user);
        BaseClientDetails myClient = new BaseClientDetails(requestingClient);
        List<String> allowedProviders = new LinkedList<String>();
        allowedProviders.add("anyIDP");
        Map<String, Object> additionalInformation = new LinkedHashMap<String, Object>();
        Collection me = AuthorityUtils.commaSeparatedStringToAuthorityList("openid,foo.bar,uaa.user,one.read");
        //when(new DefaultSecurityContextAccessor()).thenReturn((DefaultSecurityContextAccessor) securityContextAccessor);
        mockedgranter = mock(Saml2TokenGranter.class);
        when(mockedgranter.validateRequest(tokenRequest)).thenReturn(userAuthentication);
        when(mockedgranter.getOAuth2Authentication((ClientDetails)myClient, (TokenRequest)tokenRequest)).thenCallRealMethod();
        myClient.setScope(StringUtils.commaDelimitedListToSet("openid,foo.bar"));
        additionalInformation.put(ClientConstants.ALLOWED_PROVIDERS, allowedProviders);
        myClient.setAdditionalInformation(additionalInformation);
        Whitebox.setInternalState(mockedgranter, "identityProviderProvisioning", identityProviderProvisioning);
        when(userAuthentication.getAuthorities()).thenReturn(me);
        when(requestFactory.createOAuth2Request(receivingClient, tokenRequest)).thenReturn(myReq);
        when(userAuthentication.getPrincipal()).thenReturn(uaaPrincipal);
        when(identityProviderProvisioning.retrieveByOrigin("uaa","uaa")).thenThrow(new EmptyResultDataAccessException(0));
        mockedgranter.getOAuth2Authentication((ClientDetails)myClient, (TokenRequest)tokenRequest);
    }

    @Test(expected = DisallowedIdpException.class)
    public void test_oauth2_authentication_with_disallowed_provider() {
        OAuth2Request myReq = new OAuth2Request(requestParameters, receivingClient.getClientId(), receivingClient.getAuthorities(), true, receivingClient.getScope(), receivingClient.getResourceIds(), null, null, null);
        UaaUser user = new UaaUser("testid", "testuser","","test@test.org",AuthorityUtils.commaSeparatedStringToAuthorityList("foo.bar,spam.baz,space.1.developer,space.2.developer,space.1.admin"),"givenname", "familyname", null, null, OriginKeys.UAA, null, true, IdentityZone.getUaa().getId(), "testid", new Date());
        UaaPrincipal uaaPrincipal = new UaaPrincipal(user);
        when(uaaUserDatabase.retrieveUserById(anyString())).thenReturn(user);
        BaseClientDetails myClient = new BaseClientDetails(requestingClient);
        List<String> allowedProviders = new LinkedList<String>();
        allowedProviders.add("anyIDP");
        Map<String, Object> additionalInformation = new LinkedHashMap<String, Object>();
        Collection me = AuthorityUtils.commaSeparatedStringToAuthorityList("openid,foo.bar,uaa.user,one.read");
        //when(new DefaultSecurityContextAccessor()).thenReturn((DefaultSecurityContextAccessor) securityContextAccessor);
        mockedgranter = mock(Saml2TokenGranter.class);
        when(mockedgranter.validateRequest(tokenRequest)).thenReturn(userAuthentication);
        when(mockedgranter.getOAuth2Authentication((ClientDetails)myClient, (TokenRequest)tokenRequest)).thenCallRealMethod();
        myClient.setScope(StringUtils.commaDelimitedListToSet("openid,foo.bar"));
        additionalInformation.put(ClientConstants.ALLOWED_PROVIDERS, allowedProviders);
        myClient.setAdditionalInformation(additionalInformation);
        Whitebox.setInternalState(mockedgranter, "identityProviderProvisioning", identityProviderProvisioning);
        when(userAuthentication.getAuthorities()).thenReturn(me);
        when(requestFactory.createOAuth2Request(receivingClient, tokenRequest)).thenReturn(myReq);
        when(userAuthentication.getPrincipal()).thenReturn(uaaPrincipal);
        //when(identityProviderProvisioning.retrieveByOrigin("uaa","uaa")).thenThrow(new EmptyResultDataAccessException(0));
        mockedgranter.getOAuth2Authentication((ClientDetails)myClient, (TokenRequest)tokenRequest);
    }

    @Test(expected = UnauthorizedClientException.class)
    public void test_oauth2_authentication_with_empty_allowed() {
        OAuth2Request myReq = new OAuth2Request(requestParameters, receivingClient.getClientId(), receivingClient.getAuthorities(), true, receivingClient.getScope(), receivingClient.getResourceIds(), null, null, null);
        BaseClientDetails myClient = new BaseClientDetails(requestingClient);
        List<String> allowedProviders = new LinkedList<String>();
        Map<String, Object> additionalInformation = new LinkedHashMap<String, Object>();
        Collection me = AuthorityUtils.commaSeparatedStringToAuthorityList("openid,foo.bar,uaa.user,one.read");
        //when(new DefaultSecurityContextAccessor()).thenReturn((DefaultSecurityContextAccessor) securityContextAccessor);
        mockedgranter = mock(Saml2TokenGranter.class);
        when(mockedgranter.validateRequest(tokenRequest)).thenReturn(userAuthentication);
        when(mockedgranter.getOAuth2Authentication((ClientDetails)myClient, (TokenRequest)tokenRequest)).thenCallRealMethod();
        myClient.setScope(StringUtils.commaDelimitedListToSet("openid,foo.bar"));
        additionalInformation.put(ClientConstants.ALLOWED_PROVIDERS, allowedProviders);
        myClient.setAdditionalInformation(additionalInformation);
        when(userAuthentication.getAuthorities()).thenReturn(me);
        when(requestFactory.createOAuth2Request(receivingClient, tokenRequest)).thenReturn(myReq);
        mockedgranter.getOAuth2Authentication((ClientDetails)myClient, (TokenRequest)tokenRequest);
    }

    @Test(expected = InvalidScopeException.class)
    public void test_oauth2_authentication_with_empty_scope_list() {
        Collection me = AuthorityUtils.commaSeparatedStringToAuthorityList("");
        //when(new DefaultSecurityContextAccessor()).thenReturn((DefaultSecurityContextAccessor) securityContextAccessor);
        mockedgranter = mock(Saml2TokenGranter.class);
        when(mockedgranter.validateRequest(tokenRequest)).thenReturn(userAuthentication);
        when(mockedgranter.getOAuth2Authentication((ClientDetails)requestingClient, (TokenRequest)tokenRequest)).thenCallRealMethod();
        requestingClient.setScope(StringUtils.commaDelimitedListToSet("openid,foo.bar"));
        when(userAuthentication.getAuthorities()).thenReturn(me);
        when(mockedgranter.getRequestFactory()).thenReturn(requestFactory);
        Whitebox.setInternalState(mockedgranter, "scopeToResource", Collections.singletonMap("openid", "openid"));
        Whitebox.setInternalState(mockedgranter, "scopeSeparator", ".");
        mockedgranter.getOAuth2Authentication((ClientDetails)requestingClient, (TokenRequest)tokenRequest);
    }

    @Test
    public void test_oauth2_authentication() {
        Collection me = AuthorityUtils.commaSeparatedStringToAuthorityList("openid,foo.bar,uaa.user,one.read");
        //when(new DefaultSecurityContextAccessor()).thenReturn((DefaultSecurityContextAccessor) securityContextAccessor);
        mockedgranter = mock(Saml2TokenGranter.class);
        when(mockedgranter.validateRequest(tokenRequest)).thenReturn(userAuthentication);
        when(mockedgranter.getOAuth2Authentication((ClientDetails)requestingClient, (TokenRequest)tokenRequest)).thenCallRealMethod();
        requestingClient.setScope(StringUtils.commaDelimitedListToSet("openid,foo.bar"));
        when(userAuthentication.getAuthorities()).thenReturn(me);
        when(mockedgranter.getRequestFactory()).thenReturn(requestFactory);
        Whitebox.setInternalState(mockedgranter, "scopeToResource", Collections.singletonMap("openid", "openid"));
        Whitebox.setInternalState(mockedgranter, "scopeSeparator", ".");
        Logger.getLogger(Saml2TokenGranter.class).setLevel(Level.DEBUG);
        Whitebox.setInternalState(mockedgranter, "logger", LogFactory.getLog(Saml2TokenGranter.class));
        mockedgranter.getOAuth2Authentication((ClientDetails)requestingClient, (TokenRequest)tokenRequest);
    }

    @Test(expected = InsufficientAuthenticationException.class)
    public void test_invalid_idp() {
        EntityDescriptor s = getMetadata(invalidMetaDataXml);
        try {
            when(metadata.getEntityDescriptor("remote.idp.org")).thenReturn(s);
            when(metadata.getEntityDescriptor((String)null)).thenReturn(s);
        } catch (MetadataProviderException e) { }
        missing_parameter("non existent");
    }

    @Test(expected = InvalidGrantException.class)
    public void test_missing_token_Request() {
        granter.validateRequest(null);
    }

    @Test
    public void test_valid_from_xml() throws UnsupportedEncodingException {
        validate_assertion(valid_plain_Assertion);
    }

    @Test(expected = InsufficientAuthenticationException.class)
    public void test_invalid_from_xml() throws UnsupportedEncodingException {
        Assertion _assertion = getAssertion(valid_plain_Assertion);
        _assertion.getIssuer().setValue("");
        validate_assertion(getAssertionXml(_assertion));
    }

    @Test
    public void happy_day() {
        missing_parameter("non existent");
    }

    public void validate_assertion(String xmlAssertion) throws UnsupportedEncodingException {
        String samlAssertionB64Url = Base64.encodeBase64URLSafeString(xmlAssertion.getBytes("utf-8"));
        requestParameters.put("assertion", samlAssertionB64Url);
        missing_parameter("non existent");
    }

    protected void missing_parameter(String parameter) {
        tokenRequest.setClientId(receivingClient.getClientId());
        when(authentication.isAuthenticated()).thenReturn(true);
        when(authentication.getUserAuthentication()).thenReturn(null);
        when(authentication.getUserAuthentication()).thenReturn(userAuthentication);
        when(userAuthentication.isAuthenticated()).thenReturn(true);
        when(samlAuthenticationProvider.authenticate(null)).thenReturn(userAuthentication);
        requestParameters.remove(parameter);
        tokenRequest.setGrantType(requestParameters.get(GRANT_TYPE));
        granter.validateRequest(tokenRequest);
    }

    public static class PublicTokenRequest extends TokenRequest {
        public PublicTokenRequest() {
        }
    }

    EntityDescriptor getMetadata(String xml) {
       try {
           return (EntityDescriptor)unmarshallObject(xml);
       } catch(Exception e) {
       }
       return null;
    }

    Assertion getAssertion(String xml) {
        try {
            return (Assertion)unmarshallObject(xml);
        } catch(Exception e) {
        }
        return null;
    }

    String getAssertionXml(Assertion assertion) {
        try {
            AssertionMarshaller marshaller = new AssertionMarshaller();
            Element plaintextElement = marshaller.marshall(assertion);
            String serializedElement = XMLHelper.nodeToString(plaintextElement);
            return serializedElement;
        } catch(Exception e) {
        }
        return null;
    }

	/*
	 * Unmarshall XML string to OpenSAML XMLObject
	 */
	private XMLObject unmarshallObject(String xmlString) throws UnmarshallingException, XMLParserException, UnsupportedEncodingException {
		BasicParserPool parser = new BasicParserPool();
		parser.setNamespaceAware(true);
		/* Base64URL encoded */ 
		byte bytes[] = xmlString.getBytes("utf-8");
		if (bytes == null || bytes.length == 0)
			throw new InsufficientAuthenticationException("Invalid assertion encoding");
		Reader reader = new InputStreamReader(new ByteArrayInputStream(bytes));
		Document doc = parser.parse(reader);
		Element samlElement = doc.getDocumentElement();

		UnmarshallerFactory unmarshallerFactory = Configuration.getUnmarshallerFactory();
		Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(samlElement);
		if (unmarshaller == null) {
			throw new InsufficientAuthenticationException("Failed to unmarshal assertion string");
		}
		return unmarshaller.unmarshall(samlElement);
	}

}
