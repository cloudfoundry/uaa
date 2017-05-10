/*
 * *****************************************************************************
 *      Cloud Foundry
 *      Copyright (c) [2009-2015] Pivotal Software, Inc. All Rights Reserved.
 *      This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *      You may not use this product except in compliance with the License.
 *
 *      This product includes a number of subcomponents with
 *      separate copyright notices and license terms. Your use of these
 *      subcomponents is subject to the terms and conditions of the
 *      subcomponent's license, as noted in the LICENSE file.
 * *****************************************************************************
 */

package org.cloudfoundry.identity.uaa.provider.saml;

import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.manager.AuthEvent;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.JdbcIdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.SamlIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.resources.jdbc.JdbcPagingListFactory;
import org.cloudfoundry.identity.uaa.scim.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.ScimGroupProvisioning;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.scim.bootstrap.ScimUserBootstrap;
import org.cloudfoundry.identity.uaa.scim.jdbc.JdbcScimGroupExternalMembershipManager;
import org.cloudfoundry.identity.uaa.scim.jdbc.JdbcScimGroupMembershipManager;
import org.cloudfoundry.identity.uaa.scim.jdbc.JdbcScimGroupProvisioning;
import org.cloudfoundry.identity.uaa.scim.jdbc.JdbcScimUserProvisioning;
import org.cloudfoundry.identity.uaa.test.JdbcTestBase;
import org.cloudfoundry.identity.uaa.user.JdbcUaaUserDatabase;
import org.cloudfoundry.identity.uaa.user.UaaAuthority;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UserInfo;
import org.cloudfoundry.identity.uaa.util.TimeService;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.joda.time.DateTime;
import org.junit.Before;
import org.junit.Test;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AuthnContext;
import org.opensaml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml2.core.AuthnStatement;
import org.opensaml.saml2.core.NameID;
import org.opensaml.ws.wsaddressing.impl.AttributedURIImpl;
import org.opensaml.ws.wssecurity.impl.AttributedStringImpl;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.schema.XSBooleanValue;
import org.opensaml.xml.schema.impl.XSAnyImpl;
import org.opensaml.xml.schema.impl.XSBase64BinaryImpl;
import org.opensaml.xml.schema.impl.XSBooleanImpl;
import org.opensaml.xml.schema.impl.XSDateTimeImpl;
import org.opensaml.xml.schema.impl.XSIntegerImpl;
import org.opensaml.xml.schema.impl.XSQNameImpl;
import org.opensaml.xml.schema.impl.XSURIImpl;
import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.dao.IncorrectResultSizeDataAccessException;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.saml.SAMLAuthenticationToken;
import org.springframework.security.saml.SAMLConstants;
import org.springframework.security.saml.SAMLCredential;
import org.springframework.security.saml.context.SAMLMessageContext;
import org.springframework.security.saml.log.SAMLLogger;
import org.springframework.security.saml.metadata.ExtendedMetadata;
import org.springframework.security.saml.websso.WebSSOProfileConsumer;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import javax.xml.namespace.QName;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import static org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition.GROUP_ATTRIBUTE_NAME;
import static org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition.USER_ATTRIBUTE_PREFIX;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.not;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.mockito.Matchers.anyObject;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class LoginSamlAuthenticationProviderTests extends JdbcTestBase {

    public static final String SAML_USER = "saml.user";
    public static final String SAML_ADMIN = "saml.admin";
    public static final String SAML_TEST = "saml.test";
    public static final String SAML_NOT_MAPPED = "saml.unmapped";
    public static final String UAA_SAML_USER = "uaa.saml.user";
    public static final String UAA_SAML_ADMIN = "uaa.saml.admin";
    public static final String UAA_SAML_TEST = "uaa.saml.test";

    public static final String COST_CENTER = "costCenter";
    public static final String DENVER_CO = "Denver,CO";
    public static final String MANAGER = "manager";
    public static final String JOHN_THE_SLOTH = "John the Sloth";
    public static final String KARI_THE_ANT_EATER = "Kari the Ant Eater";


    IdentityProviderProvisioning providerProvisioning;
    ApplicationEventPublisher publisher;
    JdbcUaaUserDatabase userDatabase;
    LoginSamlAuthenticationProvider authprovider;
    WebSSOProfileConsumer consumer;
    SAMLCredential credential;
    SAMLLogger samlLogger = mock(SAMLLogger.class);
    SamlIdentityProviderDefinition providerDefinition;
    private IdentityProvider provider;
    private ScimUserProvisioning userProvisioning;
    private JdbcScimGroupExternalMembershipManager externalManager;
    private ScimGroup uaaSamlUser;
    private ScimGroup uaaSamlAdmin;
    private ScimGroup uaaSamlTest;
    private TimeService timeService;

    public List<Attribute> getAttributes(Map<String,Object> values) {
        List<Attribute> result = new LinkedList<>();
        for (Map.Entry<String,Object> entry : values.entrySet()) {
            result.addAll(getAttributes(entry.getKey(), entry.getValue()));
        }
        return result;
    }
    public List<Attribute> getAttributes(final String name, Object value) {
        Attribute attribute = mock(Attribute.class);
        when(attribute.getName()).thenReturn(name);
        when(attribute.getFriendlyName()).thenReturn(name);

        List<XMLObject> xmlObjects = new LinkedList<>();
        if ("XSURI".equals(name)) {
            XSURIImpl impl = new AttributedURIImpl("", "", "");
            impl.setValue((String)value);
            xmlObjects.add(impl);
        } else if ("XSAny".equals(name)) {
            XSAnyImpl impl = new XSAnyImpl("","","") {};
            impl.setTextContent((String)value);
            xmlObjects.add(impl);
        } else if ("XSQName".equals(name)) {
            XSQNameImpl impl = new XSQNameImpl("","","") {};
            impl.setValue(new QName("", (String)value));
            xmlObjects.add(impl);
        } else if ("XSInteger".equals(name)) {
            XSIntegerImpl impl = new XSIntegerImpl("","",""){};
            impl.setValue((Integer)value);
            xmlObjects.add(impl);
        } else if ("XSBoolean".equals(name)) {
            XSBooleanImpl impl = new XSBooleanImpl("","",""){};
            impl.setValue(new XSBooleanValue((Boolean)value, false));
            xmlObjects.add(impl);
        } else if ("XSDateTime".equals(name)) {
            XSDateTimeImpl impl = new XSDateTimeImpl("","",""){};
            impl.setValue((DateTime)value);
            xmlObjects.add(impl);
        } else if ("XSBase64Binary".equals(name)) {
            XSBase64BinaryImpl impl = new XSBase64BinaryImpl("","",""){};
            impl.setValue((String)value);
            xmlObjects.add(impl);
        } else if (value instanceof List) {
            for (String s : (List<String>) value) {
                if (SAML_USER.equals(s)) {
                    XSAnyImpl impl = new XSAnyImpl("","","") {};
                    impl.setTextContent(s);
                    xmlObjects.add(impl);
                } else {
                    AttributedStringImpl impl = new AttributedStringImpl("", "", "");
                    impl.setValue(s);
                    xmlObjects.add(impl);
                }
            }
        } else {
            AttributedStringImpl impl = new AttributedStringImpl("", "", "");
            impl.setValue((String)value);
            xmlObjects.add(impl);
        }
        when(attribute.getAttributeValues()).thenReturn(xmlObjects);
        return Arrays.asList(attribute);
    }

    @Before
    public void configureProvider() throws Exception {
        providerDefinition = new SamlIdentityProviderDefinition();

        userProvisioning = new JdbcScimUserProvisioning(jdbcTemplate, new JdbcPagingListFactory(jdbcTemplate, limitSqlAdapter));
        ScimGroupProvisioning groupProvisioning = new JdbcScimGroupProvisioning(jdbcTemplate, new JdbcPagingListFactory(jdbcTemplate, limitSqlAdapter));

        uaaSamlUser = groupProvisioning.create(new ScimGroup(null,UAA_SAML_USER, IdentityZone.getUaa().getId()));
        uaaSamlAdmin = groupProvisioning.create(new ScimGroup(null,UAA_SAML_ADMIN, IdentityZone.getUaa().getId()));
        uaaSamlTest = groupProvisioning.create(new ScimGroup(null,UAA_SAML_TEST, IdentityZone.getUaa().getId()));

        JdbcScimGroupMembershipManager membershipManager = new JdbcScimGroupMembershipManager(jdbcTemplate, new JdbcPagingListFactory(jdbcTemplate, limitSqlAdapter));
        membershipManager.setScimGroupProvisioning(groupProvisioning);
        membershipManager.setScimUserProvisioning(userProvisioning);
        ScimUserBootstrap bootstrap = new ScimUserBootstrap(userProvisioning, groupProvisioning, membershipManager, Collections.EMPTY_LIST);

        externalManager = new JdbcScimGroupExternalMembershipManager(jdbcTemplate, new JdbcPagingListFactory(jdbcTemplate, limitSqlAdapter));
        externalManager.setScimGroupProvisioning(groupProvisioning);
        externalManager.mapExternalGroup(uaaSamlUser.getId(), SAML_USER, OriginKeys.SAML);
        externalManager.mapExternalGroup(uaaSamlAdmin.getId(), SAML_ADMIN, OriginKeys.SAML);
        externalManager.mapExternalGroup(uaaSamlTest.getId(), SAML_TEST, OriginKeys.SAML);

        consumer = mock(WebSSOProfileConsumer.class);
        credential = getUserCredential("marissa-saml", "Marissa", "Bloggs", "marissa.bloggs@test.com", "1234567890");
        Map<String, Object> attributes = new HashMap<>();
        attributes.put("firstName", "Marissa");
        attributes.put("lastName", "Bloggs");
        attributes.put("emailAddress", "marissa.bloggs@test.com");
        attributes.put("phone", "1234567890");
        attributes.put("groups", Arrays.asList(SAML_USER,SAML_ADMIN,SAML_NOT_MAPPED));
        attributes.put("2ndgroups", Arrays.asList(SAML_TEST));

        when(consumer.processAuthenticationResponse(anyObject())).thenReturn(credential);

        timeService = mock(TimeService.class);
        userDatabase = new JdbcUaaUserDatabase(jdbcTemplate, timeService);
        userDatabase.setDefaultAuthorities(new HashSet<>(Arrays.asList(UaaAuthority.UAA_USER.getAuthority())));
        providerProvisioning = new JdbcIdentityProviderProvisioning(jdbcTemplate);
        publisher = new CreateUserPublisher(bootstrap);
        authprovider = new LoginSamlAuthenticationProvider();

        authprovider.setUserDatabase(userDatabase);
        authprovider.setIdentityProviderProvisioning(providerProvisioning);
        authprovider.setApplicationEventPublisher(publisher);
        authprovider.setConsumer(consumer);
        authprovider.setSamlLogger(samlLogger);
        authprovider.setExternalMembershipManager(externalManager);

        provider = new IdentityProvider();
        provider.setIdentityZoneId(IdentityZone.getUaa().getId());
        provider.setOriginKey(OriginKeys.SAML);
        provider.setName("saml-test");
        provider.setActive(true);
        provider.setType(OriginKeys.SAML);
        providerDefinition.setMetaDataLocation(String.format(IDP_META_DATA, OriginKeys.SAML));
        providerDefinition.setIdpEntityAlias(OriginKeys.SAML);
        provider.setConfig(providerDefinition);
        provider = providerProvisioning.create(provider);
    }

    private SAMLCredential getUserCredential(String username, String firstName, String lastName, String emailAddress, String phoneNumber) {
        NameID usernameID = mock(NameID.class);
        when(usernameID.getValue()).thenReturn(username);

        Map<String, Object> attributes = new HashMap<>();
        attributes.put("firstName", firstName);
        attributes.put("lastName", lastName);
        attributes.put("emailAddress", emailAddress);
        attributes.put("phone", phoneNumber);
        attributes.put("groups", Arrays.asList(SAML_USER, SAML_ADMIN, SAML_NOT_MAPPED));
        attributes.put("2ndgroups", Arrays.asList(SAML_TEST));
        attributes.put(COST_CENTER, Arrays.asList(DENVER_CO));
        attributes.put(MANAGER, Arrays.asList(JOHN_THE_SLOTH, KARI_THE_ANT_EATER));

        //test different types
        attributes.put("XSURI", "http://localhost:8080/someuri");
        attributes.put("XSAny", "XSAnyValue");
        attributes.put("XSQName", "XSQNameValue");
        attributes.put("XSInteger", new Integer(3));
        attributes.put("XSBoolean", Boolean.TRUE);
        attributes.put("XSDateTime", new DateTime(0));
        attributes.put("XSBase64Binary", "00001111");


        AuthnContextClassRef contextClassRef = mock(AuthnContextClassRef.class);
        when(contextClassRef.getAuthnContextClassRef()).thenReturn(AuthnContext.PASSWORD_AUTHN_CTX);

        AuthnContext authenticationContext = mock(AuthnContext.class);
        when(authenticationContext.getAuthnContextClassRef()).thenReturn(contextClassRef);

        AuthnStatement statement = mock(AuthnStatement.class);
        when(statement.getAuthnContext()).thenReturn(authenticationContext);

        Assertion authenticationAssertion = mock(Assertion.class);
        when(authenticationAssertion.getAuthnStatements()).thenReturn(Arrays.asList(statement));

        return new SAMLCredential(
            usernameID,
            authenticationAssertion,
            "remoteEntityID",
            getAttributes(attributes),
            "localEntityID");
    }

    @Test
    public void testAuthenticateSimple() {
        authprovider.authenticate(mockSamlAuthentication(OriginKeys.SAML));
    }

    @Test
    public void saml_authentication_contains_acr() {
        Authentication authentication = authprovider.authenticate(mockSamlAuthentication(OriginKeys.SAML));
        assertNotNull("Authentication cannot be null", authentication);
        assertTrue("Authentication should be of type:"+UaaAuthentication.class.getName(), authentication instanceof UaaAuthentication);
        UaaAuthentication uaaAuthentication = (UaaAuthentication)authentication;
        assertThat(uaaAuthentication.getAuthContextClassRef(),containsInAnyOrder(AuthnContext.PASSWORD_AUTHN_CTX));
    }


    @Test
    public void test_multiple_group_attributes() throws Exception {
        providerDefinition.addAttributeMapping(GROUP_ATTRIBUTE_NAME, Arrays.asList("2ndgroups", "groups"));
        provider.setConfig(providerDefinition);
        providerProvisioning.update(provider);
        UaaAuthentication authentication = getAuthentication();
        assertEquals("Four authorities should have been granted!", 4, authentication.getAuthorities().size());
        assertThat(authentication.getAuthorities(),
                   containsInAnyOrder(
                       new SimpleGrantedAuthority(UAA_SAML_ADMIN),
                       new SimpleGrantedAuthority(UAA_SAML_USER),
                       new SimpleGrantedAuthority(UAA_SAML_TEST),
                       new SimpleGrantedAuthority(UaaAuthority.UAA_USER.getAuthority())
                   )
        );
    }

    @Test
    public void authenticationContainsAmr() throws Exception {
        UaaAuthentication authentication = getAuthentication();
        assertThat(authentication.getAuthenticationMethods(), containsInAnyOrder("ext"));
    }

    @Test
    public void test_external_groups_as_scopes() throws Exception {
        providerDefinition.setGroupMappingMode(SamlIdentityProviderDefinition.ExternalGroupMappingMode.AS_SCOPES);
        providerDefinition.addAttributeMapping(GROUP_ATTRIBUTE_NAME, Arrays.asList("2ndgroups", "groups"));
        provider.setConfig(providerDefinition);
        providerProvisioning.update(provider);
        UaaAuthentication authentication = getAuthentication();
        assertThat(authentication.getAuthorities(),
                containsInAnyOrder(
                        new SimpleGrantedAuthority(SAML_ADMIN),
                        new SimpleGrantedAuthority(SAML_USER),
                        new SimpleGrantedAuthority(SAML_TEST),
                        new SimpleGrantedAuthority(SAML_NOT_MAPPED),
                        new SimpleGrantedAuthority(UaaAuthority.UAA_USER.getAuthority())
                )
        );
    }

    @Test
    public void test_group_mapping() throws Exception {
        providerDefinition.addAttributeMapping(GROUP_ATTRIBUTE_NAME, "groups");
        provider.setConfig(providerDefinition);
        providerProvisioning.update(provider);
        UaaAuthentication authentication = getAuthentication();
        assertEquals("Three authorities should have been granted!", 3, authentication.getAuthorities().size());
        assertThat(authentication.getAuthorities(),
                   containsInAnyOrder(
                       new SimpleGrantedAuthority(UAA_SAML_ADMIN),
                       new SimpleGrantedAuthority(UAA_SAML_USER),
                       new SimpleGrantedAuthority(UaaAuthority.UAA_USER.getAuthority())
                   )
        );
    }

    @Test
    public void test_non_string_attributes() throws Exception {
        providerDefinition.addAttributeMapping(USER_ATTRIBUTE_PREFIX+"XSURI", "XSURI");
        providerDefinition.addAttributeMapping(USER_ATTRIBUTE_PREFIX+"XSAny", "XSAny");
        providerDefinition.addAttributeMapping(USER_ATTRIBUTE_PREFIX+"XSQName", "XSQName");
        providerDefinition.addAttributeMapping(USER_ATTRIBUTE_PREFIX+"XSInteger", "XSInteger");
        providerDefinition.addAttributeMapping(USER_ATTRIBUTE_PREFIX+"XSBoolean", "XSBoolean");
        providerDefinition.addAttributeMapping(USER_ATTRIBUTE_PREFIX+"XSDateTime", "XSDateTime");
        providerDefinition.addAttributeMapping(USER_ATTRIBUTE_PREFIX+"XSBase64Binary", "XSBase64Binary");

        provider.setConfig(providerDefinition);
        providerProvisioning.update(provider);
        UaaAuthentication authentication = getAuthentication();
        assertEquals("http://localhost:8080/someuri", authentication.getUserAttributes().getFirst("XSURI"));
        assertEquals("XSAnyValue", authentication.getUserAttributes().getFirst("XSAny"));
        assertEquals("XSQNameValue", authentication.getUserAttributes().getFirst("XSQName"));
        assertEquals("3", authentication.getUserAttributes().getFirst("XSInteger"));
        assertEquals("true", authentication.getUserAttributes().getFirst("XSBoolean"));
        assertEquals(new DateTime(0).toString(), authentication.getUserAttributes().getFirst("XSDateTime"));
        assertEquals("00001111", authentication.getUserAttributes().getFirst("XSBase64Binary"));
    }


    @Test
    public void externalGroup_NotMapped_ToScope() throws Exception {
        try {
            externalManager.unmapExternalGroup(uaaSamlUser.getId(), SAML_USER, OriginKeys.SAML);
            externalManager.unmapExternalGroup(uaaSamlAdmin.getId(), SAML_ADMIN, OriginKeys.SAML);
            providerDefinition.addAttributeMapping(GROUP_ATTRIBUTE_NAME, "groups");
            provider.setConfig(providerDefinition);
            providerProvisioning.update(provider);
            UaaAuthentication authentication = getAuthentication();
            assertEquals("Three authorities should have been granted!", 1, authentication.getAuthorities().size());
            assertThat(authentication.getAuthorities(),
                    not(containsInAnyOrder(
                        new SimpleGrantedAuthority(UAA_SAML_ADMIN),
                        new SimpleGrantedAuthority(UAA_SAML_USER)
                    ))
            );
        } finally {
            externalManager.mapExternalGroup(uaaSamlUser.getId(), SAML_USER, OriginKeys.SAML);
            externalManager.mapExternalGroup(uaaSamlAdmin.getId(), SAML_ADMIN, OriginKeys.SAML);
        }
    }

    @Test
    public void test_group_attribute_not_set() throws Exception {
        UaaAuthentication uaaAuthentication = getAuthentication();
        assertEquals("Only uaa.user should have been granted", 1, uaaAuthentication.getAuthorities().size());
        assertEquals(UaaAuthority.UAA_USER.getAuthority(), uaaAuthentication.getAuthorities().iterator().next().getAuthority());
    }

    @Test
    public void dontAdd_external_groups_to_authentication_without_whitelist() throws Exception {
        providerDefinition.addAttributeMapping(GROUP_ATTRIBUTE_NAME, "groups");
        provider.setConfig(providerDefinition);
        providerProvisioning.update(provider);

        UaaAuthentication authentication = getAuthentication();
        assertEquals(Collections.EMPTY_SET, authentication.getExternalGroups());
    }

    @Test
    public void add_external_groups_to_authentication_with_whitelist() throws Exception {
        providerDefinition.addAttributeMapping(GROUP_ATTRIBUTE_NAME, "groups");
        providerDefinition.addWhiteListedGroup(SAML_ADMIN);
        provider.setConfig(providerDefinition);
        providerProvisioning.update(provider);

        UaaAuthentication authentication = getAuthentication();
        assertEquals(Collections.singleton(SAML_ADMIN), authentication.getExternalGroups());
    }

    @Test
    public void add_external_groups_to_authentication_with_wildcard_whitelist() throws Exception {
        providerDefinition.addAttributeMapping(GROUP_ATTRIBUTE_NAME, "groups");
        providerDefinition.addWhiteListedGroup("saml*");
        provider.setConfig(providerDefinition);
        providerProvisioning.update(provider);
        UaaAuthentication authentication = getAuthentication();
        assertThat(authentication.getExternalGroups(), containsInAnyOrder(SAML_USER, SAML_ADMIN, SAML_NOT_MAPPED));
    }

    @Test
    public void update_invitedUser_whose_username_is_notEmail() throws Exception {
        ScimUser scimUser = getInvitedUser();

        SAMLCredential credential = getUserCredential("marissa-invited", "Marissa-invited", null, "marissa.invited@test.org", null);
        when(consumer.processAuthenticationResponse(anyObject())).thenReturn(credential);
        getAuthentication();

        UaaUser user = userDatabase.retrieveUserById(scimUser.getId());
        assertTrue(user.isVerified());
        assertEquals("marissa-invited", user.getUsername());
        assertEquals("marissa.invited@test.org", user.getEmail());

        RequestContextHolder.resetRequestAttributes();
    }

    @Test
    public void invitedUser_authentication_whenAuthenticatedEmailDoesNotMatchInvitedEmail() throws Exception {
        Map<String,Object> attributeMappings = new HashMap<>();
        attributeMappings.put("email", "emailAddress");
        providerDefinition.setAttributeMappings(attributeMappings);
        provider.setConfig(providerDefinition);
        providerProvisioning.update(provider);

        ScimUser scimUser = getInvitedUser();

        SAMLCredential credential = getUserCredential("marissa-invited", "Marissa-invited", null, "different@test.org", null);
        when(consumer.processAuthenticationResponse(anyObject())).thenReturn(credential);
        try {
            getAuthentication();
            fail();
        } catch (BadCredentialsException e) {
            UaaUser user = userDatabase.retrieveUserById(scimUser.getId());
            assertFalse(user.isVerified());
        }
        RequestContextHolder.resetRequestAttributes();
    }

    private ScimUser getInvitedUser() {
        ScimUser invitedUser = new ScimUser(null, "marissa.invited@test.org", "Marissa", "Bloggs");
        invitedUser.setPassword("a");
        invitedUser.setVerified(false);
        invitedUser.setPrimaryEmail("marissa.invited@test.org");
        invitedUser.setOrigin(OriginKeys.UAA);
        ScimUser scimUser = userProvisioning.create(invitedUser);

        RequestAttributes attributes = new ServletRequestAttributes(new MockHttpServletRequest());
        attributes.setAttribute("IS_INVITE_ACCEPTANCE", true, RequestAttributes.SCOPE_SESSION);
        attributes.setAttribute("user_id", scimUser.getId(), RequestAttributes.SCOPE_SESSION);
        RequestContextHolder.setRequestAttributes(attributes);

        return scimUser;
    }

    @Test
    public void update_existingUser_if_attributes_different() throws Exception {
        getAuthentication();

        Map<String,Object> attributeMappings = new HashMap<>();
        attributeMappings.put("given_name", "firstName");
        attributeMappings.put("email", "emailAddress");
        providerDefinition.setAttributeMappings(attributeMappings);
        provider.setConfig(providerDefinition);
        providerProvisioning.update(provider);

        SAMLCredential credential = getUserCredential("marissa-saml", "Marissa-changed", null, "marissa.bloggs@change.org", null);
        when(consumer.processAuthenticationResponse(anyObject())).thenReturn(credential);
        getAuthentication();

        UaaUser user = userDatabase.retrieveUserByName("marissa-saml", OriginKeys.SAML);
        assertEquals("Marissa-changed", user.getGivenName());
        assertEquals("marissa.bloggs@change.org", user.getEmail());
    }

    @Test
    public void dont_update_existingUser_if_attributes_areTheSame() throws Exception {
        getAuthentication();
        UaaUser user = userDatabase.retrieveUserByName("marissa-saml", OriginKeys.SAML);

        getAuthentication();
        UaaUser existingUser = userDatabase.retrieveUserByName("marissa-saml", OriginKeys.SAML);

        assertEquals(existingUser.getModified(), user.getModified());
    }

    @Test
    public void shadowAccount_createdWith_MappedUserAttributes() throws Exception {
        Map<String,Object> attributeMappings = new HashMap<>();
        attributeMappings.put("given_name", "firstName");
        attributeMappings.put("family_name", "lastName");
        attributeMappings.put("email", "emailAddress");
        attributeMappings.put("phone_number", "phone");
        providerDefinition.setAttributeMappings(attributeMappings);
        provider.setConfig(providerDefinition);
        providerProvisioning.update(provider);

        getAuthentication();
        UaaUser user = userDatabase.retrieveUserByName("marissa-saml", OriginKeys.SAML);
        assertEquals("Marissa", user.getGivenName());
        assertEquals("Bloggs", user.getFamilyName());
        assertEquals("marissa.bloggs@test.com", user.getEmail());
        assertEquals("1234567890", user.getPhoneNumber());
    }

    @Test
    public void custom_user_attributes_stored_if_configured() throws Exception {
        Map<String,Object> attributeMappings = new HashMap<>();
        attributeMappings.put("given_name", "firstName");
        attributeMappings.put("family_name", "lastName");
        attributeMappings.put("email", "emailAddress");
        attributeMappings.put("phone_number", "phone");
        attributeMappings.put(USER_ATTRIBUTE_PREFIX+"secondary_email","emailAddress");
        providerDefinition.setAttributeMappings(attributeMappings);
        providerDefinition.setStoreCustomAttributes(false);
        provider.setConfig(providerDefinition);
        provider = providerProvisioning.update(provider);

        UaaAuthentication authentication = getAuthentication();
        UaaUser user = userDatabase.retrieveUserByName("marissa-saml", OriginKeys.SAML);
        assertEquals("Marissa", user.getGivenName());
        assertEquals("Bloggs", user.getFamilyName());
        assertEquals("marissa.bloggs@test.com", user.getEmail());
        assertEquals("1234567890", user.getPhoneNumber());
        assertEquals("marissa.bloggs@test.com", authentication.getUserAttributes().getFirst("secondary_email"));

        UserInfo userInfo = userDatabase.getUserInfo(user.getId());
        assertNull(userInfo);

        providerDefinition.addAttributeMapping(GROUP_ATTRIBUTE_NAME, "groups");
        providerDefinition.addWhiteListedGroup(SAML_ADMIN);
        providerDefinition.setStoreCustomAttributes(true);
        provider.setConfig(providerDefinition);
        provider = providerProvisioning.update(provider);
        authentication = getAuthentication();
        assertEquals("marissa.bloggs@test.com", authentication.getUserAttributes().getFirst("secondary_email"));
        userInfo = userDatabase.getUserInfo(user.getId());
        assertNotNull(userInfo);
        assertEquals("marissa.bloggs@test.com", userInfo.getUserAttributes().getFirst("secondary_email"));
        assertNotNull(userInfo.getRoles());
        assertEquals(1, userInfo.getRoles().size());
        assertEquals(SAML_ADMIN, userInfo.getRoles().get(0));
    }

    @Test
    public void shadowAccountNotCreated_givenShadowAccountCreationDisabled() throws Exception {
        Map<String,Object> attributeMappings = new HashMap<>();
        attributeMappings.put("given_name", "firstName");
        attributeMappings.put("family_name", "lastName");
        attributeMappings.put("email", "emailAddress");
        attributeMappings.put("phone_number", "phone");
        providerDefinition.setAttributeMappings(attributeMappings);
        providerDefinition.setAddShadowUserOnLogin(false);
        provider.setConfig(providerDefinition);
        providerProvisioning.update(provider);

        try {
            getAuthentication();
            fail("Expected authentication to throw LoginSAMLException");
        } catch (LoginSAMLException ex) {

        }

        try {
            userDatabase.retrieveUserByName("marissa-saml", OriginKeys.SAML);
            fail("Expected user not to exist in database");
        } catch(UsernameNotFoundException ex) {

        }
    }

    @Test
    public void should_NotCreateShadowAccount_AndInstead_UpdateExistingUserUsername_if_userWithEmailExists() throws Exception {
        Map<String,Object> attributeMappings = new HashMap<>();
        attributeMappings.put("email", "emailAddress");
        providerDefinition.setAttributeMappings(attributeMappings);
        provider.setConfig(providerDefinition);
        providerProvisioning.update(provider);

        ScimUser createdUser = createSamlUser("marissa.bloggs@test.com", "marissa.bloggs@test.com", "Marissa", "Bloggs");

        getAuthentication();

        UaaUser uaaUser = userDatabase.retrieveUserByName("marissa-saml", OriginKeys.SAML);
        assertEquals(createdUser.getId(), uaaUser.getId());
        assertEquals("marissa-saml", uaaUser.getUsername());
    }

    @Test(expected = IncorrectResultSizeDataAccessException.class)
    public void error_when_multipleUsers_with_sameEmail() throws Exception {
        Map<String,Object> attributeMappings = new HashMap<>();
        attributeMappings.put("email", "emailAddress");
        providerDefinition.setAttributeMappings(attributeMappings);
        provider.setConfig(providerDefinition);
        providerProvisioning.update(provider);

        createSamlUser("marissa.bloggs@test.com", "marissa.bloggs@test.com", "Marissa", "Bloggs");
        createSamlUser("marissa.bloggs", "marissa.bloggs@test.com", "Marissa", "Bloggs");

        getAuthentication();
    }

    private ScimUser createSamlUser(String username, String email, String givenName, String familyName) {
        ScimUser user = new ScimUser("", username, givenName, familyName);
        user.setPrimaryEmail(email);
        user.setOrigin(OriginKeys.SAML);
        return userProvisioning.createUser(user, "");
    }

    @Test
    public void shadowUser_GetsCreatedWithDefaultValues_IfAttributeNotMapped() throws Exception {
        Map<String,Object> attributeMappings = new HashMap<>();
        attributeMappings.put("surname", "lastName");
        attributeMappings.put("email", "emailAddress");
        providerDefinition.setAttributeMappings(attributeMappings);
        provider.setConfig(providerDefinition);
        providerProvisioning.update(provider);

        UaaAuthentication authentication = getAuthentication();
        UaaUser user = userDatabase.retrieveUserByName("marissa-saml", OriginKeys.SAML);
        assertEquals("marissa.bloggs", user.getGivenName());
        assertEquals("test.com", user.getFamilyName());
        assertEquals("marissa.bloggs@test.com", user.getEmail());
        assertEquals("No custom attributes have been mapped", 0, authentication.getUserAttributes().size());
    }

    @Test
    public void user_authentication_contains_custom_attributes() throws Exception {
        String COST_CENTERS = COST_CENTER+"s";
        String MANAGERS = MANAGER+"s";

        Map<String,Object> attributeMappings = new HashMap<>();

        attributeMappings.put(USER_ATTRIBUTE_PREFIX+COST_CENTERS, COST_CENTER);
        attributeMappings.put(USER_ATTRIBUTE_PREFIX+MANAGERS, MANAGER);

        providerDefinition.setAttributeMappings(attributeMappings);
        provider.setConfig(providerDefinition);
        providerProvisioning.update(provider);

        UaaAuthentication authentication = getAuthentication();

        assertEquals("Expected two user attributes", 2, authentication.getUserAttributes().size());
        assertNotNull("Expected cost center attribute", authentication.getUserAttributes().get(COST_CENTERS));
        assertEquals(DENVER_CO, authentication.getUserAttributes().getFirst(COST_CENTERS));

        assertNotNull("Expected manager attribute", authentication.getUserAttributes().get(MANAGERS));
        assertEquals("Expected 2 manager attribute values", 2, authentication.getUserAttributes().get(MANAGERS).size());
        assertThat(authentication.getUserAttributes().get(MANAGERS), containsInAnyOrder(JOHN_THE_SLOTH, KARI_THE_ANT_EATER));
    }

    protected UaaAuthentication getAuthentication() {
        SAMLAuthenticationToken authentication1 = mockSamlAuthentication(OriginKeys.SAML);
        Authentication authentication = authprovider.authenticate(authentication1);
        assertNotNull("Authentication should exist", authentication);
        assertTrue("Authentication should be UaaAuthentication", authentication instanceof UaaAuthentication);
        return (UaaAuthentication)authentication;
    }

    protected SAMLAuthenticationToken mockSamlAuthentication(String originKey) {
        ExtendedMetadata metadata = mock(ExtendedMetadata.class);
        when(metadata.getAlias()).thenReturn(originKey);
        SAMLMessageContext contxt = mock(SAMLMessageContext.class);

        when(contxt.getPeerExtendedMetadata()).thenReturn(metadata);
        when(contxt.getCommunicationProfileId()).thenReturn(SAMLConstants.SAML2_WEBSSO_PROFILE_URI);
        return new SAMLAuthenticationToken(contxt);
    }

    public static class CreateUserPublisher implements ApplicationEventPublisher {

        final ScimUserBootstrap bootstrap;

        public CreateUserPublisher(ScimUserBootstrap bootstrap) {
            this.bootstrap = bootstrap;
        }


        @Override
        public void publishEvent(ApplicationEvent event) {
            if (event instanceof AuthEvent) {
                bootstrap.onApplicationEvent((AuthEvent)event);
            }
        }

        @Override
        public void publishEvent(Object event) {
            throw new UnsupportedOperationException("not implemented");
        }

    }

    public static final String IDP_META_DATA =
        "<?xml version=\"1.0\"?>\n" +
            "<md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" entityID=\"%s\" ID=\"pfx06ad4153-c17c-d286-194c-dec30bb92796\"><ds:Signature>\n" +
            "  <ds:SignedInfo><ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n" +
            "    <ds:SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"/>\n" +
            "  <ds:Reference URI=\"#pfx06ad4153-c17c-d286-194c-dec30bb92796\"><ds:Transforms><ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/><ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/></ds:Transforms><ds:DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/><ds:DigestValue>begl1WVCsXSn7iHixtWPP8d/X+k=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>BmbKqA3A0oSLcn5jImz/l5WbpVXj+8JIpT/ENWjOjSd/gcAsZm1QvYg+RxYPBk+iV2bBxD+/yAE/w0wibsHrl0u9eDhoMRUJBUSmeyuN1lYzBuoVa08PdAGtb5cGm4DMQT5Rzakb1P0hhEPPEDDHgTTxop89LUu6xx97t2Q03Khy8mXEmBmNt2NlFxJPNt0FwHqLKOHRKBOE/+BpswlBocjOQKFsI9tG3TyjFC68mM2jo0fpUQCgj5ZfhzolvS7z7c6V201d9Tqig0/mMFFJLTN8WuZPavw22AJlMjsDY9my+4R9HKhK5U53DhcTeECs9fb4gd7p5BJy4vVp7tqqOg==</ds:SignatureValue>\n" +
            "<ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIEEzCCAvugAwIBAgIJAIc1qzLrv+5nMA0GCSqGSIb3DQEBCwUAMIGfMQswCQYDVQQGEwJVUzELMAkGA1UECAwCQ08xFDASBgNVBAcMC0Nhc3RsZSBSb2NrMRwwGgYDVQQKDBNTYW1sIFRlc3RpbmcgU2VydmVyMQswCQYDVQQLDAJJVDEgMB4GA1UEAwwXc2ltcGxlc2FtbHBocC5jZmFwcHMuaW8xIDAeBgkqhkiG9w0BCQEWEWZoYW5pa0BwaXZvdGFsLmlvMB4XDTE1MDIyMzIyNDUwM1oXDTI1MDIyMjIyNDUwM1owgZ8xCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJDTzEUMBIGA1UEBwwLQ2FzdGxlIFJvY2sxHDAaBgNVBAoME1NhbWwgVGVzdGluZyBTZXJ2ZXIxCzAJBgNVBAsMAklUMSAwHgYDVQQDDBdzaW1wbGVzYW1scGhwLmNmYXBwcy5pbzEgMB4GCSqGSIb3DQEJARYRZmhhbmlrQHBpdm90YWwuaW8wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC4cn62E1xLqpN34PmbrKBbkOXFjzWgJ9b+pXuaRft6A339uuIQeoeH5qeSKRVTl32L0gdz2ZivLwZXW+cqvftVW1tvEHvzJFyxeTW3fCUeCQsebLnA2qRa07RkxTo6Nf244mWWRDodcoHEfDUSbxfTZ6IExSojSIU2RnD6WllYWFdD1GFpBJOmQB8rAc8wJIBdHFdQnX8Ttl7hZ6rtgqEYMzYVMuJ2F2r1HSU1zSAvwpdYP6rRGFRJEfdA9mm3WKfNLSc5cljz0X/TXy0vVlAV95l9qcfFzPmrkNIst9FZSwpvB49LyAVke04FQPPwLgVH4gphiJH3jvZ7I+J5lS8VAgMBAAGjUDBOMB0GA1UdDgQWBBTTyP6Cc5HlBJ5+ucVCwGc5ogKNGzAfBgNVHSMEGDAWgBTTyP6Cc5HlBJ5+ucVCwGc5ogKNGzAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQAvMS4EQeP/ipV4jOG5lO6/tYCb/iJeAduOnRhkJk0DbX329lDLZhTTL/x/w/9muCVcvLrzEp6PN+VWfw5E5FWtZN0yhGtP9R+vZnrV+oc2zGD+no1/ySFOe3EiJCO5dehxKjYEmBRv5sU/LZFKZpozKN/BMEa6CqLuxbzb7ykxVr7EVFXwltPxzE9TmL9OACNNyF5eJHWMRMllarUvkcXlh4pux4ks9e6zV9DQBy2zds9f1I3qxg0eX6JnGrXi/ZiCT+lJgVe3ZFXiejiLAiKB04sXW3ti0LW3lx13Y1YlQ4/tlpgTgfIJxKV6nyPiLoK0nywbMd+vpAirDt2Oc+hk</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>\n" +
            "  <md:IDPSSODescriptor protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\">\n" +
            "    <md:KeyDescriptor use=\"signing\">\n" +
            "      <ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n" +
            "        <ds:X509Data>\n" +
            "          <ds:X509Certificate>MIIEEzCCAvugAwIBAgIJAIc1qzLrv+5nMA0GCSqGSIb3DQEBCwUAMIGfMQswCQYDVQQGEwJVUzELMAkGA1UECAwCQ08xFDASBgNVBAcMC0Nhc3RsZSBSb2NrMRwwGgYDVQQKDBNTYW1sIFRlc3RpbmcgU2VydmVyMQswCQYDVQQLDAJJVDEgMB4GA1UEAwwXc2ltcGxlc2FtbHBocC5jZmFwcHMuaW8xIDAeBgkqhkiG9w0BCQEWEWZoYW5pa0BwaXZvdGFsLmlvMB4XDTE1MDIyMzIyNDUwM1oXDTI1MDIyMjIyNDUwM1owgZ8xCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJDTzEUMBIGA1UEBwwLQ2FzdGxlIFJvY2sxHDAaBgNVBAoME1NhbWwgVGVzdGluZyBTZXJ2ZXIxCzAJBgNVBAsMAklUMSAwHgYDVQQDDBdzaW1wbGVzYW1scGhwLmNmYXBwcy5pbzEgMB4GCSqGSIb3DQEJARYRZmhhbmlrQHBpdm90YWwuaW8wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC4cn62E1xLqpN34PmbrKBbkOXFjzWgJ9b+pXuaRft6A339uuIQeoeH5qeSKRVTl32L0gdz2ZivLwZXW+cqvftVW1tvEHvzJFyxeTW3fCUeCQsebLnA2qRa07RkxTo6Nf244mWWRDodcoHEfDUSbxfTZ6IExSojSIU2RnD6WllYWFdD1GFpBJOmQB8rAc8wJIBdHFdQnX8Ttl7hZ6rtgqEYMzYVMuJ2F2r1HSU1zSAvwpdYP6rRGFRJEfdA9mm3WKfNLSc5cljz0X/TXy0vVlAV95l9qcfFzPmrkNIst9FZSwpvB49LyAVke04FQPPwLgVH4gphiJH3jvZ7I+J5lS8VAgMBAAGjUDBOMB0GA1UdDgQWBBTTyP6Cc5HlBJ5+ucVCwGc5ogKNGzAfBgNVHSMEGDAWgBTTyP6Cc5HlBJ5+ucVCwGc5ogKNGzAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQAvMS4EQeP/ipV4jOG5lO6/tYCb/iJeAduOnRhkJk0DbX329lDLZhTTL/x/w/9muCVcvLrzEp6PN+VWfw5E5FWtZN0yhGtP9R+vZnrV+oc2zGD+no1/ySFOe3EiJCO5dehxKjYEmBRv5sU/LZFKZpozKN/BMEa6CqLuxbzb7ykxVr7EVFXwltPxzE9TmL9OACNNyF5eJHWMRMllarUvkcXlh4pux4ks9e6zV9DQBy2zds9f1I3qxg0eX6JnGrXi/ZiCT+lJgVe3ZFXiejiLAiKB04sXW3ti0LW3lx13Y1YlQ4/tlpgTgfIJxKV6nyPiLoK0nywbMd+vpAirDt2Oc+hk</ds:X509Certificate>\n" +
            "        </ds:X509Data>\n" +
            "      </ds:KeyInfo>\n" +
            "    </md:KeyDescriptor>\n" +
            "    <md:KeyDescriptor use=\"encryption\">\n" +
            "      <ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n" +
            "        <ds:X509Data>\n" +
            "          <ds:X509Certificate>MIIEEzCCAvugAwIBAgIJAIc1qzLrv+5nMA0GCSqGSIb3DQEBCwUAMIGfMQswCQYDVQQGEwJVUzELMAkGA1UECAwCQ08xFDASBgNVBAcMC0Nhc3RsZSBSb2NrMRwwGgYDVQQKDBNTYW1sIFRlc3RpbmcgU2VydmVyMQswCQYDVQQLDAJJVDEgMB4GA1UEAwwXc2ltcGxlc2FtbHBocC5jZmFwcHMuaW8xIDAeBgkqhkiG9w0BCQEWEWZoYW5pa0BwaXZvdGFsLmlvMB4XDTE1MDIyMzIyNDUwM1oXDTI1MDIyMjIyNDUwM1owgZ8xCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJDTzEUMBIGA1UEBwwLQ2FzdGxlIFJvY2sxHDAaBgNVBAoME1NhbWwgVGVzdGluZyBTZXJ2ZXIxCzAJBgNVBAsMAklUMSAwHgYDVQQDDBdzaW1wbGVzYW1scGhwLmNmYXBwcy5pbzEgMB4GCSqGSIb3DQEJARYRZmhhbmlrQHBpdm90YWwuaW8wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC4cn62E1xLqpN34PmbrKBbkOXFjzWgJ9b+pXuaRft6A339uuIQeoeH5qeSKRVTl32L0gdz2ZivLwZXW+cqvftVW1tvEHvzJFyxeTW3fCUeCQsebLnA2qRa07RkxTo6Nf244mWWRDodcoHEfDUSbxfTZ6IExSojSIU2RnD6WllYWFdD1GFpBJOmQB8rAc8wJIBdHFdQnX8Ttl7hZ6rtgqEYMzYVMuJ2F2r1HSU1zSAvwpdYP6rRGFRJEfdA9mm3WKfNLSc5cljz0X/TXy0vVlAV95l9qcfFzPmrkNIst9FZSwpvB49LyAVke04FQPPwLgVH4gphiJH3jvZ7I+J5lS8VAgMBAAGjUDBOMB0GA1UdDgQWBBTTyP6Cc5HlBJ5+ucVCwGc5ogKNGzAfBgNVHSMEGDAWgBTTyP6Cc5HlBJ5+ucVCwGc5ogKNGzAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQAvMS4EQeP/ipV4jOG5lO6/tYCb/iJeAduOnRhkJk0DbX329lDLZhTTL/x/w/9muCVcvLrzEp6PN+VWfw5E5FWtZN0yhGtP9R+vZnrV+oc2zGD+no1/ySFOe3EiJCO5dehxKjYEmBRv5sU/LZFKZpozKN/BMEa6CqLuxbzb7ykxVr7EVFXwltPxzE9TmL9OACNNyF5eJHWMRMllarUvkcXlh4pux4ks9e6zV9DQBy2zds9f1I3qxg0eX6JnGrXi/ZiCT+lJgVe3ZFXiejiLAiKB04sXW3ti0LW3lx13Y1YlQ4/tlpgTgfIJxKV6nyPiLoK0nywbMd+vpAirDt2Oc+hk</ds:X509Certificate>\n" +
            "        </ds:X509Data>\n" +
            "      </ds:KeyInfo>\n" +
            "    </md:KeyDescriptor>\n" +
            "    <md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"http://simplesamlphp.cfapps.io/saml2/idp/SingleLogoutService.php\"/>\n" +
            "    <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat>\n" +
            "    <md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"http://simplesamlphp.cfapps.io/saml2/idp/SSOService.php\"/>\n" +
            "  </md:IDPSSODescriptor>\n" +
            "  <md:ContactPerson contactType=\"technical\">\n" +
            "    <md:GivenName>Filip</md:GivenName>\n" +
            "    <md:SurName>Hanik</md:SurName>\n" +
            "    <md:EmailAddress>fhanik@pivotal.io</md:EmailAddress>\n" +
            "  </md:ContactPerson>\n" +
            "</md:EntityDescriptor>";
}
