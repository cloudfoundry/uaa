package org.cloudfoundry.identity.uaa.provider.saml;

import org.cloudfoundry.identity.uaa.annotations.WithDatabaseContext;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.authentication.event.IdentityProviderAuthenticationSuccessEvent;
import org.cloudfoundry.identity.uaa.authentication.manager.AuthEvent;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.db.DatabaseUrlModifier;
import org.cloudfoundry.identity.uaa.db.Vendor;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.JdbcIdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.SamlIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.resources.jdbc.JdbcPagingListFactory;
import org.cloudfoundry.identity.uaa.resources.jdbc.LimitSqlAdapter;
import org.cloudfoundry.identity.uaa.scim.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.ScimGroupProvisioning;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.scim.bootstrap.ScimUserBootstrap;
import org.cloudfoundry.identity.uaa.scim.jdbc.JdbcScimGroupExternalMembershipManager;
import org.cloudfoundry.identity.uaa.scim.jdbc.JdbcScimGroupMembershipManager;
import org.cloudfoundry.identity.uaa.scim.jdbc.JdbcScimGroupProvisioning;
import org.cloudfoundry.identity.uaa.scim.jdbc.JdbcScimUserProvisioning;
import org.cloudfoundry.identity.uaa.test.TestUtils;
import org.cloudfoundry.identity.uaa.user.JdbcUaaUserDatabase;
import org.cloudfoundry.identity.uaa.user.UaaAuthority;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UaaUserPrototype;
import org.cloudfoundry.identity.uaa.user.UserInfo;
import org.cloudfoundry.identity.uaa.util.TimeService;
import org.cloudfoundry.identity.uaa.util.TimeServiceImpl;
import org.cloudfoundry.identity.uaa.web.UaaSavedRequestAwareAuthenticationSuccessHandler;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManagerImpl;
import org.joda.time.DateTime;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.opensaml.common.SAMLException;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AuthnContext;
import org.opensaml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml2.core.AuthnStatement;
import org.opensaml.saml2.core.NameID;
import org.opensaml.ws.wsaddressing.impl.AttributedURIImpl;
import org.opensaml.ws.wssecurity.impl.AttributedStringImpl;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.encryption.DecryptionException;
import org.opensaml.xml.schema.XSBoolean;
import org.opensaml.xml.schema.XSBooleanValue;
import org.opensaml.xml.schema.impl.XSAnyImpl;
import org.opensaml.xml.schema.impl.XSBase64BinaryImpl;
import org.opensaml.xml.schema.impl.XSBooleanBuilder;
import org.opensaml.xml.schema.impl.XSBooleanImpl;
import org.opensaml.xml.schema.impl.XSDateTimeImpl;
import org.opensaml.xml.schema.impl.XSIntegerImpl;
import org.opensaml.xml.schema.impl.XSQNameImpl;
import org.opensaml.xml.schema.impl.XSURIImpl;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.validation.ValidationException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.dao.IncorrectResultSizeDataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.saml.SAMLAuthenticationToken;
import org.springframework.security.saml.SAMLConstants;
import org.springframework.security.saml.SAMLCredential;
import org.springframework.security.saml.context.SAMLMessageContext;
import org.springframework.security.saml.log.SAMLLogger;
import org.springframework.security.saml.metadata.ExtendedMetadata;
import org.springframework.security.saml.websso.WebSSOProfileConsumer;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.web.context.request.ServletWebRequest;

import javax.servlet.ServletContext;
import javax.xml.namespace.QName;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition.EMAIL_ATTRIBUTE_NAME;
import static org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition.EMAIL_VERIFIED_ATTRIBUTE_NAME;
import static org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition.FAMILY_NAME_ATTRIBUTE_NAME;
import static org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition.GIVEN_NAME_ATTRIBUTE_NAME;
import static org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition.GROUP_ATTRIBUTE_NAME;
import static org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition.PHONE_NUMBER_ATTRIBUTE_NAME;
import static org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition.USER_ATTRIBUTE_PREFIX;
import static org.cloudfoundry.identity.uaa.test.ModelTestUtils.getResourceAsString;
import static org.cloudfoundry.identity.uaa.user.UaaUserMatcher.aUaaUser;
import static org.cloudfoundry.identity.uaa.util.AssertThrowsWithMessage.assertThrowsWithMessageThat;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.emptyIterable;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@WithDatabaseContext
class LoginSamlAuthenticationProviderTests {
    private static final String SAML_USER = "saml.user";
    private static final String SAML_ADMIN = "saml.admin";
    private static final String SAML_TEST = "saml.test";
    private static final String SAML_NOT_MAPPED = "saml.unmapped";
    private static final String UAA_SAML_USER = "uaa.saml.user";
    private static final String UAA_SAML_ADMIN = "uaa.saml.admin";
    private static final String UAA_SAML_TEST = "uaa.saml.test";
    private static final String COST_CENTER = "costCenter";
    private static final String DENVER_CO = "Denver,CO";
    private static final String MANAGER = "manager";
    private static final String JOHN_THE_SLOTH = "John the Sloth";
    private static final String KARI_THE_ANT_EATER = "Kari the Ant Eater";

    private JdbcIdentityProviderProvisioning providerProvisioning;
    private CreateUserPublisher publisher;
    private JdbcUaaUserDatabase userDatabase;
    private LoginSamlAuthenticationProvider authprovider;
    private WebSSOProfileConsumer consumer;
    private SAMLLogger samlLogger = mock(SAMLLogger.class);
    private SamlIdentityProviderDefinition providerDefinition;
    private IdentityProvider<SamlIdentityProviderDefinition> provider;
    private ScimUserProvisioning userProvisioning;
    private JdbcScimGroupExternalMembershipManager externalManager;
    private ScimGroup uaaSamlUser;
    private ScimGroup uaaSamlAdmin;
    private IdentityZoneManager identityZoneManager;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Autowired
    private LimitSqlAdapter limitSqlAdapter;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @BeforeEach
    void configureProvider() throws SAMLException, SecurityException, DecryptionException, ValidationException {
        identityZoneManager = new IdentityZoneManagerImpl();
        RequestContextHolder.resetRequestAttributes();
        MockHttpServletRequest request = new MockHttpServletRequest(mock(ServletContext.class));
        MockHttpServletResponse response = new MockHttpServletResponse();
        ServletWebRequest servletWebRequest = new ServletWebRequest(request, response);
        RequestContextHolder.setRequestAttributes(servletWebRequest);

        ScimGroupProvisioning groupProvisioning = new JdbcScimGroupProvisioning(jdbcTemplate, new JdbcPagingListFactory(jdbcTemplate, limitSqlAdapter));
        identityZoneManager.getCurrentIdentityZone().getConfig().getUserConfig().setDefaultGroups(Collections.singletonList("uaa.user"));
        groupProvisioning.createOrGet(new ScimGroup(null, "uaa.user", identityZoneManager.getCurrentIdentityZone().getId()), identityZoneManager.getCurrentIdentityZone().getId());
        providerDefinition = new SamlIdentityProviderDefinition();

        userProvisioning = new JdbcScimUserProvisioning(jdbcTemplate, new JdbcPagingListFactory(jdbcTemplate, limitSqlAdapter), passwordEncoder);


        uaaSamlUser = groupProvisioning.create(new ScimGroup(null, UAA_SAML_USER, IdentityZone.getUaaZoneId()), identityZoneManager.getCurrentIdentityZone().getId());
        uaaSamlAdmin = groupProvisioning.create(new ScimGroup(null, UAA_SAML_ADMIN, IdentityZone.getUaaZoneId()), identityZoneManager.getCurrentIdentityZone().getId());
        ScimGroup uaaSamlTest = groupProvisioning.create(new ScimGroup(null, UAA_SAML_TEST, IdentityZone.getUaaZoneId()), identityZoneManager.getCurrentIdentityZone().getId());

        JdbcScimGroupMembershipManager membershipManager = new JdbcScimGroupMembershipManager(jdbcTemplate, new TimeServiceImpl(), userProvisioning, null);
        membershipManager.setScimGroupProvisioning(groupProvisioning);
        ScimUserBootstrap bootstrap = new ScimUserBootstrap(userProvisioning, groupProvisioning, membershipManager, Collections.emptyList(), false, Collections.emptyList());

        externalManager = new JdbcScimGroupExternalMembershipManager(jdbcTemplate);
        externalManager.setScimGroupProvisioning(groupProvisioning);
        externalManager.mapExternalGroup(uaaSamlUser.getId(), SAML_USER, OriginKeys.SAML, identityZoneManager.getCurrentIdentityZone().getId());
        externalManager.mapExternalGroup(uaaSamlAdmin.getId(), SAML_ADMIN, OriginKeys.SAML, identityZoneManager.getCurrentIdentityZone().getId());
        externalManager.mapExternalGroup(uaaSamlTest.getId(), SAML_TEST, OriginKeys.SAML, identityZoneManager.getCurrentIdentityZone().getId());

        consumer = mock(WebSSOProfileConsumer.class);
        SAMLCredential credential = getUserCredential("marissa-saml", "Marissa", "Bloggs", "marissa.bloggs@test.com", "1234567890");

        when(consumer.processAuthenticationResponse(any())).thenReturn(credential);

        TimeService timeService = mock(TimeService.class);
        DatabaseUrlModifier databaseUrlModifier = mock(DatabaseUrlModifier.class);
        when(databaseUrlModifier.getDatabaseType()).thenReturn(Vendor.unknown);
        userDatabase = new JdbcUaaUserDatabase(jdbcTemplate, timeService, false, identityZoneManager,
                databaseUrlModifier);
        providerProvisioning = new JdbcIdentityProviderProvisioning(jdbcTemplate);
        publisher = new CreateUserPublisher(bootstrap);

        authprovider = new LoginSamlAuthenticationProvider(
                identityZoneManager,
                userDatabase,
                providerProvisioning,
                externalManager);
        authprovider.setApplicationEventPublisher(publisher);
        authprovider.setConsumer(consumer);
        authprovider.setSamlLogger(samlLogger);

        provider = new IdentityProvider();
        provider.setIdentityZoneId(IdentityZone.getUaaZoneId());
        provider.setOriginKey(OriginKeys.SAML);
        provider.setName("saml-test");
        provider.setActive(true);
        provider.setType(OriginKeys.SAML);
        providerDefinition.setMetaDataLocation(String.format(IDP_META_DATA, OriginKeys.SAML));
        providerDefinition.setIdpEntityAlias(OriginKeys.SAML);
        provider.setConfig(providerDefinition);
        provider = providerProvisioning.create(provider, identityZoneManager.getCurrentIdentityZone().getId());
    }

    @AfterEach
    void tearDown(@Autowired ApplicationContext applicationContext) {
        TestUtils.restoreToDefaults(applicationContext);
        RequestContextHolder.resetRequestAttributes();
    }

    @Test
    void testAuthenticateSimple() {
        authprovider.authenticate(mockSamlAuthentication());
    }

    @Test
    void testAuthenticationEvents() {
        authprovider.authenticate(mockSamlAuthentication());
        assertEquals(3, publisher.events.size());
        assertTrue(publisher.events.get(2) instanceof IdentityProviderAuthenticationSuccessEvent);
    }

    @Test
    void relay_sets_attribute() {
        for (String url : Arrays.asList("test", "www.google.com", null)) {
            authprovider.configureRelayRedirect(url);
            assertNull(RequestContextHolder.currentRequestAttributes().getAttribute(UaaSavedRequestAwareAuthenticationSuccessHandler.URI_OVERRIDE_ATTRIBUTE, RequestAttributes.SCOPE_REQUEST));
        }
    }

    @Test
    void test_relay_state_when_url() {
        String redirectUrl = "https://www.cloudfoundry.org";
        SAMLAuthenticationToken samlAuthenticationToken = mockSamlAuthentication();
        when(samlAuthenticationToken.getCredentials().getRelayState()).thenReturn(redirectUrl);
        Authentication authentication = authprovider.authenticate(samlAuthenticationToken);
        assertNotNull(authentication, "Authentication cannot be null");
        assertTrue(authentication instanceof UaaAuthentication, "Authentication should be of type:" + UaaAuthentication.class.getName());
        UaaAuthentication uaaAuthentication = (UaaAuthentication) authentication;
        assertThat(uaaAuthentication.getAuthContextClassRef(), containsInAnyOrder(AuthnContext.PASSWORD_AUTHN_CTX));
        SAMLMessageContext context = samlAuthenticationToken.getCredentials();
        verify(context, times(1)).getRelayState();
        assertEquals(redirectUrl, RequestContextHolder.currentRequestAttributes().getAttribute(UaaSavedRequestAwareAuthenticationSuccessHandler.URI_OVERRIDE_ATTRIBUTE, RequestAttributes.SCOPE_REQUEST));
    }

    @Test
    void saml_authentication_contains_acr() {
        SAMLAuthenticationToken samlAuthenticationToken = mockSamlAuthentication();
        Authentication authentication = authprovider.authenticate(samlAuthenticationToken);
        assertNotNull(authentication, "Authentication cannot be null");
        assertTrue(authentication instanceof UaaAuthentication, "Authentication should be of type:" + UaaAuthentication.class.getName());
        UaaAuthentication uaaAuthentication = (UaaAuthentication) authentication;
        assertThat(uaaAuthentication.getAuthContextClassRef(), containsInAnyOrder(AuthnContext.PASSWORD_AUTHN_CTX));

        SAMLMessageContext context = samlAuthenticationToken.getCredentials();
        verify(context, times(1)).getRelayState();
        assertNull(RequestContextHolder.currentRequestAttributes().getAttribute(UaaSavedRequestAwareAuthenticationSuccessHandler.URI_OVERRIDE_ATTRIBUTE, RequestAttributes.SCOPE_REQUEST));
    }

    @Test
    void test_multiple_group_attributes() {
        providerDefinition.addAttributeMapping(GROUP_ATTRIBUTE_NAME, Arrays.asList("2ndgroups", "groups"));
        provider.setConfig(providerDefinition);
        providerProvisioning.update(provider, identityZoneManager.getCurrentIdentityZone().getId());
        UaaAuthentication authentication = getAuthentication(authprovider);
        assertEquals(4, authentication.getAuthorities().size(), "Four authorities should have been granted!");
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
    void authenticationContainsAmr() {
        UaaAuthentication authentication = getAuthentication(authprovider);
        assertThat(authentication.getAuthenticationMethods(), containsInAnyOrder("ext"));
    }

    @Test
    void test_external_groups_as_scopes() {
        providerDefinition.setGroupMappingMode(SamlIdentityProviderDefinition.ExternalGroupMappingMode.AS_SCOPES);
        providerDefinition.addAttributeMapping(GROUP_ATTRIBUTE_NAME, Arrays.asList("2ndgroups", "groups"));
        provider.setConfig(providerDefinition);
        providerProvisioning.update(provider, identityZoneManager.getCurrentIdentityZone().getId());
        UaaAuthentication authentication = getAuthentication(authprovider);
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
    void test_group_mapping() {
        providerDefinition.addAttributeMapping(GROUP_ATTRIBUTE_NAME, "groups");
        provider.setConfig(providerDefinition);
        providerProvisioning.update(provider, identityZoneManager.getCurrentIdentityZone().getId());
        UaaAuthentication authentication = getAuthentication(authprovider);
        assertEquals(3, authentication.getAuthorities().size(), "Three authorities should have been granted!");
        assertThat(authentication.getAuthorities(),
                containsInAnyOrder(
                        new SimpleGrantedAuthority(UAA_SAML_ADMIN),
                        new SimpleGrantedAuthority(UAA_SAML_USER),
                        new SimpleGrantedAuthority(UaaAuthority.UAA_USER.getAuthority())
                )
        );
    }

    @Test
    void test_non_string_attributes() {
        providerDefinition.addAttributeMapping(USER_ATTRIBUTE_PREFIX + "XSURI", "XSURI");
        providerDefinition.addAttributeMapping(USER_ATTRIBUTE_PREFIX + "XSAny", "XSAny");
        providerDefinition.addAttributeMapping(USER_ATTRIBUTE_PREFIX + "XSQName", "XSQName");
        providerDefinition.addAttributeMapping(USER_ATTRIBUTE_PREFIX + "XSInteger", "XSInteger");
        providerDefinition.addAttributeMapping(USER_ATTRIBUTE_PREFIX + "XSBoolean", "XSBoolean");
        providerDefinition.addAttributeMapping(USER_ATTRIBUTE_PREFIX + "XSDateTime", "XSDateTime");
        providerDefinition.addAttributeMapping(USER_ATTRIBUTE_PREFIX + "XSBase64Binary", "XSBase64Binary");

        provider.setConfig(providerDefinition);
        providerProvisioning.update(provider, identityZoneManager.getCurrentIdentityZone().getId());
        UaaAuthentication authentication = getAuthentication(authprovider);
        assertEquals("http://localhost:8080/someuri", authentication.getUserAttributes().getFirst("XSURI"));
        assertEquals("XSAnyValue", authentication.getUserAttributes().getFirst("XSAny"));
        assertEquals("XSQNameValue", authentication.getUserAttributes().getFirst("XSQName"));
        assertEquals("3", authentication.getUserAttributes().getFirst("XSInteger"));
        assertEquals("true", authentication.getUserAttributes().getFirst("XSBoolean"));
        assertEquals(new DateTime(0).toString(), authentication.getUserAttributes().getFirst("XSDateTime"));
        assertEquals("00001111", authentication.getUserAttributes().getFirst("XSBase64Binary"));
    }

    @Test
    void externalGroup_NotMapped_ToScope() {
        try {
            externalManager.unmapExternalGroup(uaaSamlUser.getId(), SAML_USER, OriginKeys.SAML, identityZoneManager.getCurrentIdentityZone().getId());
            externalManager.unmapExternalGroup(uaaSamlAdmin.getId(), SAML_ADMIN, OriginKeys.SAML, identityZoneManager.getCurrentIdentityZone().getId());
            providerDefinition.addAttributeMapping(GROUP_ATTRIBUTE_NAME, "groups");
            provider.setConfig(providerDefinition);
            providerProvisioning.update(provider, identityZoneManager.getCurrentIdentityZone().getId());
            UaaAuthentication authentication = getAuthentication(authprovider);
            assertEquals(1, authentication.getAuthorities().size(), "Three authorities should have been granted!");
            assertThat(authentication.getAuthorities(),
                    not(containsInAnyOrder(
                            new SimpleGrantedAuthority(UAA_SAML_ADMIN),
                            new SimpleGrantedAuthority(UAA_SAML_USER)
                    ))
            );
        } finally {
            externalManager.mapExternalGroup(uaaSamlUser.getId(), SAML_USER, OriginKeys.SAML, identityZoneManager.getCurrentIdentityZone().getId());
            externalManager.mapExternalGroup(uaaSamlAdmin.getId(), SAML_ADMIN, OriginKeys.SAML, identityZoneManager.getCurrentIdentityZone().getId());
        }
    }

    @Test
    void test_group_attribute_not_set() {
        UaaAuthentication uaaAuthentication = getAuthentication(authprovider);
        assertEquals(1, uaaAuthentication.getAuthorities().size(), "Only uaa.user should have been granted");
        assertEquals(UaaAuthority.UAA_USER.getAuthority(), uaaAuthentication.getAuthorities().iterator().next().getAuthority());
    }

    @Test
    void dontAdd_external_groups_to_authentication_without_whitelist() {
        providerDefinition.addAttributeMapping(GROUP_ATTRIBUTE_NAME, "groups");
        provider.setConfig(providerDefinition);
        providerProvisioning.update(provider, identityZoneManager.getCurrentIdentityZone().getId());

        UaaAuthentication authentication = getAuthentication(authprovider);
        assertEquals(Collections.EMPTY_SET, authentication.getExternalGroups());
    }

    @Test
    void add_external_groups_to_authentication_with_whitelist() {
        providerDefinition.addAttributeMapping(GROUP_ATTRIBUTE_NAME, "groups");
        providerDefinition.addWhiteListedGroup(SAML_ADMIN);
        provider.setConfig(providerDefinition);
        providerProvisioning.update(provider, identityZoneManager.getCurrentIdentityZone().getId());

        UaaAuthentication authentication = getAuthentication(authprovider);
        assertEquals(Collections.singleton(SAML_ADMIN), authentication.getExternalGroups());
    }

    @Test
    void add_external_groups_to_authentication_with_wildcard_whitelist() {
        providerDefinition.addAttributeMapping(GROUP_ATTRIBUTE_NAME, "groups");
        providerDefinition.addWhiteListedGroup("saml*");
        provider.setConfig(providerDefinition);
        providerProvisioning.update(provider, identityZoneManager.getCurrentIdentityZone().getId());
        UaaAuthentication authentication = getAuthentication(authprovider);
        assertThat(authentication.getExternalGroups(), containsInAnyOrder(SAML_USER, SAML_ADMIN, SAML_NOT_MAPPED));
    }

    @Test
    void update_invitedUser_whose_username_is_notEmail() throws Exception {
        ScimUser scimUser = getInvitedUser();

        SAMLCredential credential = getUserCredential("marissa-invited", "Marissa-invited", null, "marissa.invited@test.org", null);
        when(consumer.processAuthenticationResponse(any())).thenReturn(credential);
        getAuthentication(authprovider);

        UaaUser user = userDatabase.retrieveUserById(scimUser.getId());
        assertFalse(user.isVerified());
        assertEquals("marissa-invited", user.getUsername());
        assertEquals("marissa.invited@test.org", user.getEmail());

        RequestContextHolder.resetRequestAttributes();
    }

    @Test
    void invitedUser_authentication_whenAuthenticatedEmailDoesNotMatchInvitedEmail() throws Exception {
        Map<String, Object> attributeMappings = new HashMap<>();
        attributeMappings.put("email", "emailAddress");
        providerDefinition.setAttributeMappings(attributeMappings);
        provider.setConfig(providerDefinition);
        providerProvisioning.update(provider, identityZoneManager.getCurrentIdentityZone().getId());

        ScimUser scimUser = getInvitedUser();

        SAMLCredential credential = getUserCredential("marissa-invited", "Marissa-invited", null, "different@test.org", null);
        when(consumer.processAuthenticationResponse(any())).thenReturn(credential);
        try {
            getAuthentication(authprovider);
            fail();
        } catch (BadCredentialsException e) {
            UaaUser user = userDatabase.retrieveUserById(scimUser.getId());
            assertFalse(user.isVerified());
        }
        RequestContextHolder.resetRequestAttributes();
    }

    private ScimUser getInvitedUser() {
        ScimUser invitedUser = new ScimUser(null, "marissa.invited@test.org", "Marissa", "Bloggs");
        invitedUser.setVerified(false);
        invitedUser.setPrimaryEmail("marissa.invited@test.org");
        invitedUser.setOrigin(OriginKeys.UAA);
        ScimUser scimUser = userProvisioning.createUser(invitedUser, "getInvitedUser-password", identityZoneManager.getCurrentIdentityZone().getId());

        RequestAttributes attributes = new ServletRequestAttributes(new MockHttpServletRequest());
        attributes.setAttribute("IS_INVITE_ACCEPTANCE", true, RequestAttributes.SCOPE_SESSION);
        attributes.setAttribute("user_id", scimUser.getId(), RequestAttributes.SCOPE_SESSION);
        RequestContextHolder.setRequestAttributes(attributes);

        return scimUser;
    }

    @Test
    void update_existingUser_if_attributes_different() throws Exception {
        try {
            userDatabase.retrieveUserByName("marissa-saml", OriginKeys.SAML);
            fail("user should not exist");
        } catch (UsernameNotFoundException ignored) {
        }
        getAuthentication(authprovider);
        UaaUser user = userDatabase.retrieveUserByName("marissa-saml", OriginKeys.SAML);
        assertFalse(user.isVerified());
        Map<String, Object> attributeMappings = new HashMap<>();
        attributeMappings.put("given_name", "firstName");
        attributeMappings.put("email", "emailAddress");
        attributeMappings.put("email_verified", "emailVerified");
        providerDefinition.setAttributeMappings(attributeMappings);
        provider.setConfig(providerDefinition);
        providerProvisioning.update(provider, identityZoneManager.getCurrentIdentityZone().getId());

        SAMLCredential credential = getUserCredential("marissa-saml", "Marissa-changed", null, "marissa.bloggs@change.org", null);
        when(consumer.processAuthenticationResponse(any())).thenReturn(credential);
        getAuthentication(authprovider);

        user = userDatabase.retrieveUserByName("marissa-saml", OriginKeys.SAML);
        assertEquals("Marissa-changed", user.getGivenName());
        assertEquals("marissa.bloggs@change.org", user.getEmail());
        assertFalse(user.isVerified());

        credential = getUserCredential("marissa-saml", "Marissa-changed", null, "marissa.bloggs@change.org", null, true);
        when(consumer.processAuthenticationResponse(any())).thenReturn(credential);
        getAuthentication(authprovider);

        user = userDatabase.retrieveUserByName("marissa-saml", OriginKeys.SAML);
        assertEquals("Marissa-changed", user.getGivenName());
        assertEquals("marissa.bloggs@change.org", user.getEmail());
        assertTrue(user.isVerified());
    }

    @Test
    void update_existingUser_if_username_different() {
        Map<String, Object> attributeMappings = new HashMap<>();
        attributeMappings.put("given_name", "firstName");
        attributeMappings.put("family_name", "lastName");
        attributeMappings.put("email", "emailAddress");
        attributeMappings.put("phone_number", "phone");
        providerDefinition.setAttributeMappings(attributeMappings);
        provider.setConfig(providerDefinition);
        providerProvisioning.update(provider, identityZoneManager.getCurrentIdentityZone().getId());

        getAuthentication(authprovider);

        UaaUser originalUser = userDatabase.retrieveUserByEmail("marissa.bloggs@test.com", OriginKeys.SAML);
        assertNotNull(originalUser);
        assertEquals("marissa-saml", originalUser.getUsername());

        LinkedMultiValueMap<String, String> attributes = new LinkedMultiValueMap<>();
        attributes.add(GIVEN_NAME_ATTRIBUTE_NAME, "Marissa");
        attributes.add(FAMILY_NAME_ATTRIBUTE_NAME, "Bloggs");
        attributes.add(EMAIL_ATTRIBUTE_NAME, "marissa.bloggs@test.com");
        attributes.add(PHONE_NUMBER_ATTRIBUTE_NAME, "1234567890");

        UaaPrincipal samlPrincipal = new UaaPrincipal(OriginKeys.NotANumber, "marissa-saml-changed", "marissa.bloggs@test.com", OriginKeys.SAML, "marissa-saml-changed", identityZoneManager.getCurrentIdentityZone().getId());
        UaaUser user = authprovider.createIfMissing(samlPrincipal, false, new ArrayList<SimpleGrantedAuthority>(), attributes);

        assertNotNull(user);
        assertEquals("marissa-saml-changed", user.getUsername());
    }

    @Test
    void dont_update_existingUser_if_attributes_areTheSame() {
        getAuthentication(authprovider);
        UaaUser user = userDatabase.retrieveUserByName("marissa-saml", OriginKeys.SAML);

        getAuthentication(authprovider);
        UaaUser existingUser = userDatabase.retrieveUserByName("marissa-saml", OriginKeys.SAML);

        assertEquals(existingUser.getModified(), user.getModified());
    }

    @Test
    void have_attributes_changed() {
        getAuthentication(authprovider);
        UaaUser existing = userDatabase.retrieveUserByName("marissa-saml", OriginKeys.SAML);
        UaaUser modified = new UaaUser(new UaaUserPrototype(existing));
        assertFalse(authprovider.haveUserAttributesChanged(existing, modified), "Nothing modified");
        modified = new UaaUser(new UaaUserPrototype(existing).withEmail("other-email"));
        assertTrue(authprovider.haveUserAttributesChanged(existing, modified), "Email modified");
        modified = new UaaUser(new UaaUserPrototype(existing).withPhoneNumber("other-phone"));
        assertTrue(authprovider.haveUserAttributesChanged(existing, modified), "Phone number modified");
        modified = new UaaUser(new UaaUserPrototype(existing).withVerified(!existing.isVerified()));
        assertTrue(authprovider.haveUserAttributesChanged(existing, modified), "Verified email modified");
        modified = new UaaUser(new UaaUserPrototype(existing).withGivenName("other-given"));
        assertTrue(authprovider.haveUserAttributesChanged(existing, modified), "First name modified");
        modified = new UaaUser(new UaaUserPrototype(existing).withFamilyName("other-family"));
        assertTrue(authprovider.haveUserAttributesChanged(existing, modified), "Last name modified");
    }

    @Test
    void shadowAccount_createdWith_MappedUserAttributes() {
        Map<String, Object> attributeMappings = new HashMap<>();
        attributeMappings.put("given_name", "firstName");
        attributeMappings.put("family_name", "lastName");
        attributeMappings.put("email", "emailAddress");
        attributeMappings.put("phone_number", "phone");
        providerDefinition.setAttributeMappings(attributeMappings);
        provider.setConfig(providerDefinition);
        providerProvisioning.update(provider, identityZoneManager.getCurrentIdentityZone().getId());

        getAuthentication(authprovider);
        UaaUser user = userDatabase.retrieveUserByName("marissa-saml", OriginKeys.SAML);
        assertEquals("Marissa", user.getGivenName());
        assertEquals("Bloggs", user.getFamilyName());
        assertEquals("marissa.bloggs@test.com", user.getEmail());
        assertEquals("1234567890", user.getPhoneNumber());
    }

    @Test
    void custom_user_attributes_stored_if_configured() {
        Map<String, Object> attributeMappings = new HashMap<>();
        attributeMappings.put("given_name", "firstName");
        attributeMappings.put("family_name", "lastName");
        attributeMappings.put("email", "emailAddress");
        attributeMappings.put("phone_number", "phone");
        attributeMappings.put(USER_ATTRIBUTE_PREFIX + "secondary_email", "emailAddress");
        providerDefinition.setAttributeMappings(attributeMappings);
        providerDefinition.setStoreCustomAttributes(false);
        provider.setConfig(providerDefinition);
        provider = providerProvisioning.update(provider, identityZoneManager.getCurrentIdentityZone().getId());

        UaaAuthentication authentication = getAuthentication(authprovider);
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
        provider = providerProvisioning.update(provider, identityZoneManager.getCurrentIdentityZone().getId());
        authentication = getAuthentication(authprovider);
        assertEquals("marissa.bloggs@test.com", authentication.getUserAttributes().getFirst("secondary_email"));
        userInfo = userDatabase.getUserInfo(user.getId());
        assertNotNull(userInfo);
        assertEquals("marissa.bloggs@test.com", userInfo.getUserAttributes().getFirst("secondary_email"));
        assertNotNull(userInfo.getRoles());
        assertEquals(1, userInfo.getRoles().size());
        assertEquals(SAML_ADMIN, userInfo.getRoles().get(0));
    }

    @Test
    void authnContext_isvalidated_fail() {
        providerDefinition.setAuthnContext(Arrays.asList("some-context", "another-context"));
        provider.setConfig(providerDefinition);
        providerProvisioning.update(provider, identityZoneManager.getCurrentIdentityZone().getId());

        try {
            getAuthentication(authprovider);
            fail("Expected authentication to throw BadCredentialsException");
        } catch (BadCredentialsException ignored) {

        }
    }

    @Test
    void authnContext_isvalidated_good() {
        providerDefinition.setAuthnContext(Collections.singletonList(AuthnContext.PASSWORD_AUTHN_CTX));
        provider.setConfig(providerDefinition);
        providerProvisioning.update(provider, identityZoneManager.getCurrentIdentityZone().getId());

        try {
            getAuthentication(authprovider);
        } catch (BadCredentialsException ex) {
            fail("Expected authentication to succeed");
        }
    }

    @Test
    void shadowAccountNotCreated_givenShadowAccountCreationDisabled() {
        Map<String, Object> attributeMappings = new HashMap<>();
        attributeMappings.put("given_name", "firstName");
        attributeMappings.put("family_name", "lastName");
        attributeMappings.put("email", "emailAddress");
        attributeMappings.put("phone_number", "phone");
        providerDefinition.setAttributeMappings(attributeMappings);
        providerDefinition.setAddShadowUserOnLogin(false);
        provider.setConfig(providerDefinition);
        providerProvisioning.update(provider, identityZoneManager.getCurrentIdentityZone().getId());

        try {
            getAuthentication(authprovider);
            fail("Expected authentication to throw LoginSAMLException");
        } catch (LoginSAMLException ignored) {

        }

        try {
            userDatabase.retrieveUserByName("marissa-saml", OriginKeys.SAML);
            fail("Expected user not to exist in database");
        } catch (UsernameNotFoundException ignored) {

        }
    }

    @Test
    void should_NotCreateShadowAccount_AndInstead_UpdateExistingUserUsername_if_userWithEmailExists() {
        Map<String, Object> attributeMappings = new HashMap<>();
        attributeMappings.put("email", "emailAddress");
        providerDefinition.setAttributeMappings(attributeMappings);
        provider.setConfig(providerDefinition);
        providerProvisioning.update(provider, identityZoneManager.getCurrentIdentityZone().getId());

        ScimUser createdUser = createSamlUser("marissa.bloggs@test.com", identityZoneManager.getCurrentIdentityZone().getId(), userProvisioning);

        getAuthentication(authprovider);

        UaaUser uaaUser = userDatabase.retrieveUserByName("marissa-saml", OriginKeys.SAML);
        assertEquals(createdUser.getId(), uaaUser.getId());
        assertEquals("marissa-saml", uaaUser.getUsername());
    }

    @Test
    void error_when_multipleUsers_with_sameEmail() {
        Map<String, Object> attributeMappings = new HashMap<>();
        attributeMappings.put("email", "emailAddress");
        providerDefinition.setAttributeMappings(attributeMappings);
        provider.setConfig(providerDefinition);
        providerProvisioning.update(provider, identityZoneManager.getCurrentIdentityZone().getId());

        createSamlUser("marissa.bloggs@test.com", identityZoneManager.getCurrentIdentityZone().getId(), userProvisioning);
        createSamlUser("marissa.bloggs", identityZoneManager.getCurrentIdentityZone().getId(), userProvisioning);

        assertThrows(IncorrectResultSizeDataAccessException.class, () -> getAuthentication(authprovider));
    }

    @Test
    void shadowUser_GetsCreatedWithDefaultValues_IfAttributeNotMapped() {
        Map<String, Object> attributeMappings = new HashMap<>();
        attributeMappings.put("surname", "lastName");
        attributeMappings.put("email", "emailAddress");
        providerDefinition.setAttributeMappings(attributeMappings);
        provider.setConfig(providerDefinition);
        providerProvisioning.update(provider, identityZoneManager.getCurrentIdentityZone().getId());

        UaaAuthentication authentication = getAuthentication(authprovider);
        UaaUser user = userDatabase.retrieveUserByName("marissa-saml", OriginKeys.SAML);
        assertEquals("marissa.bloggs", user.getGivenName());
        assertEquals("test.com", user.getFamilyName());
        assertEquals("marissa.bloggs@test.com", user.getEmail());
        assertEquals(0, authentication.getUserAttributes().size(), "No custom attributes have been mapped");
    }

    @Test
    void user_authentication_contains_custom_attributes() {
        String COST_CENTERS = COST_CENTER + "s";
        String MANAGERS = MANAGER + "s";

        Map<String, Object> attributeMappings = new HashMap<>();

        attributeMappings.put(USER_ATTRIBUTE_PREFIX + COST_CENTERS, COST_CENTER);
        attributeMappings.put(USER_ATTRIBUTE_PREFIX + MANAGERS, MANAGER);

        providerDefinition.setAttributeMappings(attributeMappings);
        provider.setConfig(providerDefinition);
        providerProvisioning.update(provider, identityZoneManager.getCurrentIdentityZone().getId());

        UaaAuthentication authentication = getAuthentication(authprovider);

        assertEquals(2, authentication.getUserAttributes().size(), "Expected two user attributes");
        assertNotNull(authentication.getUserAttributes().get(COST_CENTERS), "Expected cost center attribute");
        assertEquals(DENVER_CO, authentication.getUserAttributes().getFirst(COST_CENTERS));

        assertNotNull(authentication.getUserAttributes().get(MANAGERS), "Expected manager attribute");
        assertEquals(2, authentication.getUserAttributes().get(MANAGERS).size(), "Expected 2 manager attribute values");
        assertThat(authentication.getUserAttributes().get(MANAGERS), containsInAnyOrder(JOHN_THE_SLOTH, KARI_THE_ANT_EATER));
    }

    @Test
    void getUserByDefaultUsesTheAvailableData() {
        UaaPrincipal principal = new UaaPrincipal(
                UUID.randomUUID().toString(),
                "user",
                "user@example.com",
                OriginKeys.SAML,
                "user",
                identityZoneManager.getCurrentIdentityZone().getId()
        );
        LinkedMultiValueMap<String, String> attributes = new LinkedMultiValueMap<>();
        attributes.add(EMAIL_ATTRIBUTE_NAME, "user@example.com");
        attributes.add(PHONE_NUMBER_ATTRIBUTE_NAME, "(415) 555-0111");
        attributes.add(GIVEN_NAME_ATTRIBUTE_NAME, "Jane");
        attributes.add(FAMILY_NAME_ATTRIBUTE_NAME, "Doe");
        attributes.add(EMAIL_VERIFIED_ATTRIBUTE_NAME, "true");

        UaaUser user = authprovider.getUser(principal, attributes);
        assertThat(user, is(
                aUaaUser()
                        .withUsername("user")
                        .withEmail("user@example.com")
                        .withPhoneNumber("(415) 555-0111")
                        .withPassword("")
                        .withGivenName("Jane")
                        .withFamilyName("Doe")
                        .withAuthorities(emptyIterable())
                        .withVerified(true)
                        .withOrigin(OriginKeys.SAML)
                        .withExternalId("user")
                        .withZoneId(identityZoneManager.getCurrentIdentityZoneId())
        ));
    }

    @Test
    void getUserWithoutOriginSuppliesDefaultsToLoginServer() {
        UaaPrincipal principal = new UaaPrincipal(
                UUID.randomUUID().toString(),
                "user",
                "user@example.com",
                null,
                "user",
                identityZoneManager.getCurrentIdentityZone().getId()
        );

        LinkedMultiValueMap<String, String> attributes = new LinkedMultiValueMap<>();
        UaaUser user = authprovider.getUser(principal, attributes);
        assertThat(user, is(aUaaUser().withOrigin(OriginKeys.LOGIN_SERVER)));
    }

    @Test
    void getUserWithoutVerifiedDefaultsToFalse() {
        UaaPrincipal principal = new UaaPrincipal(
                UUID.randomUUID().toString(),
                "user",
                "user@example.com",
                null,
                "user",
                identityZoneManager.getCurrentIdentityZone().getId()
        );

        LinkedMultiValueMap<String, String> attributes = new LinkedMultiValueMap<>();
        UaaUser user = authprovider.getUser(principal, attributes);
        assertThat(user, is(aUaaUser().withVerified(false)));
    }

    @Test
    void throwsIfUserNameAndEmailAreMissing() {
        UaaPrincipal principal = new UaaPrincipal(
                UUID.randomUUID().toString(),
                null,
                "user@example.com",
                null,
                "user",
                identityZoneManager.getCurrentIdentityZone().getId()
        );

        LinkedMultiValueMap<String, String> attributes = new LinkedMultiValueMap<>();

        assertThrowsWithMessageThat(
                BadCredentialsException.class,
                () -> authprovider.getUser(principal, attributes),
                is("Cannot determine username from credentials supplied")
        );
    }

    private static ScimUser createSamlUser(String username, String zoneId, ScimUserProvisioning userProvisioning) {
        ScimUser user = new ScimUser("", username, "Marissa", "Bloggs");
        user.setPrimaryEmail("marissa.bloggs@test.com");
        user.setOrigin(OriginKeys.SAML);
        return userProvisioning.createUser(user, "", zoneId);
    }

    private static UaaAuthentication getAuthentication(LoginSamlAuthenticationProvider authprovider) {
        SAMLAuthenticationToken authentication1 = mockSamlAuthentication();
        Authentication authentication = authprovider.authenticate(authentication1);
        assertNotNull(authentication, "Authentication should exist");
        assertTrue(authentication instanceof UaaAuthentication, "Authentication should be UaaAuthentication");
        return (UaaAuthentication) authentication;
    }

    private static SAMLAuthenticationToken mockSamlAuthentication() {
        ExtendedMetadata metadata = mock(ExtendedMetadata.class);
        when(metadata.getAlias()).thenReturn(OriginKeys.SAML);
        SAMLMessageContext contxt = mock(SAMLMessageContext.class);

        when(contxt.getPeerExtendedMetadata()).thenReturn(metadata);
        when(contxt.getCommunicationProfileId()).thenReturn(SAMLConstants.SAML2_WEBSSO_PROFILE_URI);
        return new SAMLAuthenticationToken(contxt);
    }

    public static class CreateUserPublisher implements ApplicationEventPublisher {
        final ScimUserBootstrap bootstrap;
        final List<ApplicationEvent> events = new ArrayList<>();

        CreateUserPublisher(ScimUserBootstrap bootstrap) {
            this.bootstrap = bootstrap;
        }


        @Override
        public void publishEvent(ApplicationEvent event) {
            events.add(event);
            if (event instanceof AuthEvent) {
                bootstrap.onApplicationEvent((AuthEvent) event);
            }
        }

        @Override
        public void publishEvent(Object event) {
            throw new UnsupportedOperationException("not implemented");
        }
    }

    private static final String IDP_META_DATA = getResourceAsString(LoginSamlAuthenticationProviderTests.class, "IDP_META_DATA.xml");

    private static List<Attribute> getAttributes(Map<String, Object> values) {
        List<Attribute> result = new LinkedList<>();
        for (Map.Entry<String, Object> entry : values.entrySet()) {
            result.addAll(getAttributes(entry.getKey(), entry.getValue()));
        }
        return result;
    }

    private static List<Attribute> getAttributes(final String name, Object value) {
        Attribute attribute = mock(Attribute.class);
        when(attribute.getName()).thenReturn(name);
        when(attribute.getFriendlyName()).thenReturn(name);

        List<XMLObject> xmlObjects = new LinkedList<>();
        if ("XSURI".equals(name)) {
            XSURIImpl impl = new AttributedURIImpl("", "", "");
            impl.setValue((String) value);
            xmlObjects.add(impl);
        } else if ("XSAny".equals(name)) {
            XSAnyImpl impl = new XSAnyImpl("", "", "") {
            };
            impl.setTextContent((String) value);
            xmlObjects.add(impl);
        } else if ("XSQName".equals(name)) {
            XSQNameImpl impl = new XSQNameImpl("", "", "") {
            };
            impl.setValue(new QName("", (String) value));
            xmlObjects.add(impl);
        } else if ("XSInteger".equals(name)) {
            XSIntegerImpl impl = new XSIntegerImpl("", "", "") {
            };
            impl.setValue((Integer) value);
            xmlObjects.add(impl);
        } else if ("XSBoolean".equals(name)) {
            XSBooleanImpl impl = new XSBooleanImpl("", "", "") {
            };
            impl.setValue(new XSBooleanValue((Boolean) value, false));
            xmlObjects.add(impl);
        } else if ("XSDateTime".equals(name)) {
            XSDateTimeImpl impl = new XSDateTimeImpl("", "", "") {
            };
            impl.setValue((DateTime) value);
            xmlObjects.add(impl);
        } else if ("XSBase64Binary".equals(name)) {
            XSBase64BinaryImpl impl = new XSBase64BinaryImpl("", "", "") {
            };
            impl.setValue((String) value);
            xmlObjects.add(impl);
        } else if (value instanceof List) {
            for (String s : (List<String>) value) {
                if (SAML_USER.equals(s)) {
                    XSAnyImpl impl = new XSAnyImpl("", "", "") {
                    };
                    impl.setTextContent(s);
                    xmlObjects.add(impl);
                } else {
                    AttributedStringImpl impl = new AttributedStringImpl("", "", "");
                    impl.setValue(s);
                    xmlObjects.add(impl);
                }
            }
        } else if (value instanceof Boolean) {
            XSBoolean impl = new XSBooleanBuilder().buildObject("", "", "");
            impl.setValue(new XSBooleanValue((Boolean) value, false));
            xmlObjects.add(impl);
        } else {
            AttributedStringImpl impl = new AttributedStringImpl("", "", "");
            impl.setValue((String) value);
            xmlObjects.add(impl);
        }
        when(attribute.getAttributeValues()).thenReturn(xmlObjects);
        return Collections.singletonList(attribute);
    }

    private static SAMLCredential getUserCredential(String username, String firstName, String lastName, String emailAddress, String phoneNumber) {
        return getUserCredential(username,
                firstName,
                lastName,
                emailAddress,
                phoneNumber,
                null);
    }

    private static SAMLCredential getUserCredential(String username,
                                                    String firstName,
                                                    String lastName,
                                                    String emailAddress,
                                                    String phoneNumber,
                                                    Boolean emailVerified) {
        NameID usernameID = mock(NameID.class);
        when(usernameID.getValue()).thenReturn(username);

        Map<String, Object> attributes = new HashMap<>();
        attributes.put("firstName", firstName);
        attributes.put("lastName", lastName);
        attributes.put("emailAddress", emailAddress);
        attributes.put("phone", phoneNumber);
        attributes.put("groups", Arrays.asList(SAML_USER, SAML_ADMIN, SAML_NOT_MAPPED));
        attributes.put("2ndgroups", Collections.singletonList(SAML_TEST));
        attributes.put(COST_CENTER, Collections.singletonList(DENVER_CO));
        attributes.put(MANAGER, Arrays.asList(JOHN_THE_SLOTH, KARI_THE_ANT_EATER));
        if (emailVerified != null) {
            attributes.put("emailVerified", emailVerified);
        }

        //test different types
        attributes.put("XSURI", "http://localhost:8080/someuri");
        attributes.put("XSAny", "XSAnyValue");
        attributes.put("XSQName", "XSQNameValue");
        attributes.put("XSInteger", 3);
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
        when(authenticationAssertion.getAuthnStatements()).thenReturn(Collections.singletonList(statement));

        return new SAMLCredential(
                usernameID,
                authenticationAssertion,
                "remoteEntityID",
                getAttributes(attributes),
                "localEntityID");
    }
}
