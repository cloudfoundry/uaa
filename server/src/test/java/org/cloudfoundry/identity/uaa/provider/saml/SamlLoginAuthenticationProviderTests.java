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
import org.cloudfoundry.identity.uaa.user.UserInfo;
import org.cloudfoundry.identity.uaa.util.TimeService;
import org.cloudfoundry.identity.uaa.util.TimeServiceImpl;
import org.cloudfoundry.identity.uaa.util.beans.DbUtils;
import org.cloudfoundry.identity.uaa.web.UaaSavedRequestAwareAuthenticationSuccessHandler;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.JdbcIdentityZoneProvisioning;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManagerImpl;
import org.joda.time.DateTime;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EmptySource;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.opensaml.core.config.InitializationException;
import org.opensaml.core.config.InitializationService;
import org.opensaml.saml.saml2.core.AuthnContext;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.dao.IncorrectResultSizeDataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.saml2.provider.service.authentication.AbstractSaml2AuthenticationRequest;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationToken;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.web.context.request.ServletWebRequest;

import javax.servlet.ServletContext;
import java.sql.SQLException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assumptions.assumeThat;
import static org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition.EMAIL_ATTRIBUTE_NAME;
import static org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition.EMAIL_VERIFIED_ATTRIBUTE_NAME;
import static org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition.FAMILY_NAME_ATTRIBUTE_NAME;
import static org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition.GIVEN_NAME_ATTRIBUTE_NAME;
import static org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition.GROUP_ATTRIBUTE_NAME;
import static org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition.PHONE_NUMBER_ATTRIBUTE_NAME;
import static org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition.USER_ATTRIBUTE_PREFIX;
import static org.cloudfoundry.identity.uaa.provider.saml.Saml2TestUtils.authenticationToken;
import static org.cloudfoundry.identity.uaa.test.ModelTestUtils.getResourceAsString;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@WithDatabaseContext
class SamlLoginAuthenticationProviderTests {

    private static final String SAML_USER = "saml.user";
    private static final String SAML_ADMIN = "saml.admin";
    private static final String SAML_TEST = "saml.test";
    private static final String SAML_NOT_MAPPED = "saml.unmapped";
    private static final String UAA_USER = "uaa.user";
    private static final String UAA_SAML_USER = "uaa.saml.user";
    private static final String UAA_SAML_ADMIN = "uaa.saml.admin";
    private static final String UAA_SAML_TEST = "uaa.saml.test";
    private static final String COST_CENTER = "costCenter";
    private static final String DENVER_CO = "Denver,CO";
    private static final String MANAGER = "manager";
    private static final String JOHN_THE_SLOTH = "John the Sloth";
    private static final String KARI_THE_ANT_EATER = "Kari the Ant Eater";
    private static final String IDP_META_DATA = getResourceAsString(
            SamlLoginAuthenticationProviderTests.class, "IDP_META_DATA.xml");

    private static final String TEST_EMAIL = "john.doe@example.com";
    private static final String TEST_USERNAME = "test@saml.user";
    private static final String TEST_PHONE_NUMBER = "123-456-7890";
    @Autowired
    NamedParameterJdbcTemplate namedJdbcTemplate;
    private JdbcIdentityProviderProvisioning providerProvisioning;
    private CreateUserPublisher publisher;
    private JdbcUaaUserDatabase userDatabase;
    private AuthenticationProvider authprovider;
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

    private static ScimUser createSamlUser(String username, String zoneId,
                                           ScimUserProvisioning userProvisioning) {
        ScimUser user = new ScimUser("", username, "Marissa", "Bloggs");
        user.setPrimaryEmail(TEST_EMAIL);
        user.setOrigin(OriginKeys.SAML);
        return userProvisioning.createUser(user, "", zoneId);
    }

    private UaaAuthentication authenticate() {
        return authenticate(authenticationToken());
    }

    private UaaAuthentication authenticate(Authentication inAuthentication) {
        Authentication authentication = authprovider.authenticate(inAuthentication);
        assertThat(authentication).isInstanceOf(UaaAuthentication.class);
        return (UaaAuthentication) authentication;
    }

    @BeforeEach
    void configureProvider() throws SecurityException, SQLException, InitializationException {
        identityZoneManager = new IdentityZoneManagerImpl();
        RequestContextHolder.resetRequestAttributes();
        MockHttpServletRequest request = new MockHttpServletRequest(mock(ServletContext.class));
        MockHttpServletResponse response = new MockHttpServletResponse();
        ServletWebRequest servletWebRequest = new ServletWebRequest(request, response);
        RequestContextHolder.setRequestAttributes(servletWebRequest);
        DbUtils dbUtils = new DbUtils();

        InitializationService.initialize();

        ScimGroupProvisioning groupProvisioning = new JdbcScimGroupProvisioning(
                namedJdbcTemplate, new JdbcPagingListFactory(namedJdbcTemplate, limitSqlAdapter),
                dbUtils);
        identityZoneManager.getCurrentIdentityZone().getConfig().getUserConfig()
                .setDefaultGroups(Collections.singletonList(UAA_USER));
        identityZoneManager.getCurrentIdentityZone().getConfig().getUserConfig()
                .setAllowedGroups(Arrays.asList(UAA_USER, SAML_USER,
                        SAML_ADMIN, SAML_TEST, SAML_NOT_MAPPED, UAA_SAML_USER, UAA_SAML_ADMIN,
                        UAA_SAML_TEST));
        groupProvisioning.createOrGet(
                new ScimGroup(null, UAA_USER, identityZoneManager.getCurrentIdentityZone().getId()),
                identityZoneManager.getCurrentIdentityZone().getId());

        userProvisioning = new JdbcScimUserProvisioning(namedJdbcTemplate,
                new JdbcPagingListFactory(namedJdbcTemplate, limitSqlAdapter), passwordEncoder,
                new IdentityZoneManagerImpl(), new JdbcIdentityZoneProvisioning(jdbcTemplate));

        uaaSamlUser = groupProvisioning.create(
                new ScimGroup(null, UAA_SAML_USER, IdentityZone.getUaaZoneId()),
                identityZoneManager.getCurrentIdentityZone().getId());
        uaaSamlAdmin = groupProvisioning.create(
                new ScimGroup(null, UAA_SAML_ADMIN, IdentityZone.getUaaZoneId()),
                identityZoneManager.getCurrentIdentityZone().getId());
        ScimGroup uaaSamlTest = groupProvisioning.create(
                new ScimGroup(null, UAA_SAML_TEST, IdentityZone.getUaaZoneId()),
                identityZoneManager.getCurrentIdentityZone().getId());

        JdbcScimGroupMembershipManager membershipManager = new JdbcScimGroupMembershipManager(
                jdbcTemplate, new TimeServiceImpl(), userProvisioning, null, dbUtils);
        membershipManager.setScimGroupProvisioning(groupProvisioning);
        ScimUserBootstrap bootstrap = new ScimUserBootstrap(userProvisioning, groupProvisioning,
                membershipManager, Collections.emptyList(), false, Collections.emptyList());

        externalManager = new JdbcScimGroupExternalMembershipManager(jdbcTemplate, dbUtils);
        externalManager.setScimGroupProvisioning(groupProvisioning);
        externalManager.mapExternalGroup(uaaSamlUser.getId(), SAML_USER, OriginKeys.SAML,
                identityZoneManager.getCurrentIdentityZone().getId());
        externalManager.mapExternalGroup(uaaSamlAdmin.getId(), SAML_ADMIN, OriginKeys.SAML,
                identityZoneManager.getCurrentIdentityZone().getId());
        externalManager.mapExternalGroup(uaaSamlTest.getId(), SAML_TEST, OriginKeys.SAML,
                identityZoneManager.getCurrentIdentityZone().getId());

        TimeService timeService = mock(TimeService.class);
        DatabaseUrlModifier databaseUrlModifier = mock(DatabaseUrlModifier.class);
        when(databaseUrlModifier.getDatabaseType()).thenReturn(Vendor.unknown);
        userDatabase = new JdbcUaaUserDatabase(jdbcTemplate, timeService, false,
                identityZoneManager,
                databaseUrlModifier, new DbUtils());
        providerProvisioning = new JdbcIdentityProviderProvisioning(jdbcTemplate);
        publisher = new CreateUserPublisher(bootstrap);

        SamlAuthenticationFilterConfig samlAuthenticationFilterConfig = new SamlAuthenticationFilterConfig();
        authprovider = samlAuthenticationFilterConfig.samlAuthenticationProvider(
                identityZoneManager, userDatabase, providerProvisioning, externalManager, publisher);

        providerDefinition = new SamlIdentityProviderDefinition();
        providerDefinition.setMetaDataLocation(String.format(IDP_META_DATA, OriginKeys.SAML));
        providerDefinition.setIdpEntityAlias(OriginKeys.SAML);

        provider = new IdentityProvider<>();
        provider.setIdentityZoneId(IdentityZone.getUaaZoneId());
        provider.setOriginKey(OriginKeys.SAML);
        provider.setName("saml-test");
        provider.setActive(true);
        provider.setType(OriginKeys.SAML);
        provider.setConfig(providerDefinition);
        provider = providerProvisioning.create(provider,
                identityZoneManager.getCurrentIdentityZone().getId());
    }

    @AfterEach
    void tearDown(@Autowired ApplicationContext applicationContext) throws SQLException {
        TestUtils.restoreToDefaults(applicationContext);
        RequestContextHolder.resetRequestAttributes();
    }

    @Test
    void testAuthenticateSimple() {
        assertThat(authprovider.authenticate(authenticationToken())).isNotNull();
    }

    @ParameterizedTest(name = "#{index} relayRedirectRejectsNonUrls - {0}")
    @ValueSource(strings = {"test", "www.google.com"})
    @NullSource
    @EmptySource
    void relayRedirectRejectsNonUrls(String url) {
        SamlLoginAuthenticationProvider authprovider = (SamlLoginAuthenticationProvider) this.authprovider;
        authprovider.getResponseAuthenticationConverter().configureRelayRedirect(url);
        assertThat(RequestContextHolder.currentRequestAttributes()
                .getAttribute(UaaSavedRequestAwareAuthenticationSuccessHandler.URI_OVERRIDE_ATTRIBUTE,
                        RequestAttributes.SCOPE_REQUEST))
                .isNull();
    }

    @Test
    void relayRedirectIsSetForUrl() {
        String redirectUrl = "https://www.cloudfoundry.org";

        Saml2AuthenticationToken authenticationToken = authenticationToken();
        AbstractSaml2AuthenticationRequest mockAuthenticationRequest = authenticationToken.getAuthenticationRequest();
        when(mockAuthenticationRequest.getRelayState()).thenReturn(redirectUrl);
        UaaAuthentication uaaAuthentication = authenticate(authenticationToken);

        assertThat(RequestContextHolder.currentRequestAttributes()
                .getAttribute(UaaSavedRequestAwareAuthenticationSuccessHandler.URI_OVERRIDE_ATTRIBUTE,
                        RequestAttributes.SCOPE_REQUEST))
                .isEqualTo(redirectUrl);
        assertThat(uaaAuthentication.getAuthContextClassRef()).contains(
                AuthnContext.PASSWORD_AUTHN_CTX);
    }

    @Test
    void testAuthenticationEvents() {
        authprovider.authenticate(authenticationToken());
        assertEquals(3, publisher.events.size());
        assertInstanceOf(IdentityProviderAuthenticationSuccessEvent.class, publisher.events.get(2));
    }


    @Test
    void saml_authentication_contains_acr() {
        Saml2AuthenticationToken mockAuthenticationToken = authenticationToken();
        UaaAuthentication uaaAuthentication = authenticate(mockAuthenticationToken);
        assertThat(uaaAuthentication.getAuthContextClassRef()).contains(
                AuthnContext.PASSWORD_AUTHN_CTX);
        verify(mockAuthenticationToken.getAuthenticationRequest(), times(1)).getRelayState();
        assertThat(RequestContextHolder.currentRequestAttributes()
                .getAttribute(UaaSavedRequestAwareAuthenticationSuccessHandler.URI_OVERRIDE_ATTRIBUTE,
                        RequestAttributes.SCOPE_REQUEST))
                .isNull();
    }

    @Test
    void multipleGroupAttributesMapping() {
        providerDefinition.addAttributeMapping(GROUP_ATTRIBUTE_NAME,
                Arrays.asList("2ndgroups", "groups"));
        provider.setConfig(providerDefinition);
        providerProvisioning.update(provider, identityZoneManager.getCurrentIdentityZone().getId());
        UaaAuthentication authentication = authenticate();
        assertThat(authentication.getAuthorities()).
                containsExactlyInAnyOrder(
                        new SimpleGrantedAuthority(UAA_SAML_ADMIN),
                        new SimpleGrantedAuthority(UAA_SAML_USER),
                        new SimpleGrantedAuthority(UAA_SAML_TEST),
                        new SimpleGrantedAuthority(UaaAuthority.UAA_USER.getAuthority())
                );
    }

    @Test
    void authenticationContainsAmr() {
        UaaAuthentication authentication = authenticate();
        assertThat(authentication.getAuthenticationMethods()).contains("ext");
    }

    @Test
    void test_external_groups_as_scopes() {
        providerDefinition.setGroupMappingMode(
                SamlIdentityProviderDefinition.ExternalGroupMappingMode.AS_SCOPES);
        providerDefinition.addAttributeMapping(GROUP_ATTRIBUTE_NAME,
                Arrays.asList("2ndgroups", "groups"));
        provider.setConfig(providerDefinition);
        providerProvisioning.update(provider, identityZoneManager.getCurrentIdentityZone().getId());
        UaaAuthentication authentication = authenticate();
        assertThat(authentication.getAuthorities()).containsExactlyInAnyOrder(
                new SimpleGrantedAuthority(SAML_ADMIN),
                new SimpleGrantedAuthority(SAML_USER),
                new SimpleGrantedAuthority(SAML_TEST),
                new SimpleGrantedAuthority(SAML_NOT_MAPPED),
                new SimpleGrantedAuthority(UaaAuthority.UAA_USER.getAuthority())
        );
    }

    @Test
    void test_group_mapping() {
        providerDefinition.addAttributeMapping(GROUP_ATTRIBUTE_NAME, "groups");
        provider.setConfig(providerDefinition);
        providerProvisioning.update(provider, identityZoneManager.getCurrentIdentityZone().getId());
        UaaAuthentication authentication = authenticate();
        assertThat(authentication.getAuthorities()).containsExactlyInAnyOrder(
                new SimpleGrantedAuthority(UAA_SAML_ADMIN),
                new SimpleGrantedAuthority(UAA_SAML_USER),
                new SimpleGrantedAuthority(UaaAuthority.UAA_USER.getAuthority())
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
        UaaAuthentication authentication = authenticate();

        assertThat(authentication.getUserAttributes())
                .containsEntry("XSURI", List.of("http://localhost:8080/someuri"))
                .containsEntry("XSAny", List.of("XSAnyValue"))
                .containsEntry("XSQName", List.of("XSQNameValue"))
                .containsEntry("XSInteger", List.of("3"))
                .containsEntry("XSBoolean", List.of("true"))
                .containsEntry("XSDateTime", List.of("1970-01-01T00:00:00Z"))
                .containsEntry("XSBase64Binary", List.of("00001111"));
    }

    @Test
    void externalGroupNotMappedToScope() {
        externalManager.unmapExternalGroup(uaaSamlUser.getId(), SAML_USER, OriginKeys.SAML,
                identityZoneManager.getCurrentIdentityZone().getId());
        externalManager.unmapExternalGroup(uaaSamlAdmin.getId(), SAML_ADMIN, OriginKeys.SAML,
                identityZoneManager.getCurrentIdentityZone().getId());
        providerDefinition.addAttributeMapping(GROUP_ATTRIBUTE_NAME, "groups");
        provider.setConfig(providerDefinition);
        providerProvisioning.update(provider, identityZoneManager.getCurrentIdentityZone().getId());
        UaaAuthentication authentication = authenticate();
        assertThat(authentication.getAuthorities()).hasSize(1).doesNotContainAnyElementsOf(List.of(
                new SimpleGrantedAuthority(UAA_SAML_ADMIN),
                new SimpleGrantedAuthority(UAA_SAML_USER))
        );
    }

    @Test
    void uaaUserAuthorityGrantedIfNoOtherProvided() {
        UaaAuthentication uaaAuthentication = authenticate();
        assertThat(uaaAuthentication.getAuthorities()).containsExactly(
                new SimpleGrantedAuthority(UaaAuthority.UAA_USER.getAuthority())
        );
    }

    @Test
    void dontAddExternalGroupsToAuthenticationWithoutWhitelist() {
        providerDefinition.addAttributeMapping(GROUP_ATTRIBUTE_NAME, "groups");
        provider.setConfig(providerDefinition);
        providerProvisioning.update(provider, identityZoneManager.getCurrentIdentityZone().getId());

        UaaAuthentication authentication = authenticate();
        assertThat(authentication.getExternalGroups()).isEmpty();
    }

    @Test
    void addExternalGroupsToAuthenticationWithWhitelist() {
        providerDefinition.addAttributeMapping(GROUP_ATTRIBUTE_NAME, "groups");
        providerDefinition.addWhiteListedGroup(SAML_ADMIN);
        provider.setConfig(providerDefinition);
        providerProvisioning.update(provider, identityZoneManager.getCurrentIdentityZone().getId());

        UaaAuthentication authentication = authenticate();
        assertEquals(Collections.singleton(SAML_ADMIN), authentication.getExternalGroups());
    }

    @Test
    void addExternalGroupsToAuthenticationWithWildcardWhitelist() {
        providerDefinition.addAttributeMapping(GROUP_ATTRIBUTE_NAME, "groups");
        providerDefinition.addWhiteListedGroup("saml*");
        provider.setConfig(providerDefinition);
        providerProvisioning.update(provider, identityZoneManager.getCurrentIdentityZone().getId());
        UaaAuthentication authentication = authenticate();
        assertThat(authentication.getExternalGroups()).containsExactlyInAnyOrder(SAML_USER, SAML_ADMIN, SAML_NOT_MAPPED);
    }

    @Test
    @Disabled("SAML test doesn't compile")
    void update_invitedUser_whose_username_is_notEmail() throws Exception {
        ScimUser scimUser = getInvitedUser();

//        SAMLCredential credential = getUserCredential("marissa-invited", "Marissa-invited", null, "marissa.invited@test.org", null);
//        when(consumer.processAuthenticationResponse(any())).thenReturn(credential);
//        getAuthentication(authprovider);

        UaaUser user = userDatabase.retrieveUserById(scimUser.getId());
        assertFalse(user.isVerified());
        assertEquals("marissa-invited", user.getUsername());
        assertEquals("marissa.invited@test.org", user.getEmail());

        RequestContextHolder.resetRequestAttributes();
    }

    @Test
    @Disabled("SAML test doesn't compile")
    void invitedUser_authentication_whenAuthenticatedEmailDoesNotMatchInvitedEmail()
            throws Exception {
        Map<String, Object> attributeMappings = new HashMap<>();
        attributeMappings.put("email", "emailAddress");
        providerDefinition.setAttributeMappings(attributeMappings);
        provider.setConfig(providerDefinition);
        providerProvisioning.update(provider, identityZoneManager.getCurrentIdentityZone().getId());

        ScimUser scimUser = getInvitedUser();

//        SAMLCredential credential = getUserCredential("marissa-invited", "Marissa-invited", null, "different@test.org", null);
//        when(consumer.processAuthenticationResponse(any())).thenReturn(credential);
//        try {
//            getAuthentication(authprovider);
//            fail();
//        } catch (BadCredentialsException e) {
//            UaaUser user = userDatabase.retrieveUserById(scimUser.getId());
//            assertFalse(user.isVerified());
//        }
        RequestContextHolder.resetRequestAttributes();
    }

    private ScimUser getInvitedUser() {
        ScimUser invitedUser = new ScimUser(null, "marissa.invited@test.org", "Marissa", "Bloggs");
        invitedUser.setVerified(false);
        invitedUser.setPrimaryEmail("marissa.invited@test.org");
        invitedUser.setOrigin(OriginKeys.UAA);
        ScimUser scimUser = userProvisioning.createUser(invitedUser, "getInvitedUser-password",
                identityZoneManager.getCurrentIdentityZone().getId());

        RequestAttributes attributes = new ServletRequestAttributes(new MockHttpServletRequest());
        attributes.setAttribute("IS_INVITE_ACCEPTANCE", true, RequestAttributes.SCOPE_SESSION);
        attributes.setAttribute("user_id", scimUser.getId(), RequestAttributes.SCOPE_SESSION);
        RequestContextHolder.setRequestAttributes(attributes);

        return scimUser;
    }

    @Test
    void updateExistingUserWithDifferentAttributes() throws Exception {
        try {
            userDatabase.retrieveUserByName(TEST_USERNAME, OriginKeys.SAML);
            fail("user should not exist");
        } catch (UsernameNotFoundException ignored) {
        }
        authenticate();

        UaaUser user = userDatabase.retrieveUserByName(TEST_USERNAME, OriginKeys.SAML);
        assertThat(user).returns("john.doe", UaaUser::getGivenName)
                .returns(TEST_EMAIL, UaaUser::getEmail);

        Map<String, Object> attributeMappings = new HashMap<>();
        attributeMappings.put("given_name", "firstName");
        attributeMappings.put("email", "emailAddress");
        providerDefinition.setAttributeMappings(attributeMappings);
        provider.setConfig(providerDefinition);
        providerProvisioning.update(provider, identityZoneManager.getCurrentIdentityZone().getId());
        authenticate();

        user = userDatabase.retrieveUserByName(TEST_USERNAME, OriginKeys.SAML);
        assertThat(user).returns("John", UaaUser::getGivenName)
                .returns(TEST_EMAIL, UaaUser::getEmail);

    }

    @Test
    @DisplayName("Can update existing user with different username but same email")
    void updateExistingUserWithDifferentUsername() {
        Map<String, Object> attributeMappings = new HashMap<>();
        attributeMappings.put("given_name", "firstName");
        attributeMappings.put("family_name", "lastName");
        attributeMappings.put("email", "emailAddress");
        attributeMappings.put("phone_number", "phone");
        providerDefinition.setAttributeMappings(attributeMappings);
        provider.setConfig(providerDefinition);
        providerProvisioning.update(provider, identityZoneManager.getCurrentIdentityZone().getId());

        authenticate();

        UaaUser originalUser = userDatabase.retrieveUserByEmail(TEST_EMAIL, OriginKeys.SAML);
        assertNotNull(originalUser);
        assertEquals(TEST_USERNAME, originalUser.getUsername());

        LinkedMultiValueMap<String, String> attributes = new LinkedMultiValueMap<>();
        attributes.add(GIVEN_NAME_ATTRIBUTE_NAME, "Marissa");
        attributes.add(FAMILY_NAME_ATTRIBUTE_NAME, "Bloggs");
        attributes.add(EMAIL_ATTRIBUTE_NAME, TEST_EMAIL);
        attributes.add(PHONE_NUMBER_ATTRIBUTE_NAME, TEST_PHONE_NUMBER);

        UaaPrincipal samlPrincipal = new UaaPrincipal(OriginKeys.NotANumber,
                "test-changed@saml.user", TEST_EMAIL, OriginKeys.SAML, TEST_USERNAME,
                identityZoneManager.getCurrentIdentityZone().getId());
        SamlUaaResponseAuthenticationConverter responseAuthenticationConverter = ((SamlLoginAuthenticationProvider) authprovider).getResponseAuthenticationConverter();
        UaaUser user = responseAuthenticationConverter.getUserManager()
                .createIfMissing(samlPrincipal, false, new ArrayList<SimpleGrantedAuthority>(),
                        attributes);

        assertNotNull(user);
        assertEquals("test-changed@saml.user", user.getUsername());
    }

    @Test
    void dontUpdateExistingUserIfAttributesSame() {
        authenticate();
        UaaUser user = userDatabase.retrieveUserByName(TEST_USERNAME, OriginKeys.SAML);

        authenticate();
        UaaUser existingUser = userDatabase.retrieveUserByName(TEST_USERNAME, OriginKeys.SAML);

        assertThat(existingUser.getModified()).isEqualTo(user.getModified());
    }

    @Test
    void createShadowAccountWithMappedUserAttributes() {
        Map<String, Object> attributeMappings = new HashMap<>();
        attributeMappings.put("given_name", "firstName");
        attributeMappings.put("family_name", "lastName");
        attributeMappings.put("email", "emailAddress");
        attributeMappings.put("phone_number", "phone");
        providerDefinition.setAttributeMappings(attributeMappings);
        provider.setConfig(providerDefinition);
        providerProvisioning.update(provider, identityZoneManager.getCurrentIdentityZone().getId());

        authenticate();

        UaaUser user = userDatabase.retrieveUserByName(TEST_USERNAME, OriginKeys.SAML);
        assertThat(user)
                .returns("John", UaaUser::getGivenName)
                .returns("Doe", UaaUser::getFamilyName)
                .returns(TEST_EMAIL, UaaUser::getEmail)
                .returns(TEST_PHONE_NUMBER, UaaUser::getPhoneNumber);
    }

    @Test
    void setStoreCustomAttributesInProviderDefinitionFalse() {
        providerDefinition.setStoreCustomAttributes(false);
        provider.setConfig(providerDefinition);
        providerProvisioning.update(provider, identityZoneManager.getCurrentIdentityZone().getId());

        authenticate();
        UaaUser user = userDatabase.retrieveUserByName(TEST_USERNAME, OriginKeys.SAML);
        UserInfo userInfo = userDatabase.getUserInfo(user.getId());
        assertThat(userInfo).isNull();
    }

    @Test
    void setStoreCustomAttributesInProviderDefinitionTrue() {
        providerDefinition.addAttributeMapping(USER_ATTRIBUTE_PREFIX + "secondary_email",
                "secondaryEmail");
        providerDefinition.setStoreCustomAttributes(true);
        provider.setConfig(providerDefinition);
        provider = providerProvisioning.update(provider, identityZoneManager.getCurrentIdentityZone().getId());

        authenticate();
        UaaUser user = userDatabase.retrieveUserByName(TEST_USERNAME, OriginKeys.SAML);
        UserInfo userInfo = userDatabase.getUserInfo(user.getId());
        assertThat(userInfo).isNotNull();
        assertThat(userInfo.getUserAttributes())
                .hasSize(1)
                .containsEntry("secondary_email", List.of("john.doe.secondary@example.com"));
    }

    @Test
    void setsUserInfoRolesWhenWhiteListIsSet() {
        providerDefinition.addAttributeMapping(GROUP_ATTRIBUTE_NAME, "groups");
        providerDefinition.setStoreCustomAttributes(true);
        providerDefinition.addWhiteListedGroup(SAML_ADMIN);
        provider.setConfig(providerDefinition);
        providerProvisioning.update(provider, identityZoneManager.getCurrentIdentityZone().getId());

        authenticate();
        UaaUser user = userDatabase.retrieveUserByName(TEST_USERNAME, OriginKeys.SAML);
        UserInfo userInfo = userDatabase.getUserInfo(user.getId());

        assertThat(userInfo).isNotNull();
        assertThat(userInfo.getRoles()).containsExactly(SAML_ADMIN);
    }

    @Test
    @Disabled("SAML test doesn't compile")
    void authnContext_isvalidated_fail() {
        providerDefinition.setAuthnContext(Arrays.asList("some-context", "another-context"));
        provider.setConfig(providerDefinition);
        providerProvisioning.update(provider, identityZoneManager.getCurrentIdentityZone().getId());

        try {
//            getAuthentication(authprovider);
            fail("Expected authentication to throw BadCredentialsException");
        } catch (BadCredentialsException ignored) {

        }
    }

    @Test
    @Disabled("SAML test doesn't compile")
    void authnContext_isvalidated_good() {
//        providerDefinition.setAuthnContext(Collections.singletonList(AuthnContext.PASSWORD_AUTHN_CTX));
        provider.setConfig(providerDefinition);
        providerProvisioning.update(provider, identityZoneManager.getCurrentIdentityZone().getId());

        try {
//            getAuthentication(authprovider);
        } catch (BadCredentialsException ex) {
            fail("Expected authentication to succeed");
        }
    }

    @Test
    @Disabled("SAML test doesn't compile")
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
            authenticate();
            fail("Expected authentication to throw LoginSAMLException");
        } catch (SamlLoginException ignored) {

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

        ScimUser createdUser = createSamlUser(TEST_EMAIL,
                identityZoneManager.getCurrentIdentityZone().getId(), userProvisioning);

        authenticate();
        UaaUser uaaUser = userDatabase.retrieveUserByName(TEST_USERNAME, OriginKeys.SAML);
        assertThat(uaaUser)
                .returns(createdUser.getId(), UaaUser::getId)
                .returns(TEST_USERNAME, UaaUser::getUsername);
    }

    @Test
    void authFailsIfMultipleExistingUsersWithSameEmailExist() {
        Map<String, Object> attributeMappings = new HashMap<>();
        attributeMappings.put("email", "emailAddress");
        providerDefinition.setAttributeMappings(attributeMappings);
        provider.setConfig(providerDefinition);
        providerProvisioning.update(provider, identityZoneManager.getCurrentIdentityZone().getId());

        createSamlUser(TEST_EMAIL, identityZoneManager.getCurrentIdentityZone().getId(),
                userProvisioning);
        // get user by username should fail, then attempt get user by email causes exception
        createSamlUser("randomUsername", identityZoneManager.getCurrentIdentityZone().getId(),
                userProvisioning);

        assertThrows(IncorrectResultSizeDataAccessException.class, this::authenticate);
    }

    @Test
    void shadowUserGetsCreatedWithDefaultValuesIfAttributeNotMapped() {
        Map<String, Object> attributeMappings = new HashMap<>();
        attributeMappings.put("surname", "lastName");
        attributeMappings.put("email", "emailAddress");
        providerDefinition.setAttributeMappings(attributeMappings);
        provider.setConfig(providerDefinition);
        providerProvisioning.update(provider, identityZoneManager.getCurrentIdentityZone().getId());

        UaaAuthentication authentication = authenticate();
        UaaUser user = userDatabase.retrieveUserByName(TEST_USERNAME, OriginKeys.SAML);

        // this splits name fields from email from TestOpenSamlObjects
        assertThat(user).returns("john.doe", UaaUser::getGivenName)
                .returns("example.com", UaaUser::getFamilyName)
                .returns(TEST_EMAIL, UaaUser::getEmail);
        assertThat(authentication.getUserAttributes())
                .as("No custom attributes have been mapped")
                .isEmpty();
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

        UaaAuthentication authentication = authenticate();
        assertThat(authentication.getUserAttributes())
                .hasSize(2)
                .containsEntry(COST_CENTERS, List.of(DENVER_CO))
                .containsEntry(MANAGERS, List.of(JOHN_THE_SLOTH, KARI_THE_ANT_EATER));
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
}
