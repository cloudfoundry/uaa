package org.cloudfoundry.identity.uaa.provider.saml;

import org.cloudfoundry.identity.uaa.annotations.WithDatabaseContext;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.authentication.event.IdentityProviderAuthenticationSuccessEvent;
import org.cloudfoundry.identity.uaa.authentication.manager.AuthEvent;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.db.beans.DatabaseProperties;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.JdbcIdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.SamlIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.resources.jdbc.JdbcPagingListFactory;
import org.cloudfoundry.identity.uaa.resources.jdbc.LimitSqlAdapter;
import org.cloudfoundry.identity.uaa.resources.jdbc.SimpleSearchQueryConverter;
import org.cloudfoundry.identity.uaa.scim.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.ScimGroupProvisioning;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUserAliasHandler;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.scim.bootstrap.ScimUserBootstrap;
import org.cloudfoundry.identity.uaa.scim.jdbc.JdbcScimGroupExternalMembershipManager;
import org.cloudfoundry.identity.uaa.scim.jdbc.JdbcScimGroupMembershipManager;
import org.cloudfoundry.identity.uaa.scim.jdbc.JdbcScimGroupProvisioning;
import org.cloudfoundry.identity.uaa.scim.jdbc.JdbcScimUserProvisioning;
import org.cloudfoundry.identity.uaa.scim.services.ScimUserService;
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
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EmptySource;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.opensaml.core.config.InitializationException;
import org.opensaml.core.config.InitializationService;
import org.opensaml.saml.saml2.core.AuthnContext;
import org.opensaml.saml.saml2.core.Response;
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
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationException;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationToken;
import org.springframework.security.saml2.provider.service.registration.Saml2MessageBinding;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.web.context.request.ServletWebRequest;

import jakarta.servlet.ServletContext;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.fail;
import static org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition.EMAIL_ATTRIBUTE_NAME;
import static org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition.FAMILY_NAME_ATTRIBUTE_NAME;
import static org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition.GIVEN_NAME_ATTRIBUTE_NAME;
import static org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition.GROUP_ATTRIBUTE_NAME;
import static org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition.PHONE_NUMBER_ATTRIBUTE_NAME;
import static org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition.USER_ATTRIBUTE_PREFIX;
import static org.cloudfoundry.identity.uaa.provider.saml.Saml2TestUtils.authenticationToken;
import static org.cloudfoundry.identity.uaa.provider.saml.Saml2TestUtils.mockedStoredAuthenticationRequest;
import static org.cloudfoundry.identity.uaa.provider.saml.Saml2TestUtils.registration;
import static org.cloudfoundry.identity.uaa.provider.saml.Saml2TestUtils.responseWithAssertions;
import static org.cloudfoundry.identity.uaa.provider.saml.Saml2TestUtils.token;
import static org.cloudfoundry.identity.uaa.provider.saml.Saml2TestUtils.verifying;
import static org.cloudfoundry.identity.uaa.provider.saml.TestOpenSamlObjects.attributeStatements;
import static org.cloudfoundry.identity.uaa.test.ModelTestUtils.getResourceAsString;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@WithDatabaseContext
class OpenSaml4AuthenticationProviderUaaTests {

    private static final String SAML_USER = "saml.user";
    private static final String SAML_ADMIN = "saml.admin";
    private static final String SAML_TEST = "saml.test";
    private static final String SAML_NOT_MAPPED = "saml.unmapped";
    private static final String SAML_NOT_ASSERTED = "saml.unasserted";
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
            OpenSaml4AuthenticationProviderUaaTests.class, "IDP_META_DATA.xml");

    private static final String TEST_EMAIL = "john.doe@example.com";
    private static final String TEST_USERNAME = "test@saml.user";
    private static final String TEST_PHONE_NUMBER = "123-456-7890";


    private JdbcIdentityProviderProvisioning providerProvisioning;
    private CreateUserPublisher publisher;
    private JdbcUaaUserDatabase userDatabase;
    private SamlUaaAuthenticationUserManager samlUaaAuthenticationUserManager;
    private AuthenticationProvider authprovider;
    private SamlIdentityProviderDefinition providerDefinition;
    private IdentityProvider<SamlIdentityProviderDefinition> provider;
    private ScimUserProvisioning userProvisioning;
    private JdbcScimGroupExternalMembershipManager externalManager;
    private ScimGroup uaaSamlUser;
    private ScimGroup uaaSamlAdmin;
    private IdentityZoneManager identityZoneManager;
    private SamlAuthenticationFilterConfig samlAuthenticationFilterConfig;

    @Autowired
    private NamedParameterJdbcTemplate namedJdbcTemplate;
    @Autowired
    private JdbcTemplate jdbcTemplate;
    @Autowired
    private LimitSqlAdapter limitSqlAdapter;
    @Autowired
    private PasswordEncoder passwordEncoder;
    @Autowired
    private DatabaseProperties databaseProperties;

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
                new IdentityZoneManagerImpl(), new JdbcIdentityZoneProvisioning(jdbcTemplate),
                new SimpleSearchQueryConverter(), new SimpleSearchQueryConverter(), new TimeServiceImpl(),
                true);

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
                identityZoneManager, jdbcTemplate, new TimeServiceImpl(), userProvisioning, null, dbUtils);
        membershipManager.setScimGroupProvisioning(groupProvisioning);

        final ScimUserAliasHandler aliasHandler = mock(ScimUserAliasHandler.class);
        when(aliasHandler.aliasPropertiesAreValid(any(), any())).thenReturn(true);

        final ScimUserService scimUserService = new ScimUserService(
                aliasHandler,
                userProvisioning,
                identityZoneManager,
                null, // not required since alias is disabled
                false
        );
        ScimUserBootstrap bootstrap = new ScimUserBootstrap(
                userProvisioning,
                scimUserService,
                groupProvisioning,
                membershipManager,
                identityZoneManager,
                Collections.emptyList(),
                false,
                Collections.emptyList(),
                false
        );

        externalManager = new JdbcScimGroupExternalMembershipManager(jdbcTemplate, dbUtils);
        externalManager.setScimGroupProvisioning(groupProvisioning);
        externalManager.mapExternalGroup(uaaSamlUser.getId(), SAML_USER, OriginKeys.SAML,
                identityZoneManager.getCurrentIdentityZone().getId());
        externalManager.mapExternalGroup(uaaSamlAdmin.getId(), SAML_ADMIN, OriginKeys.SAML,
                identityZoneManager.getCurrentIdentityZone().getId());
        externalManager.mapExternalGroup(uaaSamlTest.getId(), SAML_TEST, OriginKeys.SAML,
                identityZoneManager.getCurrentIdentityZone().getId());

        TimeService timeService = mock(TimeService.class);
        userDatabase = new JdbcUaaUserDatabase(jdbcTemplate, timeService, databaseProperties,
                identityZoneManager, new DbUtils());
        providerProvisioning = new JdbcIdentityProviderProvisioning(jdbcTemplate);
        publisher = new CreateUserPublisher(bootstrap);

        samlAuthenticationFilterConfig = new SamlAuthenticationFilterConfig();
        samlUaaAuthenticationUserManager = samlAuthenticationFilterConfig.samlUaaAuthenticationUserManager(identityZoneManager, providerProvisioning, externalManager, userDatabase, publisher);
        authprovider = samlAuthenticationFilterConfig.samlAuthenticationProvider(
                identityZoneManager, samlUaaAuthenticationUserManager, publisher, new SamlConfigProps());

        providerDefinition = new SamlIdentityProviderDefinition();
        providerDefinition.setMetaDataLocation(IDP_META_DATA.formatted(OriginKeys.SAML));
        providerDefinition.setIdpEntityAlias(OriginKeys.SAML);

        IdentityProvider<SamlIdentityProviderDefinition> createProvider = new IdentityProvider<>();
        createProvider.setIdentityZoneId(IdentityZone.getUaaZoneId());
        createProvider.setOriginKey(OriginKeys.SAML);
        createProvider.setName("saml-test");
        createProvider.setActive(true);
        createProvider.setType(OriginKeys.SAML);
        createProvider.setConfig(providerDefinition);
        provider = providerProvisioning.create(createProvider, identityZoneManager.getCurrentIdentityZone().getId());
    }

    @AfterEach
    void tearDown(@Autowired ApplicationContext applicationContext) throws SQLException {
        TestUtils.restoreToDefaults(applicationContext);
        RequestContextHolder.resetRequestAttributes();
    }

    @Test
    void authenticateSimple() {
        assertThat(authenticate()).isNotNull();
    }

    @ParameterizedTest(name = "#{index} relayRedirectRejectsNonUrls - {0}")
    @ValueSource(strings = {"test", "www.google.com"})
    @NullSource
    @EmptySource
    void relayRedirectRejectsNonUrls(String url) {
        Saml2AuthenticationToken authenticationToken = authenticationToken();
        AbstractSaml2AuthenticationRequest mockAuthenticationRequest = authenticationToken.getAuthenticationRequest();
        when(mockAuthenticationRequest.getRelayState()).thenReturn(url);
        authenticate(authenticationToken);
        verify(mockAuthenticationRequest, times(1)).getRelayState();

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
        assertThat(uaaAuthentication.getAuthContextClassRef()).contains(AuthnContext.PASSWORD_AUTHN_CTX);
    }

    @Test
    void authenticationEvents() {
        authenticate();
        assertThat(publisher.events).hasSize(3);
        assertThat(publisher.events.get(2)).isInstanceOf(IdentityProviderAuthenticationSuccessEvent.class);
    }

    @Test
    void samlAuthenticationContainsAcr() {
        Saml2AuthenticationToken mockAuthenticationToken = authenticationToken();
        UaaAuthentication uaaAuthentication = authenticate(mockAuthenticationToken);
        assertThat(uaaAuthentication.getAuthContextClassRef()).contains(AuthnContext.PASSWORD_AUTHN_CTX);
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
    void externalGroupsAsScopes() {
        providerDefinition.setGroupMappingMode(SamlIdentityProviderDefinition.ExternalGroupMappingMode.AS_SCOPES);
        providerDefinition.addAttributeMapping(GROUP_ATTRIBUTE_NAME, Arrays.asList("2ndgroups", "groups"));
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
    void groupMapping() {
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
    void nonStringAttributes() {
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
    void dontAddExternalGroupsToAuthenticationWithoutMatchingWhitelist() {
        providerDefinition.addAttributeMapping(GROUP_ATTRIBUTE_NAME, "groups");
        providerDefinition.addWhiteListedGroup(SAML_NOT_ASSERTED);
        provider.setConfig(providerDefinition);
        providerProvisioning.update(provider, identityZoneManager.getCurrentIdentityZone().getId());

        UaaAuthentication authentication = authenticate();
        assertThat(authentication.getExternalGroups()).isEmpty();
    }

    @Test
    void add_external_groups_to_authentication_with_empty_whitelist() {
        providerDefinition.addAttributeMapping(GROUP_ATTRIBUTE_NAME, "groups");
        provider.setConfig(providerDefinition);
        providerProvisioning.update(provider, identityZoneManager.getCurrentIdentityZone().getId());
        UaaAuthentication authentication = authenticate();
        assertThat(authentication.getExternalGroups()).contains(SAML_USER, SAML_ADMIN, SAML_NOT_MAPPED);
    }

    @Test
    void addExternalGroupsToAuthenticationWithWhitelist() {
        providerDefinition.addAttributeMapping(GROUP_ATTRIBUTE_NAME, "groups");
        providerDefinition.addWhiteListedGroup(SAML_ADMIN);
        provider.setConfig(providerDefinition);
        providerProvisioning.update(provider, identityZoneManager.getCurrentIdentityZone().getId());

        UaaAuthentication authentication = authenticate();
        assertThat(authentication.getExternalGroups()).isEqualTo(Collections.singleton(SAML_ADMIN));
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
    void updateInvitedUserWhoseUsernameIsNotEmail() {
        ScimUser scimUser = getInvitedUser();
        Map<String, String> userAttributes = getUserAttributes("Marissa-invited", null, "marissa.invited@test.org", null, null);
        authenticate(authenticationToken("marissa-invited", attributeStatements(userAttributes)));

        UaaUser user = userDatabase.retrieveUserById(scimUser.getId());
        assertThat(user.isVerified()).isFalse();
        assertThat(user.getUsername()).isEqualTo("marissa-invited");
        assertThat(user.getEmail()).isEqualTo("marissa.invited@test.org");

        RequestContextHolder.resetRequestAttributes();
    }

    @Test
    void invitedUserAuthenticationWhenAuthenticatedEmailDoesNotMatchInvitedEmail() {
        Map<String, Object> attributeMappings = new HashMap<>();
        attributeMappings.put("email", "emailAddress");
        providerDefinition.setAttributeMappings(attributeMappings);
        provider.setConfig(providerDefinition);
        providerProvisioning.update(provider, identityZoneManager.getCurrentIdentityZone().getId());

        ScimUser scimUser = getInvitedUser();
        Map<String, String> userAttributes = getUserAttributes("Marissa-invited", null, "different@test.org", null, null);
        Saml2AuthenticationToken authenticationToken = authenticationToken("marissa-invited", attributeStatements(userAttributes));

        assertThatThrownBy(() -> authenticate(authenticationToken))
                .isInstanceOf(Saml2AuthenticationException.class)
                .hasMessageContaining("Authenticated email doesn't match invited email");

        UaaUser user = userDatabase.retrieveUserById(scimUser.getId());
        assertThat(user.isVerified()).isFalse();
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

    private Map<String, String> getUserAttributes(String firstName,
                                                  String lastName,
                                                  String emailAddress,
                                                  String phoneNumber,
                                                  Boolean emailVerified) {
        Map<String, String> attributes = new HashMap<>();
        attributes.put("firstName", firstName);
        attributes.put("lastName", lastName);
        attributes.put("emailAddress", emailAddress);
        attributes.put("phone", phoneNumber);
        if (emailVerified != null) {
            attributes.put("emailVerified", emailVerified.toString());
        }

        return attributes;
    }

    @Test
    void updateExistingUserWithDifferentAttributes() throws Exception {
        try {
            userDatabase.retrieveUserByName(TEST_USERNAME, OriginKeys.SAML);
            fail("user should not exist");
        } catch (UsernameNotFoundException ignored) {
            // expected
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
    void updateExistingUserWithDifferentUsernameButSameEmail() {
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
        assertThat(originalUser).isNotNull();
        assertThat(originalUser.getUsername()).isEqualTo(TEST_USERNAME);

        LinkedMultiValueMap<String, String> attributes = new LinkedMultiValueMap<>();
        attributes.add(GIVEN_NAME_ATTRIBUTE_NAME, "Marissa");
        attributes.add(FAMILY_NAME_ATTRIBUTE_NAME, "Bloggs");
        attributes.add(EMAIL_ATTRIBUTE_NAME, TEST_EMAIL);
        attributes.add(PHONE_NUMBER_ATTRIBUTE_NAME, TEST_PHONE_NUMBER);

        UaaPrincipal samlPrincipal = new UaaPrincipal(OriginKeys.NotANumber,
                "test-changed@saml.user", TEST_EMAIL, OriginKeys.SAML, TEST_USERNAME,
                identityZoneManager.getCurrentIdentityZone().getId());

        UaaUser user = samlUaaAuthenticationUserManager.createIfMissing(samlPrincipal, false, new ArrayList<SimpleGrantedAuthority>(), attributes);

        assertThat(user).isNotNull();
        assertThat(user.getUsername()).isEqualTo("test-changed@saml.user");
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
    void authnContextValidationFails() {
        providerDefinition.setAuthnContext(Arrays.asList("some-context", "another-context"));
        provider.setConfig(providerDefinition);
        providerProvisioning.update(provider, identityZoneManager.getCurrentIdentityZone().getId());

        assertThatThrownBy(this::authenticate)
                .isInstanceOf(Saml2AuthenticationException.class)
                .hasCauseExactlyInstanceOf(BadCredentialsException.class)
                .hasMessage("Identity Provider did not authenticate with the requested AuthnContext.");
    }

    @Test
    void authnContextValidationSucceeds() {
        providerDefinition.setAuthnContext(Collections.singletonList(AuthnContext.PASSWORD_AUTHN_CTX));
        provider.setConfig(providerDefinition);
        providerProvisioning.update(provider, identityZoneManager.getCurrentIdentityZone().getId());

        assertThat(authenticate()).isNotNull();
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

        assertThatThrownBy(this::authenticate)
                .isInstanceOf(Saml2AuthenticationException.class)
                .hasCauseExactlyInstanceOf(SamlLoginException.class)
                .hasMessage("SAML user does not exist. You can correct this by creating a shadow user for the SAML user.");

        assertThatThrownBy(() -> userDatabase.retrieveUserByName(TEST_USERNAME, OriginKeys.SAML))
                .isInstanceOf(UsernameNotFoundException.class)
                .hasMessage(TEST_USERNAME);
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

        // get user by username should fail, then attempt get user by email causes exception in JdbcUaaUserDatabase.retrieveUserPrototypeByEmail
        createSamlUser("randomUsername", identityZoneManager.getCurrentIdentityZone().getId(),
                userProvisioning);

        assertThatThrownBy(() -> authenticate())
                .isInstanceOf(Saml2AuthenticationException.class)
                .hasCauseExactlyInstanceOf(IncorrectResultSizeDataAccessException.class)
                .hasMessage("Multiple users match email=john.doe@example.com origin=saml");
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
        String costCenters = COST_CENTER + "s";
        String managers = MANAGER + "s";

        Map<String, Object> attributeMappings = new HashMap<>();
        attributeMappings.put(USER_ATTRIBUTE_PREFIX + costCenters, COST_CENTER);
        attributeMappings.put(USER_ATTRIBUTE_PREFIX + managers, MANAGER);
        providerDefinition.setAttributeMappings(attributeMappings);
        provider.setConfig(providerDefinition);
        providerProvisioning.update(provider, identityZoneManager.getCurrentIdentityZone().getId());

        UaaAuthentication authentication = authenticate();
        assertThat(authentication.getUserAttributes())
                .hasSize(2)
                .containsEntry(costCenters, List.of(DENVER_CO))
                .containsEntry(managers, List.of(JOHN_THE_SLOTH, KARI_THE_ANT_EATER));
    }

    @Test
    void failsWithIncorrectInResponseTo() {
        // This test is to ensure that the InResponseTo attribute is being validated
        // and that the response is not accepted if it does not match the stored request
        Response response = responseWithAssertions();
        response.setInResponseTo("incorrect");
        AbstractSaml2AuthenticationRequest mockAuthenticationRequest = mockedStoredAuthenticationRequest("SAML2",
                Saml2MessageBinding.POST, false);
        Saml2AuthenticationToken authenticationToken = token(response, verifying(registration()), mockAuthenticationRequest);

        assertThatThrownBy(() -> authenticate(authenticationToken))
                .isInstanceOf(Saml2AuthenticationException.class)
                .hasMessage("The InResponseTo attribute [incorrect] does not match the ID of the authentication request [SAML2]");
    }

    @Test
    void successWithIncorrectInResponseTo() {
        // setup the same as failsWithIncorrectInResponseTo,
        // but with the disableInResponseToCheck property set to true
        // so that the InResponseTo check is skipped
        SamlConfigProps samlConfigProps = new SamlConfigProps();
        samlConfigProps.setDisableInResponseToCheck(true);
        authprovider = samlAuthenticationFilterConfig.samlAuthenticationProvider(
                identityZoneManager, samlUaaAuthenticationUserManager, publisher, samlConfigProps);

        Response response = responseWithAssertions();
        response.setInResponseTo("incorrect");
        AbstractSaml2AuthenticationRequest mockAuthenticationRequest = mockedStoredAuthenticationRequest("SAML2",
                Saml2MessageBinding.POST, false);
        Saml2AuthenticationToken authenticationToken = token(response, verifying(registration()), mockAuthenticationRequest);

        UaaAuthentication authentication = authenticate(authenticationToken);
        assertThat(authentication.isAuthenticated()).isTrue();
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
            if (event instanceof AuthEvent authEvent) {
                bootstrap.onApplicationEvent(authEvent);
            }
        }

        @Override
        public void publishEvent(Object event) {
            throw new UnsupportedOperationException("not implemented");
        }
    }
}
