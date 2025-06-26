package org.cloudfoundry.identity.uaa.invitations;

import jakarta.annotation.PostConstruct;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.authentication.manager.DynamicLdapAuthenticationManager;
import org.cloudfoundry.identity.uaa.authentication.manager.DynamicZoneAwareAuthenticationManager;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCode;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCodeStore;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.home.BuildInfo;
import org.cloudfoundry.identity.uaa.login.ThymeleafConfig;
import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetailsService;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.OIDCIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.SamlIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.ldap.ExtendedLdapUserDetails;
import org.cloudfoundry.identity.uaa.provider.oauth.ExternalOAuthProviderConfigurator;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.scim.exception.InvalidPasswordException;
import org.cloudfoundry.identity.uaa.scim.validate.PasswordValidator;
import org.cloudfoundry.identity.uaa.security.web.CookieBasedCsrfTokenRepository;
import org.cloudfoundry.identity.uaa.user.UaaAuthority;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UaaUserDatabase;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.util.beans.TestBuildInfo;
import org.cloudfoundry.identity.uaa.zone.BrandingInformation;
import org.cloudfoundry.identity.uaa.zone.Consent;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManagerImpl;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.context.support.ResourceBundleMessageSource;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.junit.jupiter.SpringJUnitConfig;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.context.ConfigurableWebApplicationContext;
import org.springframework.web.servlet.config.annotation.DefaultServletHandlerConfigurer;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerAdapter;

import java.net.URI;
import java.sql.Timestamp;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.cloudfoundry.identity.uaa.codestore.ExpiringCodeType.INVITATION;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.LDAP;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.Matchers.containsString;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.http.HttpStatus.BAD_REQUEST;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.model;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.xpath;

@WebAppConfiguration
@SpringJUnitConfig(classes = InvitationsControllerTest.ContextConfiguration.class)
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_EACH_TEST_METHOD)
class InvitationsControllerTest {

    private MockMvc mockMvc;

    @Autowired
    ConfigurableWebApplicationContext webApplicationContext;

    @Autowired
    InvitationsService invitationsService;

    @Autowired
    ExpiringCodeStore expiringCodeStore;

    @Autowired
    PasswordValidator passwordValidator;

    @Autowired
    IdentityProviderProvisioning providerProvisioning;

    @Autowired
    UaaUserDatabase userDatabase;

    @Autowired
    DynamicZoneAwareAuthenticationManager zoneAwareAuthenticationManager;

    @Autowired
    ScimUserProvisioning scimUserProvisioning;

    @Autowired
    ExternalOAuthProviderConfigurator externalOAuthProviderConfigurator;

    @BeforeEach
    void setUp() {
        IdentityZoneHolder.clear();
        SecurityContextHolder.clearContext();
        mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext)
                .build();
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void acceptInvitationsPage() throws Exception {
        String zoneId = IdentityZoneHolder.get().getId();
        Map<String, String> codeData = new HashMap<>();
        codeData.put("user_id", "user-id-001");
        codeData.put("email", "user@example.com");
        codeData.put("client_id", "client-id");
        codeData.put("redirect_uri", "blah.test.com");
        when(expiringCodeStore.peekCode("code", zoneId)).thenReturn(createCode(codeData), null);
        IdentityProvider provider = new IdentityProvider<>();
        provider.setType(OriginKeys.UAA);
        when(providerProvisioning.retrieveByOrigin(any(), any())).thenReturn(provider);

        mockMvc.perform(get("/invitations/accept").param("code", "code"))
                .andExpect(status().isOk())
                .andExpect(model().attribute("email", "user@example.com"))
                .andExpect(model().attribute("code", "code"))
                .andExpect(view().name("invitations/accept_invite"));

        UaaPrincipal principal = (UaaPrincipal) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isInstanceOf(AnonymousAuthenticationToken.class);
        assertThat(principal.getId()).isEqualTo("user-id-001");
        assertThat(principal.getName()).isEqualTo("user@example.com");
        assertThat(principal.getEmail()).isEqualTo("user@example.com");

        mockMvc.perform(get("/invitations/accept").param("code", "code"))
                .andExpect(status().isUnprocessableEntity())
                .andExpect(view().name("invitations/accept_invite"))
                .andExpect(model().attribute("error_message_code", "code_expired"));
    }

    @Test
    void incorrectCodeIntent() throws Exception {
        String zoneId = IdentityZoneHolder.get().getId();
        Map<String, String> codeData = new HashMap<>();
        codeData.put("user_id", "user-id-001");
        codeData.put("email", "user@example.com");
        codeData.put("client_id", "client-id");
        codeData.put("redirect_uri", "blah.test.com");
        when(expiringCodeStore.retrieveCode("the_secret_code", zoneId)).thenReturn(new ExpiringCode("code", new Timestamp(System.currentTimeMillis()), JsonUtils.writeValueAsString(codeData), "incorrect-code-intent"));

        MockHttpServletRequestBuilder get = get("/invitations/accept")
                .param("code", "the_secret_code");

        mockMvc.perform(get).andExpect(status().isUnprocessableEntity());
    }

    @Test
    void acceptInvitePage_for_unverifiedSamlUser() throws Exception {
        Map<String, String> codeData = getInvitationsCode("test-saml");
        String zoneId = IdentityZoneHolder.get().getId();
        when(expiringCodeStore.peekCode("the_secret_code", zoneId)).thenReturn(createCode(codeData));
        IdentityProvider<SamlIdentityProviderDefinition> provider = new IdentityProvider<>();
        SamlIdentityProviderDefinition definition = new SamlIdentityProviderDefinition()
                .setMetaDataLocation("http://test.saml.com")
                .setIdpEntityAlias("test-saml")
                .setNameID("test")
                .setLinkText("testsaml")
                .setIconUrl("test.com")
                .setZoneId(zoneId);
        provider.setConfig(definition);
        provider.setType(OriginKeys.SAML);
        when(providerProvisioning.retrieveByOrigin(eq("test-saml"), anyString())).thenReturn(provider);
        MockHttpServletRequestBuilder get = get("/invitations/accept")
                .param("code", "the_secret_code");

        MvcResult result = mockMvc.perform(get)
                .andExpect(redirectedUrl("/saml2/authenticate/test-saml"))
                .andReturn();

        assertThat(result.getRequest().getSession().getAttribute("IS_INVITE_ACCEPTANCE")).isEqualTo(true);
        assertThat(result.getRequest().getSession().getAttribute("user_id")).isEqualTo("user-id-001");
    }

    @Test
    void acceptInvitePage_for_unverifiedOIDCUser() throws Exception {
        Map<String, String> codeData = getInvitationsCode("test-oidc");
        String zoneId = IdentityZoneHolder.get().getId();
        when(expiringCodeStore.peekCode("the_secret_code", zoneId)).thenReturn(createCode(codeData));

        OIDCIdentityProviderDefinition definition = new OIDCIdentityProviderDefinition();
        definition.setAuthUrl(URI.create("https://oidc10.auth.url").toURL());

        IdentityProvider<OIDCIdentityProviderDefinition> provider = new IdentityProvider<>();
        provider.setConfig(definition);
        provider.setType(OriginKeys.OIDC10);
        when(providerProvisioning.retrieveByOrigin(eq("test-oidc"), anyString())).thenReturn(provider);
        when(externalOAuthProviderConfigurator.getIdpAuthenticationUrl(any(), any(), any())).thenReturn("http://example.com");

        MockHttpServletRequestBuilder get = get("/invitations/accept")
                .param("code", "the_secret_code");

        MvcResult result = mockMvc.perform(get)
                .andExpect(redirectedUrl("http://example.com"))
                .andReturn();

        assertThat(result.getRequest().getSession().getAttribute("IS_INVITE_ACCEPTANCE")).isEqualTo(true);
        assertThat(result.getRequest().getSession().getAttribute("user_id")).isEqualTo("user-id-001");
    }

    @Test
    void acceptInvitePage_for_unverifiedLdapUser() throws Exception {
        Map<String, String> codeData = getInvitationsCode(LDAP);
        String zoneId = IdentityZoneHolder.get().getId();
        when(expiringCodeStore.peekCode("the_secret_code", zoneId)).thenReturn(createCode(codeData));

        IdentityProvider provider = new IdentityProvider<>();
        provider.setType(LDAP);
        when(providerProvisioning.retrieveByOrigin(eq(LDAP), anyString())).thenReturn(provider);

        MockHttpServletRequestBuilder get = get("/invitations/accept")
                .param("code", "the_secret_code");

        mockMvc.perform(get)
                .andExpect(view().name("invitations/accept_invite"))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("Email: " + "user@example.com")))
                .andExpect(content().string(containsString("Sign in with enterprise credentials:")))
                .andExpect(content().string(containsString("username")))
                .andExpect(model().attribute("code", "the_secret_code"))
                .andReturn();
    }

    private Map<String, String> getInvitationsCode(String origin) {
        Map<String, String> codeData = new HashMap<>();
        codeData.put("user_id", "user-id-001");
        codeData.put("email", "user@example.com");
        codeData.put("client_id", "client-id");
        codeData.put("redirect_uri", "blah.test.com");
        codeData.put("origin", origin);
        return codeData;
    }

    @Test
    void unverifiedLdapUser_acceptsInvite_byLoggingIn() throws Exception {
        Map<String, String> codeData = getInvitationsCode(LDAP);
        String zoneId = IdentityZoneHolder.get().getId();
        when(expiringCodeStore.retrieveCode("the_secret_code", zoneId)).thenReturn(new ExpiringCode("code", new Timestamp(System.currentTimeMillis()), JsonUtils.writeValueAsString(codeData), null));
        when(expiringCodeStore.generateCode(anyString(), any(), eq(null), eq(zoneId))).thenReturn(new ExpiringCode("code", new Timestamp(System.currentTimeMillis()), JsonUtils.writeValueAsString(codeData), null));
        DynamicLdapAuthenticationManager ldapAuthenticationManager = mock(DynamicLdapAuthenticationManager.class);
        when(zoneAwareAuthenticationManager.getLdapAuthenticationManager(any(), any())).thenReturn(ldapAuthenticationManager);

        AuthenticationManager ldapActual = mock(AuthenticationManager.class);
        when(ldapAuthenticationManager.getLdapManagerActual()).thenReturn(ldapActual);

        Authentication auth = mock(Authentication.class);
        when(auth.isAuthenticated()).thenReturn(true);
        when(ldapActual.authenticate(any())).thenReturn(auth);

        ExtendedLdapUserDetails extendedLdapUserDetails = mock(ExtendedLdapUserDetails.class);

        when(auth.getPrincipal()).thenReturn(extendedLdapUserDetails);
        when(extendedLdapUserDetails.getEmailAddress()).thenReturn("user@example.com");
        when(extendedLdapUserDetails.getUsername()).thenReturn("test-ldap-user");

        ScimUser invitedUser = new ScimUser("user-id-001", "user@example.com", "g", "f");
        invitedUser.setPrimaryEmail("user@example.com");

        when(scimUserProvisioning.retrieve("user-id-001", zoneId)).thenReturn(invitedUser);
        when(invitationsService.acceptInvitation(anyString(), anyString())).thenReturn(new AcceptedInvitation("blah.test.com", new ScimUser()));
        when(expiringCodeStore.generateCode(anyString(), any(), eq(null), eq(zoneId))).thenReturn(new ExpiringCode("code", new Timestamp(System.currentTimeMillis()), JsonUtils.writeValueAsString(codeData), null));

        mockMvc.perform(post("/invitations/accept_enterprise.do")
                        .param("enterprise_username", "test-ldap-user")
                        .param("enterprise_password", "password")
                        .param("enterprise_email", "email")
                        .param("code", "the_secret_code"))
                .andExpect(redirectedUrl("/login?success=invite_accepted&form_redirect_uri=blah.test.com"))
                .andReturn();

        verify(ldapActual).authenticate(any());
        ArgumentCaptor<ScimUser> userArgumentCaptor = ArgumentCaptor.forClass(ScimUser.class);
        verify(scimUserProvisioning).update(anyString(), userArgumentCaptor.capture(), eq(zoneId));
        ScimUser value = userArgumentCaptor.getValue();
        assertThat(value.getUserName()).isEqualTo("test-ldap-user");
        assertThat(value.getPrimaryEmail()).isEqualTo("user@example.com");
        verify(ldapAuthenticationManager).authenticate(any());
    }

    @Test
    void unverifiedLdapUser_acceptsInvite_byLoggingIn_bad_credentials() throws Exception {
        Map<String, String> codeData = getInvitationsCode("ldap");
        String zoneId = IdentityZoneHolder.get().getId();
        when(expiringCodeStore.retrieveCode("the_secret_code", zoneId)).thenReturn(new ExpiringCode("code", new Timestamp(System.currentTimeMillis()), JsonUtils.writeValueAsString(codeData), null));
        when(expiringCodeStore.generateCode(anyString(), any(), eq(null), eq(zoneId))).thenReturn(new ExpiringCode("code", new Timestamp(System.currentTimeMillis()), JsonUtils.writeValueAsString(codeData), null));
        DynamicLdapAuthenticationManager ldapAuthenticationManager = mock(DynamicLdapAuthenticationManager.class);
        when(zoneAwareAuthenticationManager.getLdapAuthenticationManager(any(), any())).thenReturn(ldapAuthenticationManager);

        AuthenticationManager ldapActual = mock(AuthenticationManager.class);
        when(ldapAuthenticationManager.getLdapManagerActual()).thenReturn(ldapActual);

        Authentication auth = mock(Authentication.class);
        when(auth.isAuthenticated()).thenReturn(true);
        when(ldapActual.authenticate(any())).thenThrow(new BadCredentialsException("bad creds"));

        mockMvc.perform(post("/invitations/accept_enterprise.do")
                        .param("enterprise_username", "test-ldap-user")
                        .param("enterprise_password", "password")
                        .param("enterprise_email", "email")
                        .param("code", "the_secret_code"))
                .andExpect(model().attribute("ldap", true))
                .andExpect(model().attribute("email", "email"))
                .andExpect(model().attribute("error_message", "bad_credentials"))
                .andReturn();
    }

    @Test
    void unverifiedLdapUser_acceptsInvite_byLoggingIn_whereEmailDoesNotMatchAuthenticatedEmail() throws Exception {
        Map<String, String> codeData = getInvitationsCode(LDAP);
        String zoneId = IdentityZoneHolder.get().getId();
        when(expiringCodeStore.retrieveCode("the_secret_code", zoneId)).thenReturn(new ExpiringCode("code", new Timestamp(System.currentTimeMillis()), JsonUtils.writeValueAsString(codeData), null));
        DynamicLdapAuthenticationManager ldapAuthenticationManager = mock(DynamicLdapAuthenticationManager.class);
        when(zoneAwareAuthenticationManager.getLdapAuthenticationManager(any(), any())).thenReturn(ldapAuthenticationManager);

        AuthenticationManager ldapActual = mock(AuthenticationManager.class);
        when(ldapAuthenticationManager.getLdapManagerActual()).thenReturn(ldapActual);
        Authentication auth = mock(Authentication.class);
        when(ldapActual.authenticate(any())).thenReturn(auth);

        ExtendedLdapUserDetails extendedLdapUserDetails = mock(ExtendedLdapUserDetails.class);
        when(auth.getPrincipal()).thenReturn(extendedLdapUserDetails);
        when(extendedLdapUserDetails.getEmailAddress()).thenReturn("different-email@example.com");

        ScimUser invitedUser = new ScimUser("user-id-001", "user@example.com", "g", "f");
        invitedUser.setPrimaryEmail("user@example.com");
        when(scimUserProvisioning.retrieve("user-id-001", zoneId)).thenReturn(invitedUser);
        when(expiringCodeStore.generateCode(anyString(), any(), eq(null), eq(zoneId))).thenReturn(new ExpiringCode("code", new Timestamp(System.currentTimeMillis()), JsonUtils.writeValueAsString(codeData), null));

        mockMvc.perform(post("/invitations/accept_enterprise.do")
                        .param("enterprise_username", "test-ldap-user")
                        .param("enterprise_password", "password")
                        .param("enterprise_email", "email")
                        .param("code", "the_secret_code"))
                .andExpect(status().isUnprocessableEntity())
                .andExpect(view().name("invitations/accept_invite"))
                .andExpect(content().string(containsString("Email: " + "user@example.com")))
                .andExpect(content().string(containsString("Sign in with enterprise credentials:")))
                .andExpect(content().string(containsString("username")))
                .andExpect(model().attribute("code", "code"))
                .andExpect(model().attribute("error_message", "invite.email_mismatch"))
                .andReturn();

        verify(ldapActual).authenticate(any());
    }

    @Test
    void acceptInvitePage_for_verifiedUser() throws Exception {
        String zoneId = IdentityZoneHolder.get().getId();
        UaaUser user = new UaaUser("user@example.com", "", "user@example.com", "Given", "family");
        user.modifyId("verified-user");
        user.setVerified(true);
        when(userDatabase.retrieveUserById("verified-user")).thenReturn(user);
        Map<String, String> codeData = new HashMap<>();
        codeData.put("user_id", "verified-user");
        codeData.put("email", "user@example.com");
        codeData.put("origin", "some-origin");

        when(expiringCodeStore.peekCode("the_secret_code", zoneId)).thenReturn(createCode(codeData), null);
        when(invitationsService.acceptInvitation(anyString(), eq(""))).thenReturn(new AcceptedInvitation("blah.test.com", new ScimUser()));
        IdentityProvider provider = new IdentityProvider<>();
        provider.setType(OriginKeys.UAA);
        when(providerProvisioning.retrieveByOrigin(anyString(), anyString())).thenReturn(provider);
        MockHttpServletRequestBuilder get = get("/invitations/accept")
                .param("code", "the_secret_code");

        mockMvc.perform(get)
                .andExpect(redirectedUrl("blah.test.com"));
    }

    private ExpiringCode createCode(Map<String, String> codeData) {
        return new ExpiringCode("code", new Timestamp(System.currentTimeMillis()), JsonUtils.writeValueAsString(codeData), INVITATION.name());
    }

    @Test
    void incorrectGeneratedCodeIntent_for_verifiedUser() throws Exception {
        String zoneId = IdentityZoneHolder.get().getId();
        UaaUser user = new UaaUser("user@example.com", "", "user@example.com", "Given", "family");
        user.modifyId("verified-user");
        user.setVerified(true);
        when(userDatabase.retrieveUserById("verified-user")).thenReturn(user);

        Map<String, String> codeData = new HashMap<>();
        codeData.put("user_id", "verified-user");
        codeData.put("email", "user@example.com");
        when(expiringCodeStore.retrieveCode("the_secret_code", zoneId)).thenReturn(new ExpiringCode("code", new Timestamp(System.currentTimeMillis()), JsonUtils.writeValueAsString(codeData), "incorrect-code-intent"));
        when(expiringCodeStore.generateCode(anyString(), any(), eq(null), eq(zoneId))).thenReturn(new ExpiringCode("code", new Timestamp(System.currentTimeMillis()), JsonUtils.writeValueAsString(codeData), "incorrect-code-intent"));
        when(invitationsService.acceptInvitation("incorrect-code-intent", "")).thenThrow(new HttpClientErrorException(BAD_REQUEST));

        MockHttpServletRequestBuilder get = get("/invitations/accept")
                .param("code", "the_secret_code");

        mockMvc.perform(get).andExpect(status().isUnprocessableEntity());
    }

    @Test
    void acceptInvitePageWithExpiredCode() throws Exception {
        String zoneId = IdentityZoneHolder.get().getId();
        when(expiringCodeStore.retrieveCode(anyString(), eq(zoneId))).thenReturn(null);
        MockHttpServletRequestBuilder get = get("/invitations/accept").param("code", "the_secret_code");
        mockMvc.perform(get)
                .andExpect(status().isUnprocessableEntity())
                .andExpect(model().attribute("error_message_code", "code_expired"))
                .andExpect(view().name("invitations/accept_invite"))
                .andExpect(xpath("//*[@class='email-display']").doesNotExist())
                .andExpect(xpath("//form").doesNotExist());
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
    }

    @Test
    void missing_code() throws Exception {
        MockHttpServletRequestBuilder post = startAcceptInviteFlow("a", "a");

        String zoneId = IdentityZoneHolder.get().getId();
        when(expiringCodeStore.retrieveCode("thecode", zoneId)).thenReturn(null);

        IdentityProvider identityProvider = new IdentityProvider<>();
        identityProvider.setType(OriginKeys.UAA);
        when(providerProvisioning.retrieveByOrigin("uaa", "uaa")).thenReturn(identityProvider);
        mockMvc.perform(post)
                .andExpect(status().isUnprocessableEntity())
                .andExpect(model().attribute("error_message_code", "code_expired"))
                .andExpect(view().name("invitations/accept_invite"));
        verify(expiringCodeStore).retrieveCode("thecode", zoneId);
        verify(expiringCodeStore, never()).generateCode(anyString(), any(), anyString(), eq(zoneId));
        verify(invitationsService, never()).acceptInvitation(anyString(), anyString());
    }

    @Test
    void invalid_principal_id() throws Exception {
        MockHttpServletRequestBuilder post = startAcceptInviteFlow("a", "a");

        String zoneId = IdentityZoneHolder.get().getId();
        Map<String, String> codeData = getInvitationsCode(OriginKeys.UAA);
        codeData.put("user_id", "invalid id");
        String codeDataString = JsonUtils.writeValueAsString(codeData);
        when(expiringCodeStore.retrieveCode("thecode", zoneId)).thenReturn(new ExpiringCode("thecode", new Timestamp(1), codeDataString, INVITATION.name()), null);

        IdentityProvider identityProvider = new IdentityProvider<>();
        identityProvider.setType(OriginKeys.UAA);
        when(providerProvisioning.retrieveByOrigin("uaa", "uaa")).thenReturn(identityProvider);
        mockMvc.perform(post)
                .andExpect(status().isUnprocessableEntity())
                .andExpect(model().attribute("error_message_code", "code_expired"))
                .andExpect(view().name("invitations/accept_invite"));
        verify(expiringCodeStore).retrieveCode("thecode", zoneId);
        verify(expiringCodeStore, never()).generateCode(anyString(), any(), anyString(), eq(zoneId));
        verify(invitationsService, never()).acceptInvitation(anyString(), anyString());
    }

    @Test
    void acceptInviteWithContraveningPassword() throws Exception {
        doThrow(new InvalidPasswordException(Arrays.asList("Msg 2c", "Msg 1c"))).when(passwordValidator).validate("a");
        MockHttpServletRequestBuilder post = startAcceptInviteFlow("a", "a");

        String zoneId = IdentityZoneHolder.get().getId();
        Map<String, String> codeData = getInvitationsCode(OriginKeys.UAA);
        String codeDataString = JsonUtils.writeValueAsString(codeData);
        when(expiringCodeStore.retrieveCode("thecode", zoneId)).thenReturn(new ExpiringCode("thecode", new Timestamp(1), codeDataString, INVITATION.name()), null);
        when(expiringCodeStore.retrieveCode("thenewcode", zoneId)).thenReturn(new ExpiringCode("thenewcode", new Timestamp(1), codeDataString, INVITATION.name()), null);
        when(expiringCodeStore.generateCode(eq(codeDataString), any(), eq(INVITATION.name()), eq(zoneId))).thenReturn(
                new ExpiringCode("thenewcode", new Timestamp(1), codeDataString, INVITATION.name()),
                new ExpiringCode("thenewcode2", new Timestamp(1), codeDataString, INVITATION.name())
        );

        IdentityProvider identityProvider = new IdentityProvider<>();
        identityProvider.setType(OriginKeys.UAA);
        when(providerProvisioning.retrieveByOrigin("uaa", "uaa")).thenReturn(identityProvider);
        mockMvc.perform(post)
                .andExpect(status().isFound())
                .andExpect(model().attribute("error_message", "Msg 1c Msg 2c"))
                .andExpect(model().attribute("code", "thenewcode2"))
                .andExpect(view().name("redirect:accept"));
        verify(expiringCodeStore).retrieveCode("thecode", zoneId);
        verify(expiringCodeStore, times(2)).generateCode(anyString(), any(), anyString(), eq(zoneId));
        verify(invitationsService, never()).acceptInvitation(anyString(), anyString());
    }

    @Test
    void acceptInvite() throws Exception {
        ScimUser user = new ScimUser("user-id-001", "user@example.com", "fname", "lname");
        user.setPrimaryEmail(user.getUserName());
        MockHttpServletRequestBuilder post = startAcceptInviteFlow("passw0rd", "passw0rd");

        String zoneId = IdentityZoneHolder.get().getId();
        Map<String, String> codeData = getInvitationsCode(OriginKeys.UAA);
        String codeDataString = JsonUtils.writeValueAsString(codeData);
        ExpiringCode thecode = new ExpiringCode("thecode", new Timestamp(1), codeDataString, INVITATION.name());
        ExpiringCode thenewcode = new ExpiringCode("thenewcode", new Timestamp(1), codeDataString, INVITATION.name());
        ExpiringCode thenewcode2 = new ExpiringCode("thenewcode2", new Timestamp(1), codeDataString, INVITATION.name());
        when(expiringCodeStore.retrieveCode("thecode", zoneId)).thenReturn(thecode, null);
        when(expiringCodeStore.retrieveCode("thenewcode", zoneId)).thenReturn(thenewcode, null);
        when(expiringCodeStore.generateCode(eq(codeDataString), any(), eq(INVITATION.name()), eq(zoneId)))
                .thenReturn(thenewcode)
                .thenReturn(thenewcode2);

        when(invitationsService.acceptInvitation(anyString(), eq("passw0rd"))).thenReturn(new AcceptedInvitation("/home", user));

        mockMvc.perform(post)
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("/login?success=invite_accepted")).andReturn();

        verify(invitationsService).acceptInvitation(anyString(), eq("passw0rd"));
    }

    private MockHttpServletRequestBuilder startAcceptInviteFlow(String password, String passwordConfirmation) {
        String zoneId = IdentityZoneHolder.get().getId();
        UaaPrincipal uaaPrincipal = new UaaPrincipal("user-id-001", "user@example.com", "user@example.com", OriginKeys.UAA, null, zoneId);
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(uaaPrincipal, null, UaaAuthority.USER_AUTHORITIES);
        SecurityContextHolder.getContext().setAuthentication(token);

        return post("/invitations/accept.do")
                .param("code", "thecode")
                .param("password", password)
                .param("password_confirmation", passwordConfirmation);
    }

    @Test
    void acceptInviteWithValidClientRedirect() throws Exception {
        String zoneId = IdentityZoneHolder.get().getId();
        UaaPrincipal uaaPrincipal = new UaaPrincipal("user-id-001", "user@example.com", "user@example.com", OriginKeys.UAA, null, zoneId);
        ScimUser user = new ScimUser(uaaPrincipal.getId(), uaaPrincipal.getName(), "fname", "lname");
        user.setPrimaryEmail(user.getUserName());

        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(uaaPrincipal, null, UaaAuthority.USER_AUTHORITIES);
        SecurityContextHolder.getContext().setAuthentication(token);

        Map<String, String> codeData = getInvitationsCode(OriginKeys.UAA);
        String codeDataString = JsonUtils.writeValueAsString(codeData);
        when(expiringCodeStore.retrieveCode("thecode", zoneId)).thenReturn(new ExpiringCode("thecode", new Timestamp(1), codeDataString, INVITATION.name()), null);
        when(expiringCodeStore.generateCode(eq(codeDataString), any(), eq(INVITATION.name()), eq(zoneId))).thenReturn(new ExpiringCode("thenewcode", new Timestamp(1), codeDataString, INVITATION.name()));
        when(invitationsService.acceptInvitation(anyString(), eq("password"))).thenReturn(new AcceptedInvitation("valid.redirect.com", user));

        MockHttpServletRequestBuilder post = post("/invitations/accept.do")
                .param("password", "password")
                .param("password_confirmation", "password")
                .param("code", "thecode");

        mockMvc.perform(post)
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("/login?success=invite_accepted&form_redirect_uri=valid.redirect.com"));
    }

    @Test
    void acceptInviteWithInvalidClientRedirect() throws Exception {
        String zoneId = IdentityZoneHolder.get().getId();
        UaaPrincipal uaaPrincipal = new UaaPrincipal("user-id-001", "user@example.com", "user@example.com", OriginKeys.UAA, null, zoneId);
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(uaaPrincipal, null, UaaAuthority.USER_AUTHORITIES);
        SecurityContextHolder.getContext().setAuthentication(token);

        ScimUser user = new ScimUser(uaaPrincipal.getId(), uaaPrincipal.getName(), "fname", "lname");
        user.setPrimaryEmail(user.getUserName());

        Map<String, String> codeData = getInvitationsCode(OriginKeys.UAA);
        String codeDataString = JsonUtils.writeValueAsString(codeData);
        when(expiringCodeStore.retrieveCode("thecode", zoneId)).thenReturn(new ExpiringCode("thecode", new Timestamp(1), codeDataString, INVITATION.name()), null);
        when(expiringCodeStore.generateCode(eq(codeDataString), any(), eq(INVITATION.name()), eq(zoneId))).thenReturn(new ExpiringCode("thenewcode", new Timestamp(1), codeDataString, INVITATION.name()));

        when(invitationsService.acceptInvitation(anyString(), eq("password"))).thenReturn(new AcceptedInvitation("/home", user));

        MockHttpServletRequestBuilder post = post("/invitations/accept.do")
                .param("code", "thecode")
                .param("password", "password")
                .param("password_confirmation", "password");

        mockMvc.perform(post)
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("/login?success=invite_accepted"));
    }

    @Test
    void invalidCodeOnAcceptPost() throws Exception {
        String zoneId = IdentityZoneHolder.get().getId();
        UaaPrincipal uaaPrincipal = new UaaPrincipal("user-id-001", "user@example.com", "user@example.com", OriginKeys.UAA, null, zoneId);
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(uaaPrincipal, null, UaaAuthority.USER_AUTHORITIES);
        SecurityContextHolder.getContext().setAuthentication(token);

        Map<String, String> codeData = getInvitationsCode(OriginKeys.UAA);
        String codeDataString = JsonUtils.writeValueAsString(codeData);
        when(expiringCodeStore.retrieveCode("thecode", zoneId)).thenReturn(new ExpiringCode("thecode", new Timestamp(1), codeDataString, INVITATION.name()), null);
        when(expiringCodeStore.generateCode(eq(codeDataString), any(), eq(INVITATION.name()), eq(zoneId))).thenReturn(new ExpiringCode("thenewcode", new Timestamp(1), codeDataString, INVITATION.name()));

        doThrow(new HttpClientErrorException(BAD_REQUEST)).when(invitationsService).acceptInvitation(anyString(), anyString());

        MockHttpServletRequestBuilder post = post("/invitations/accept.do")
                .param("code", "thecode")
                .param("password", "password")
                .param("password_confirmation", "password");

        mockMvc.perform(post)
                .andExpect(status().isUnprocessableEntity())
                .andExpect(model().attribute("error_message_code", "code_expired"))
                .andExpect(view().name("invitations/accept_invite"));
    }

    @Test
    void acceptInviteWithoutMatchingPasswords() throws Exception {
        MockHttpServletRequestBuilder post = startAcceptInviteFlow("a", "b");

        String zoneId = IdentityZoneHolder.get().getId();
        Map<String, String> codeData = getInvitationsCode(OriginKeys.UAA);
        String codeDataString = JsonUtils.writeValueAsString(codeData);
        when(expiringCodeStore.retrieveCode("thecode", zoneId)).thenReturn(new ExpiringCode("thecode", new Timestamp(1), codeDataString, INVITATION.name()), null);
        when(expiringCodeStore.retrieveCode("thenewcode", zoneId)).thenReturn(new ExpiringCode("thenewcode", new Timestamp(1), codeDataString, INVITATION.name()), null);
        when(expiringCodeStore.generateCode(eq(codeDataString), any(), eq(INVITATION.name()), eq(zoneId))).thenReturn(
                new ExpiringCode("thenewcode", new Timestamp(1), codeDataString, INVITATION.name()),
                new ExpiringCode("thenewcode2", new Timestamp(1), codeDataString, INVITATION.name())
        );

        IdentityProvider identityProvider = new IdentityProvider<>();
        identityProvider.setType(OriginKeys.UAA);
        when(providerProvisioning.retrieveByOrigin("uaa", "uaa")).thenReturn(identityProvider);
        mockMvc.perform(post)
                .andExpect(status().isFound())
                .andExpect(model().attribute("error_message_code", "form_error"))
                .andExpect(model().attribute("code", "thenewcode2"))
                .andExpect(view().name("redirect:accept"));
        verify(expiringCodeStore).retrieveCode("thecode", zoneId);
        verify(expiringCodeStore, times(2)).generateCode(anyString(), any(), anyString(), eq(zoneId));
        verify(invitationsService, never()).acceptInvitation(anyString(), anyString());
    }

    @Test
    void acceptInviteDisplaysConsentText() throws Exception {
        IdentityZone defaultZone = IdentityZoneHolder.get();
        String zoneId = IdentityZoneHolder.get().getId();
        BrandingInformation branding = new BrandingInformation();
        branding.setConsent(new Consent("paying Jaskanwal Pawar & Jennifer Hamon each a million dollars", null));
        defaultZone.getConfig().setBranding(branding);

        IdentityProvider identityProvider = new IdentityProvider<>();
        identityProvider.setType(OriginKeys.UAA);
        when(providerProvisioning.retrieveByOrigin(anyString(), anyString())).thenReturn(identityProvider);

        Map<String, String> codeData = getInvitationsCode(OriginKeys.UAA);
        String codeDataString = JsonUtils.writeValueAsString(codeData);
        ExpiringCode expiringCode = new ExpiringCode("thecode", new Timestamp(1), codeDataString, INVITATION.name());
        when(expiringCodeStore.peekCode("thecode", zoneId))
                .thenReturn(expiringCode, null);

        mockMvc.perform(get("/invitations/accept")
                        .param("code", "thecode"))
                .andExpect(content().string(containsString("Jaskanwal")));

        // cleanup changes to default zone
        defaultZone.getConfig().setBranding(null);
    }

    @Test
    void acceptInviteDoesNotDisplayConsentCheckboxWhenNotConfiguredForZone() throws Exception {
        IdentityProvider identityProvider = new IdentityProvider<>();
        identityProvider.setType(OriginKeys.UAA);
        when(providerProvisioning.retrieveByOrigin(anyString(), anyString())).thenReturn(identityProvider);

        String zoneId = IdentityZoneHolder.get().getId();
        Map<String, String> codeData = getInvitationsCode(OriginKeys.UAA);
        String codeDataString = JsonUtils.writeValueAsString(codeData);
        ExpiringCode expiringCode = new ExpiringCode("thecode", new Timestamp(1), codeDataString, INVITATION.name());
        when(expiringCodeStore.retrieveCode("thecode", zoneId))
                .thenReturn(expiringCode, null);
        when(expiringCodeStore.generateCode(anyString(), any(), eq(INVITATION.name()), eq(zoneId)))
                .thenReturn(expiringCode);

        mockMvc.perform(get("/invitations/accept")
                        .param("code", "thecode"))
                .andExpect(content().string(not(containsString("I agree"))));
    }

    @Test
    void acceptInviteDisplaysErrorMessageIfConsentNotChecked() throws Exception {
        IdentityZone defaultZone = IdentityZoneHolder.get();
        String zoneId = IdentityZoneHolder.get().getId();
        BrandingInformation branding = new BrandingInformation();
        branding.setConsent(new Consent("paying Jaskanwal Pawar & Jennifer Hamon each a million dollars", null));
        defaultZone.getConfig().setBranding(branding);

        IdentityProvider identityProvider = new IdentityProvider<>();
        identityProvider.setType(OriginKeys.UAA);
        when(providerProvisioning.retrieveByOrigin(anyString(), anyString())).thenReturn(identityProvider);

        Map<String, String> codeData = getInvitationsCode(OriginKeys.UAA);
        String codeDataString = JsonUtils.writeValueAsString(codeData);
        ExpiringCode expiringCode = new ExpiringCode("thecode", new Timestamp(1), codeDataString, INVITATION.name());
        when(expiringCodeStore.peekCode(anyString(), eq(zoneId)))
                .thenReturn(expiringCode);
        when(expiringCodeStore.retrieveCode(anyString(), eq(zoneId)))
                .thenReturn(expiringCode);
        when(expiringCodeStore.generateCode(anyString(), any(), eq(INVITATION.name()), eq(zoneId)))
                .thenReturn(expiringCode);

        MvcResult mvcResult = mockMvc.perform(startAcceptInviteFlow("password", "password"))
                .andReturn();

        mockMvc.perform(get("/invitations/" + mvcResult.getResponse().getHeader("Location")))
                .andExpect(model().attribute("error_message_code", "missing_consent"));

        // cleanup changes to default zone
        defaultZone.getConfig().setBranding(null);
    }

    @Test
    void acceptInviteWorksWithConsentProvided() throws Exception {
        IdentityZone defaultZone = IdentityZoneHolder.get();
        String zoneId = IdentityZoneHolder.get().getId();
        BrandingInformation branding = new BrandingInformation();
        branding.setConsent(new Consent("paying Jaskanwal Pawar & Jennifer Hamon each a million dollars", null));
        defaultZone.getConfig().setBranding(branding);

        IdentityProvider identityProvider = new IdentityProvider<>();
        identityProvider.setType(OriginKeys.UAA);
        when(providerProvisioning.retrieveByOrigin(anyString(), anyString())).thenReturn(identityProvider);

        Map<String, String> codeData = getInvitationsCode(OriginKeys.UAA);
        String codeDataString = JsonUtils.writeValueAsString(codeData);
        ExpiringCode expiringCode = new ExpiringCode("thecode", new Timestamp(1), codeDataString, INVITATION.name());
        when(expiringCodeStore.retrieveCode(anyString(), eq(zoneId)))
                .thenReturn(expiringCode);
        when(expiringCodeStore.generateCode(anyString(), any(), eq(INVITATION.name()), eq(zoneId)))
                .thenReturn(expiringCode);

        when(invitationsService.acceptInvitation(anyString(), anyString()))
                .thenReturn(new AcceptedInvitation(codeData.get("redirect_uri"), null));

        MvcResult mvcResult = mockMvc.perform(startAcceptInviteFlow("password", "password")
                        .param("does_user_consent", "true"))
                .andReturn();
        assertThat(mvcResult.getResponse().getHeader("Location")).contains(codeData.get("redirect_uri"));

        // cleanup changes to default zone
        defaultZone.getConfig().setBranding(null);
    }

    @EnableWebMvc
    @Import(ThymeleafConfig.class)
    static class ContextConfiguration implements WebMvcConfigurer {

        @Autowired
        private RequestMappingHandlerAdapter requestMappingHandlerAdapter;

        @PostConstruct
        public void init() {
            requestMappingHandlerAdapter.setIgnoreDefaultModelOnRedirect(false);
        }

        @Override
        public void configureDefaultServletHandling(DefaultServletHandlerConfigurer configurer) {
            configurer.enable();
        }

        @Bean
        BuildInfo buildInfo() {
            return new TestBuildInfo();
        }

        @Bean
        public UaaUserDatabase userDatabase() {
            UaaUserDatabase userDatabase = mock(UaaUserDatabase.class);
            UaaUser user = new UaaUser("user@example.com", "", "user@example.com", "Given", "family");
            user = user.modifyId("user-id-001");
            when(userDatabase.retrieveUserById(user.getId())).thenReturn(user);
            return userDatabase;
        }

        @Bean
        public DynamicZoneAwareAuthenticationManager dynamicZoneAwareAuthenticationManager() {
            return mock(DynamicZoneAwareAuthenticationManager.class);
        }

        @Bean
        public ScimUserProvisioning userProvisioning() {
            return mock(ScimUserProvisioning.class);
        }

        @Bean
        public ResourceBundleMessageSource messageSource() {
            ResourceBundleMessageSource resourceBundleMessageSource = new ResourceBundleMessageSource();
            resourceBundleMessageSource.setBasename("messages");
            return resourceBundleMessageSource;
        }

        @Bean
        InvitationsService invitationsService() {
            return mock(InvitationsService.class);
        }

        @Bean
        InvitationsController invitationsController(final InvitationsService invitationsService,
                                                    final ExpiringCodeStore codeStore,
                                                    final PasswordValidator passwordPolicyValidator,
                                                    final @Qualifier("providerProvisioning") IdentityProviderProvisioning providerProvisioning,
                                                    final UaaUserDatabase userDatabase,
                                                    final ScimUserProvisioning provisioning,
                                                    final @Qualifier("zoneAwareAuthenticationManager") DynamicZoneAwareAuthenticationManager zoneAwareAuthenticationManager,
                                                    final @Qualifier("externalOAuthProviderConfigurator") ExternalOAuthProviderConfigurator externalOAuthProviderConfigurator) {
            return new InvitationsController(
                    invitationsService,
                    codeStore,
                    passwordPolicyValidator,
                    providerProvisioning,
                    zoneAwareAuthenticationManager,
                    userDatabase,
                    provisioning,
                    new IdentityZoneManagerImpl(),
                    externalOAuthProviderConfigurator);
        }

        @Bean
        ExpiringCodeStore expiringCodeStore() {
            return mock(ExpiringCodeStore.class);
        }

        @Bean
        PasswordValidator uaaPasswordValidator() {
            return mock(PasswordValidator.class);
        }

        @Bean
        IdentityProviderProvisioning providerProvisioning() {

            return mock(IdentityProviderProvisioning.class);
        }

        @Bean
        ClientDetailsService clientDetailsService() {
            return mock(ClientDetailsService.class);
        }

        @Bean
        DynamicZoneAwareAuthenticationManager zoneAwareAuthenticationManager() {
            return mock(DynamicZoneAwareAuthenticationManager.class);
        }

        @Bean
        CookieBasedCsrfTokenRepository loginCookieCsrfRepository() {
            return mock(CookieBasedCsrfTokenRepository.class);
        }

        @Bean
        ExternalOAuthProviderConfigurator externalOAuthProviderConfigurator() {
            return mock(ExternalOAuthProviderConfigurator.class);
        }
    }
}
