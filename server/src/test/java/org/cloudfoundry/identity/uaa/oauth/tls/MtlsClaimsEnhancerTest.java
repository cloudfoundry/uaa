package org.cloudfoundry.identity.uaa.oauth.tls;

import org.cloudfoundry.identity.uaa.client.TlsClientAuthConfiguration;
import org.cloudfoundry.identity.uaa.client.UaaClientDetails;
import org.cloudfoundry.identity.uaa.constants.ClientAuthentication;
import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetailsService;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Authentication;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Request;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.security.auth.x500.X500Principal;
import java.io.Serializable;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.CLIENT_AUTH_METHOD;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class MtlsClaimsEnhancerTest {

    private TlsClientAuthentication tlsClientAuthentication;
    private ClientDetailsService clientDetailsService;
    private MtlsClaimsEnhancer enhancer;

    @BeforeEach
    void setUp() {
        tlsClientAuthentication = mock(TlsClientAuthentication.class);
        clientDetailsService = mock(ClientDetailsService.class);
        enhancer = new MtlsClaimsEnhancer(tlsClientAuthentication, clientDetailsService);
    }

    @Test
    void extractsClaimsFromCertOuFields() throws Exception {
        X509Certificate cert = mock(X509Certificate.class);
        when(cert.getSubjectX500Principal()).thenReturn(
            new X500Principal("CN=instance-guid, OU=app:app-guid-123, OU=space:space-guid-456, OU=organization:org-guid-789, O=Cloud Foundry"));
        when(tlsClientAuthentication.hasCertificateFromRequest()).thenReturn(true);
        when(tlsClientAuthentication.getCertificateFromRequest(any())).thenReturn(cert);

        UaaClientDetails clientDetails = new UaaClientDetails();
        clientDetails.setClientId("instance-identity");
        clientDetails.setTlsClientAuthConfiguration(new TlsClientAuthConfiguration(
            "-----BEGIN CERTIFICATE-----\nMIIBxxx\n-----END CERTIFICATE-----\n",
            List.of(
                new TlsClientAuthConfiguration.ClaimMapping("subject_ou", "^app:(.+)$", "app_guid"),
                new TlsClientAuthConfiguration.ClaimMapping("subject_ou", "^space:(.+)$", "space_guid"),
                new TlsClientAuthConfiguration.ClaimMapping("subject_ou", "^organization:(.+)$", "org_guid"),
                new TlsClientAuthConfiguration.ClaimMapping("subject_cn", null, "cf_instance_guid")
            )
        ));
        when(clientDetailsService.loadClientByClientId("instance-identity")).thenReturn(clientDetails);

        OAuth2Authentication auth = mockAuthentication("instance-identity");
        Map<String, Object> result = enhancer.enhance(new HashMap<>(), auth);

        assertThat(result).containsEntry("app_guid", "app-guid-123");
        assertThat(result).containsEntry("space_guid", "space-guid-456");
        assertThat(result).containsEntry("org_guid", "org-guid-789");
        assertThat(result).containsEntry("cf_instance_guid", "instance-guid");
    }

    @Test
    void addsX5tThumbprintWhenCertPresent() throws Exception {
        X509Certificate cert = mock(X509Certificate.class);
        when(cert.getEncoded()).thenReturn(new byte[]{1, 2, 3});
        when(cert.getSubjectX500Principal()).thenReturn(new X500Principal("CN=test"));
        when(tlsClientAuthentication.hasCertificateFromRequest()).thenReturn(true);
        when(tlsClientAuthentication.getCertificateFromRequest(any())).thenReturn(cert);

        UaaClientDetails clientDetails = new UaaClientDetails();
        clientDetails.setClientId("instance-identity");
        clientDetails.setTlsClientAuthConfiguration(
            new TlsClientAuthConfiguration("-----BEGIN CERTIFICATE-----\nMIIBxxx\n-----END CERTIFICATE-----\n", null));
        when(clientDetailsService.loadClientByClientId("instance-identity")).thenReturn(clientDetails);

        OAuth2Authentication auth = mockAuthentication("instance-identity");
        Map<String, Object> result = enhancer.enhance(new HashMap<>(), auth);

        assertThat(result).containsKey("cnf");
        @SuppressWarnings("unchecked")
        Map<String, Object> cnf = (Map<String, Object>) result.get("cnf");
        assertThat(cnf).containsKey("x5t#S256");
    }

    @Test
    void returnsEmptyWhenNoCertOnRequest() {
        when(tlsClientAuthentication.hasCertificateFromRequest()).thenReturn(false);
        OAuth2Authentication auth = mockAuthentication("instance-identity");
        Map<String, Object> result = enhancer.enhance(new HashMap<>(), auth);
        assertThat(result).doesNotContainKey("app_guid");
    }

    @Test
    void dotNotationClaimProducesNestedObject() throws Exception {
        X509Certificate cert = mock(X509Certificate.class);
        when(cert.getEncoded()).thenReturn(new byte[]{1, 2, 3});
        when(cert.getSubjectX500Principal()).thenReturn(new X500Principal(
            "CN=inst-guid, OU=app:app-guid, OU=space:space-guid, OU=organization:org-guid, O=Cloud Foundry"));
        when(tlsClientAuthentication.hasCertificateFromRequest()).thenReturn(true);
        when(tlsClientAuthentication.getCertificateFromRequest(any())).thenReturn(cert);

        UaaClientDetails clientDetails = new UaaClientDetails();
        clientDetails.setClientId("instance-identity");
        clientDetails.setTlsClientAuthConfiguration(new TlsClientAuthConfiguration(
            "-----BEGIN CERTIFICATE-----\nMIIBxxx\n-----END CERTIFICATE-----\n",
            List.of(
                new TlsClientAuthConfiguration.ClaimMapping("subject_ou", "^app:(.+)$",          "cf.app"),
                new TlsClientAuthConfiguration.ClaimMapping("subject_ou", "^space:(.+)$",        "cf.space"),
                new TlsClientAuthConfiguration.ClaimMapping("subject_ou", "^organization:(.+)$", "cf.org"),
                new TlsClientAuthConfiguration.ClaimMapping("subject_cn", null,                  "cf_instance_guid")
            )
        ));
        when(clientDetailsService.loadClientByClientId("instance-identity")).thenReturn(clientDetails);

        OAuth2Authentication auth = mockAuthentication("instance-identity");
        Map<String, Object> result = enhancer.enhance(new HashMap<>(), auth);

        assertThat(result).containsKey("cf");
        @SuppressWarnings("unchecked")
        Map<String, Object> cf = (Map<String, Object>) result.get("cf");
        assertThat(cf).containsEntry("app",   "app-guid");
        assertThat(cf).containsEntry("space", "space-guid");
        assertThat(cf).containsEntry("org",   "org-guid");
        assertThat(result).containsEntry("cf_instance_guid", "inst-guid");
        // Dot-notation keys must NOT appear as top-level claims
        assertThat(result).doesNotContainKey("cf.app");
        assertThat(result).doesNotContainKey("cf.space");
        assertThat(result).doesNotContainKey("cf.org");
    }

    @Test
    void flatClaimsStillWorkAfterRefactor() throws Exception {
        // Existing flat-key behaviour must be unchanged
        X509Certificate cert = mock(X509Certificate.class);
        when(cert.getEncoded()).thenReturn(new byte[]{1, 2, 3});
        when(cert.getSubjectX500Principal()).thenReturn(new X500Principal(
            "CN=instance-guid, OU=app:app-guid-123, OU=space:space-guid-456, OU=organization:org-guid-789, O=Cloud Foundry"));
        when(tlsClientAuthentication.hasCertificateFromRequest()).thenReturn(true);
        when(tlsClientAuthentication.getCertificateFromRequest(any())).thenReturn(cert);

        UaaClientDetails clientDetails = new UaaClientDetails();
        clientDetails.setClientId("instance-identity");
        clientDetails.setTlsClientAuthConfiguration(new TlsClientAuthConfiguration(
            "-----BEGIN CERTIFICATE-----\nMIIBxxx\n-----END CERTIFICATE-----\n",
            List.of(
                new TlsClientAuthConfiguration.ClaimMapping("subject_ou", "^app:(.+)$",          "app_guid"),
                new TlsClientAuthConfiguration.ClaimMapping("subject_ou", "^space:(.+)$",        "space_guid"),
                new TlsClientAuthConfiguration.ClaimMapping("subject_ou", "^organization:(.+)$", "org_guid"),
                new TlsClientAuthConfiguration.ClaimMapping("subject_cn", null,                  "cf_instance_guid")
            )
        ));
        when(clientDetailsService.loadClientByClientId("instance-identity")).thenReturn(clientDetails);

        OAuth2Authentication auth = mockAuthentication("instance-identity");
        Map<String, Object> result = enhancer.enhance(new HashMap<>(), auth);

        assertThat(result).containsEntry("app_guid",        "app-guid-123");
        assertThat(result).containsEntry("space_guid",      "space-guid-456");
        assertThat(result).containsEntry("org_guid",        "org-guid-789");
        assertThat(result).containsEntry("cf_instance_guid","instance-guid");
        assertThat(result).doesNotContainKey("cf");
    }

    @Test
    void dotNotationOverwritesFlatClaimWithSameParentKey() throws Exception {
        X509Certificate cert = mock(X509Certificate.class);
        when(cert.getEncoded()).thenReturn(new byte[]{1, 2, 3});
        when(cert.getSubjectX500Principal()).thenReturn(new X500Principal(
            "CN=inst-guid, OU=app:app-guid, O=cf-org"));
        when(tlsClientAuthentication.hasCertificateFromRequest()).thenReturn(true);
        when(tlsClientAuthentication.getCertificateFromRequest(any())).thenReturn(cert);

        UaaClientDetails clientDetails = new UaaClientDetails();
        clientDetails.setClientId("instance-identity");
        clientDetails.setTlsClientAuthConfiguration(new TlsClientAuthConfiguration(
            "-----BEGIN CERTIFICATE-----\nMIIBxxx\n-----END CERTIFICATE-----\n",
            List.of(
                new TlsClientAuthConfiguration.ClaimMapping("subject_o",  null,          "cf"),      // flat "cf"
                new TlsClientAuthConfiguration.ClaimMapping("subject_ou", "^app:(.+)$",  "cf.app")   // nested "cf.app"
            )
        ));
        when(clientDetailsService.loadClientByClientId("instance-identity")).thenReturn(clientDetails);

        OAuth2Authentication auth = mockAuthentication("instance-identity");
        Map<String, Object> result = enhancer.enhance(new HashMap<>(), auth);

        // Nested map must overwrite the flat "cf" string value
        assertThat(result.get("cf")).isInstanceOf(Map.class);
        @SuppressWarnings("unchecked")
        Map<String, Object> cf = (Map<String, Object>) result.get("cf");
        assertThat(cf).containsEntry("app", "app-guid");
    }

    @Test
    void subTemplateRendered() throws Exception {
        X509Certificate cert = mockCfCert();
        when(tlsClientAuthentication.hasCertificateFromRequest()).thenReturn(true);
        when(tlsClientAuthentication.getCertificateFromRequest(any())).thenReturn(cert);

        TlsClientAuthConfiguration config = cfMappingsConfig();
        config.setSubTemplate("o/{cf.org}/s/{cf.space}/a/{cf.app}");

        UaaClientDetails clientDetails = new UaaClientDetails();
        clientDetails.setClientId("instance-identity");
        clientDetails.setTlsClientAuthConfiguration(config);
        when(clientDetailsService.loadClientByClientId("instance-identity")).thenReturn(clientDetails);

        Map<String, Object> result = enhancer.enhance(new HashMap<>(), mockAuthentication("instance-identity"));

        assertThat(result).containsEntry("sub",
            "o/org-guid/s/space-guid/a/app-guid");
    }

    @Test
    void audTemplatesRenderedAndOverrideDefault() throws Exception {
        X509Certificate cert = mockCfCert();
        when(tlsClientAuthentication.hasCertificateFromRequest()).thenReturn(true);
        when(tlsClientAuthentication.getCertificateFromRequest(any())).thenReturn(cert);

        TlsClientAuthConfiguration config = cfMappingsConfig();
        config.setAudTemplates(List.of(
            "o/{cf.org}/s/{cf.space}/a/{cf.app}",
            "o/{cf.org}/s/{cf.space}",
            "o/{cf.org}"
        ));

        UaaClientDetails clientDetails = new UaaClientDetails();
        clientDetails.setClientId("instance-identity");
        clientDetails.setTlsClientAuthConfiguration(config);
        when(clientDetailsService.loadClientByClientId("instance-identity")).thenReturn(clientDetails);

        Map<String, Object> result = enhancer.enhance(new HashMap<>(), mockAuthentication("instance-identity"));

        assertThat(result).containsKey("aud");
        @SuppressWarnings("unchecked")
        List<String> aud = (List<String>) result.get("aud");
        assertThat(aud).containsExactly(
            "o/org-guid/s/space-guid/a/app-guid",
            "o/org-guid/s/space-guid",
            "o/org-guid"
        );
    }

    @Test
    void subOmittedWhenTemplateVarMissing() throws Exception {
        // Cert has no OU fields → cf.org will not be in vars
        X509Certificate cert = mock(X509Certificate.class);
        when(cert.getEncoded()).thenReturn(new byte[]{1, 2, 3});
        when(cert.getSubjectX500Principal()).thenReturn(new X500Principal("CN=only-cn"));
        when(tlsClientAuthentication.hasCertificateFromRequest()).thenReturn(true);
        when(tlsClientAuthentication.getCertificateFromRequest(any())).thenReturn(cert);

        TlsClientAuthConfiguration config = new TlsClientAuthConfiguration(
            "-----BEGIN CERTIFICATE-----\nMIIBxxx\n-----END CERTIFICATE-----\n",
            List.of(new TlsClientAuthConfiguration.ClaimMapping("subject_cn", null, "cf_instance_guid"))
        );
        config.setSubTemplate("o/{cf.org}");  // {cf.org} will have no value

        UaaClientDetails clientDetails = new UaaClientDetails();
        clientDetails.setClientId("instance-identity");
        clientDetails.setTlsClientAuthConfiguration(config);
        when(clientDetailsService.loadClientByClientId("instance-identity")).thenReturn(clientDetails);

        Map<String, Object> result = enhancer.enhance(new HashMap<>(), mockAuthentication("instance-identity"));

        assertThat(result).doesNotContainKey("sub");
        assertThat(result).containsEntry("cf_instance_guid", "only-cn");
    }

    @Test
    void audEntryDroppedWhenTemplateVarMissing() throws Exception {
        X509Certificate cert = mockCfCert();
        when(tlsClientAuthentication.hasCertificateFromRequest()).thenReturn(true);
        when(tlsClientAuthentication.getCertificateFromRequest(any())).thenReturn(cert);

        TlsClientAuthConfiguration config = cfMappingsConfig();
        config.setAudTemplates(List.of(
            "a/{cf.app}",          // will resolve
            "x/{missing_var}"      // {missing_var} not in vars → dropped
        ));

        UaaClientDetails clientDetails = new UaaClientDetails();
        clientDetails.setClientId("instance-identity");
        clientDetails.setTlsClientAuthConfiguration(config);
        when(clientDetailsService.loadClientByClientId("instance-identity")).thenReturn(clientDetails);

        Map<String, Object> result = enhancer.enhance(new HashMap<>(), mockAuthentication("instance-identity"));

        assertThat(result).containsKey("aud");
        @SuppressWarnings("unchecked")
        List<String> aud = (List<String>) result.get("aud");
        assertThat(aud).containsExactly("a/app-guid");
    }

    @Test
    void audOmittedWhenAllTemplateEntriesFail() throws Exception {
        X509Certificate cert = mockCfCert();
        when(tlsClientAuthentication.hasCertificateFromRequest()).thenReturn(true);
        when(tlsClientAuthentication.getCertificateFromRequest(any())).thenReturn(cert);

        TlsClientAuthConfiguration config = cfMappingsConfig();
        config.setAudTemplates(List.of("x/{missing}", "y/{also_missing}"));

        UaaClientDetails clientDetails = new UaaClientDetails();
        clientDetails.setClientId("instance-identity");
        clientDetails.setTlsClientAuthConfiguration(config);
        when(clientDetailsService.loadClientByClientId("instance-identity")).thenReturn(clientDetails);

        Map<String, Object> result = enhancer.enhance(new HashMap<>(), mockAuthentication("instance-identity"));

        assertThat(result).doesNotContainKey("aud");
    }

    @Test
    void noTemplatesConfiguredLeavesSubAndAudAbsent() throws Exception {
        X509Certificate cert = mockCfCert();
        when(tlsClientAuthentication.hasCertificateFromRequest()).thenReturn(true);
        when(tlsClientAuthentication.getCertificateFromRequest(any())).thenReturn(cert);

        // Config with no subTemplate/audTemplates (original behaviour)
        UaaClientDetails clientDetails = new UaaClientDetails();
        clientDetails.setClientId("instance-identity");
        clientDetails.setTlsClientAuthConfiguration(cfMappingsConfig());
        when(clientDetailsService.loadClientByClientId("instance-identity")).thenReturn(clientDetails);

        Map<String, Object> result = enhancer.enhance(new HashMap<>(), mockAuthentication("instance-identity"));

        assertThat(result).doesNotContainKey("sub");
        assertThat(result).doesNotContainKey("aud");
    }

    @Test
    void stringPathInAdditionalInformationLoadsSubTemplateAndAudTemplates() throws Exception {
        X509Certificate cert = mockCfCert();
        when(tlsClientAuthentication.hasCertificateFromRequest()).thenReturn(true);
        when(tlsClientAuthentication.getCertificateFromRequest(any())).thenReturn(cert);

        UaaClientDetails clientDetails = new UaaClientDetails();
        clientDetails.setClientId("instance-identity");
        // Do NOT call setTlsClientAuthConfiguration — use String values directly
        clientDetails.setAdditionalInformation(Map.of(
            TlsClientAuthConfiguration.TLS_CLIENT_AUTH_CA,
                "-----BEGIN CERTIFICATE-----\nMIIBxxx\n-----END CERTIFICATE-----\n",
            TlsClientAuthConfiguration.TLS_CLIENT_AUTH_CLAIM_MAPPINGS,
                "[{\"field\":\"subject_ou\",\"pattern\":\"^app:(.+)$\",\"claim\":\"cf.app\"},"
                + "{\"field\":\"subject_cn\",\"claim\":\"cf_instance_guid\"}]",
            TlsClientAuthConfiguration.TLS_CLIENT_AUTH_SUB_TEMPLATE,
                "app/{cf.app}",
            TlsClientAuthConfiguration.TLS_CLIENT_AUTH_AUD_TEMPLATES,
                "[\"app/{cf.app}\"]"
        ));
        when(clientDetailsService.loadClientByClientId("instance-identity")).thenReturn(clientDetails);

        Map<String, Object> result = enhancer.enhance(new HashMap<>(), mockAuthentication("instance-identity"));

        assertThat(result).containsEntry("sub", "app/app-guid");
        assertThat(result).containsKey("aud");
        @SuppressWarnings("unchecked")
        List<String> aud = (List<String>) result.get("aud");
        assertThat(aud).containsExactly("app/app-guid");
    }

    @Test
    void extractsCnValueContainingEscapedComma() throws Exception {
        // RFC 2253 escapes literal commas inside an attribute value with a backslash.
        // A naive dn.split(",") breaks on the escaped comma and mangles the CN value.
        X509Certificate cert = mock(X509Certificate.class);
        when(cert.getEncoded()).thenReturn(new byte[]{1, 2, 3});
        when(cert.getSubjectX500Principal()).thenReturn(new X500Principal(
            "CN=Smith\\, John,OU=app:app-guid-123,O=Cloud Foundry"));
        when(tlsClientAuthentication.hasCertificateFromRequest()).thenReturn(true);
        when(tlsClientAuthentication.getCertificateFromRequest(any())).thenReturn(cert);

        UaaClientDetails clientDetails = new UaaClientDetails();
        clientDetails.setClientId("instance-identity");
        clientDetails.setTlsClientAuthConfiguration(new TlsClientAuthConfiguration(
            "-----BEGIN CERTIFICATE-----\nMIIBxxx\n-----END CERTIFICATE-----\n",
            List.of(
                new TlsClientAuthConfiguration.ClaimMapping("subject_cn", null, "cf_instance_guid"),
                new TlsClientAuthConfiguration.ClaimMapping("subject_ou", "^app:(.+)$", "app_guid")
            )
        ));
        when(clientDetailsService.loadClientByClientId("instance-identity")).thenReturn(clientDetails);

        Map<String, Object> result = enhancer.enhance(new HashMap<>(), mockAuthentication("instance-identity"));

        assertThat(result).containsEntry("cf_instance_guid", "Smith, John");
        assertThat(result).containsEntry("app_guid", "app-guid-123");
    }

    @Test
    void extractsOuValueContainingEscapedComma() throws Exception {
        // Same RFC 2253 escaping issue, but for a multi-valued OU list: an escaped comma
        // inside one OU must not be treated as an RDN separator, and subsequent OUs must
        // still be collected correctly.
        X509Certificate cert = mock(X509Certificate.class);
        when(cert.getEncoded()).thenReturn(new byte[]{1, 2, 3});
        when(cert.getSubjectX500Principal()).thenReturn(new X500Principal(
            "CN=inst-guid,OU=team\\, ops,OU=app:app-guid-123,O=Cloud Foundry"));
        when(tlsClientAuthentication.hasCertificateFromRequest()).thenReturn(true);
        when(tlsClientAuthentication.getCertificateFromRequest(any())).thenReturn(cert);

        UaaClientDetails clientDetails = new UaaClientDetails();
        clientDetails.setClientId("instance-identity");
        clientDetails.setTlsClientAuthConfiguration(new TlsClientAuthConfiguration(
            "-----BEGIN CERTIFICATE-----\nMIIBxxx\n-----END CERTIFICATE-----\n",
            List.of(
                new TlsClientAuthConfiguration.ClaimMapping("subject_ou", "^(team, ops)$", "team"),
                new TlsClientAuthConfiguration.ClaimMapping("subject_ou", "^app:(.+)$", "app_guid")
            )
        ));
        when(clientDetailsService.loadClientByClientId("instance-identity")).thenReturn(clientDetails);

        Map<String, Object> result = enhancer.enhance(new HashMap<>(), mockAuthentication("instance-identity"));

        assertThat(result).containsEntry("team", "team, ops");
        assertThat(result).containsEntry("app_guid", "app-guid-123");
    }

    @Test
    void enhanceReturnsEmptyWhenClientAuthenticatedViaClientSecretInsteadOfTlsClientAuth() throws Exception {
        // Reproduces PR review concern (MtlsClaimsEnhancer.java:76): a client with both a
        // client_secret AND tls-client-auth-ca configured could hit /oauth/mtls/token, present a
        // harvested/unvalidated certificate (via the mapped X509Certificate attribute), but
        // authenticate with the secret instead -- bypassing validateTlsClientAuth entirely.
        // The enhancer must not derive identity/cnf claims from a certificate that was never
        // actually validated as the proof of authentication.
        X509Certificate cert = mock(X509Certificate.class);
        when(cert.getEncoded()).thenReturn(new byte[]{1, 2, 3});
        when(cert.getSubjectX500Principal()).thenReturn(new X500Principal(
            "CN=instance-guid, OU=app:app-guid-123, O=Cloud Foundry"));
        when(tlsClientAuthentication.hasCertificateFromRequest()).thenReturn(true);
        when(tlsClientAuthentication.getCertificateFromRequest(any())).thenReturn(cert);

        UaaClientDetails clientDetails = new UaaClientDetails();
        clientDetails.setClientId("instance-identity");
        clientDetails.setTlsClientAuthConfiguration(new TlsClientAuthConfiguration(
            "-----BEGIN CERTIFICATE-----\nMIIBxxx\n-----END CERTIFICATE-----\n",
            List.of(new TlsClientAuthConfiguration.ClaimMapping("subject_cn", null, "cf_instance_guid"))
        ));
        when(clientDetailsService.loadClientByClientId("instance-identity")).thenReturn(clientDetails);

        OAuth2Authentication auth = mockAuthenticationWithMethod("instance-identity", "client_secret_basic");
        Map<String, Object> result = enhancer.enhance(new HashMap<>(), auth);

        assertThat(result).doesNotContainKey("cf_instance_guid");
        assertThat(result).doesNotContainKey("cnf");
        assertThat(result).isEmpty();
    }

    @Test
    void enhanceReturnsEmptyWhenClientAuthMethodExtensionIsMissing() throws Exception {
        // Fail closed: if the client_auth_method extension isn't present at all (e.g. an older
        // token-granting path that never set it), claims must not be derived either.
        X509Certificate cert = mock(X509Certificate.class);
        when(cert.getEncoded()).thenReturn(new byte[]{1, 2, 3});
        when(cert.getSubjectX500Principal()).thenReturn(new X500Principal("CN=instance-guid"));
        when(tlsClientAuthentication.hasCertificateFromRequest()).thenReturn(true);
        when(tlsClientAuthentication.getCertificateFromRequest(any())).thenReturn(cert);

        UaaClientDetails clientDetails = new UaaClientDetails();
        clientDetails.setClientId("instance-identity");
        clientDetails.setTlsClientAuthConfiguration(new TlsClientAuthConfiguration(
            "-----BEGIN CERTIFICATE-----\nMIIBxxx\n-----END CERTIFICATE-----\n",
            List.of(new TlsClientAuthConfiguration.ClaimMapping("subject_cn", null, "cf_instance_guid"))
        ));
        when(clientDetailsService.loadClientByClientId("instance-identity")).thenReturn(clientDetails);

        OAuth2Authentication auth = mockAuthenticationWithMethod("instance-identity", null);
        Map<String, Object> result = enhancer.enhance(new HashMap<>(), auth);

        assertThat(result).isEmpty();
    }

    private X509Certificate mockCfCert() throws Exception {
        X509Certificate cert = mock(X509Certificate.class);
        when(cert.getEncoded()).thenReturn(new byte[]{1, 2, 3});
        when(cert.getSubjectX500Principal()).thenReturn(new X500Principal(
            "CN=inst-guid, OU=app:app-guid, OU=space:space-guid, OU=organization:org-guid, O=Cloud Foundry"));
        return cert;
    }

    private TlsClientAuthConfiguration cfMappingsConfig() {
        return new TlsClientAuthConfiguration(
            "-----BEGIN CERTIFICATE-----\nMIIBxxx\n-----END CERTIFICATE-----\n",
            List.of(
                new TlsClientAuthConfiguration.ClaimMapping("subject_ou", "^app:(.+)$",          "cf.app"),
                new TlsClientAuthConfiguration.ClaimMapping("subject_ou", "^space:(.+)$",        "cf.space"),
                new TlsClientAuthConfiguration.ClaimMapping("subject_ou", "^organization:(.+)$", "cf.org"),
                new TlsClientAuthConfiguration.ClaimMapping("subject_cn", null,                  "cf_instance_guid")
            )
        );
    }

    private OAuth2Authentication mockAuthentication(String clientId) {
        // Default: represents a client that actually authenticated via tls_client_auth,
        // matching what the mTLS token endpoint's ClientDetailsAuthenticationProvider sets
        // after validateTlsClientAuth succeeds.
        return mockAuthenticationWithMethod(clientId, ClientAuthentication.TLS_CLIENT_AUTH);
    }

    private OAuth2Authentication mockAuthenticationWithMethod(String clientId, String clientAuthMethod) {
        OAuth2Request request = mock(OAuth2Request.class);
        when(request.getClientId()).thenReturn(clientId);
        Map<String, Serializable> extensions = clientAuthMethod == null
                ? Map.of()
                : Map.of(CLIENT_AUTH_METHOD, clientAuthMethod);
        when(request.getExtensions()).thenReturn(extensions);
        OAuth2Authentication auth = mock(OAuth2Authentication.class);
        when(auth.getOAuth2Request()).thenReturn(request);
        return auth;
    }
}
