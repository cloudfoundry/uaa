package org.cloudfoundry.identity.uaa.oauth.tls;

import org.cloudfoundry.identity.uaa.client.TlsClientAuthConfiguration;
import org.cloudfoundry.identity.uaa.client.UaaClientDetails;
import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetailsService;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Authentication;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Request;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.security.auth.x500.X500Principal;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
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
        when(tlsClientAuthentication.getCertificateFromRequest()).thenReturn(cert);

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
        when(tlsClientAuthentication.getCertificateFromRequest()).thenReturn(cert);

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
        when(tlsClientAuthentication.getCertificateFromRequest()).thenReturn(null);
        OAuth2Authentication auth = mockAuthentication("instance-identity");
        Map<String, Object> result = enhancer.enhance(new HashMap<>(), auth);
        assertThat(result).doesNotContainKey("app_guid");
    }

    private OAuth2Authentication mockAuthentication(String clientId) {
        OAuth2Request request = mock(OAuth2Request.class);
        when(request.getClientId()).thenReturn(clientId);
        OAuth2Authentication auth = mock(OAuth2Authentication.class);
        when(auth.getOAuth2Request()).thenReturn(request);
        return auth;
    }
}
