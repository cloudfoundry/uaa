package org.cloudfoundry.identity.uaa.mock.saml;

import org.cloudfoundry.identity.uaa.DefaultTestContext;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.JdbcIdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.SamlIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.junit.jupiter.api.Test;
import org.opensaml.saml.saml2.core.Response;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.test.web.servlet.MockMvc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.cloudfoundry.identity.uaa.provider.saml.Saml2TestUtils.responseWithAssertions;
import static org.cloudfoundry.identity.uaa.provider.saml.Saml2TestUtils.serializedResponse;
import static org.springframework.http.HttpHeaders.HOST;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Regression test for the bug where a SAML IDP stored with a {@code null} {@code external_key}
 * column (which happens when an IDP is persisted without {@code idpEntityId} being set, as
 * {@code BootstrapSamlIdentityProviderData} did for URL-type metadata) cannot be resolved when a
 * SAML response arrives at the legacy SSO alias endpoint.
 *
 * <p>Root cause: {@code BootstrapSamlIdentityProviderData.setIdentityProviders} only called
 * {@code def.setIdpEntityId(...)} for {@code DATA} (inline XML) metadata type. For {@code URL}
 * type the field was never set. {@link org.cloudfoundry.identity.uaa.provider.JdbcIdentityProviderProvisioning}
 * stores {@code external_key = saml.getIdpEntityId()}, so URL-type bootstrap IDPs end up with
 * {@code external_key = null}. The fix adds a dynamic metadata fallback in
 * {@link org.cloudfoundry.identity.uaa.provider.saml.ConfiguratorRelyingPartyRegistrationRepository}:
 * when {@code idpEntityId} (read from {@code external_key}) is {@code null}, the entity ID is
 * resolved on-the-fly from the stored metadata XML so that the lookup succeeds.
 */
@DefaultTestContext
class BootstrapSamlIdpSsoMockMvcTests {

    /**
     * Entity ID of the test IDP. Must not overlap with the entity IDs already registered in
     * {@code mockmvc_unittest_properties.yml} ({@code https://some.idp.test/saml/idp} and
     * {@code https://some.idp.test/saml2/idp}).
     */
    private static final String IDP_ENTITY_ID = "https://test-saml-idp.example.org/metadata";

    /**
     * PKCS8-encoded RSA private key for the test IDP, generated solely for this test.
     * The matching certificate is embedded in {@link #IDP_METADATA}.
     */
    private static final String IDP_PRIVATE_KEY = """
            -----BEGIN PRIVATE KEY-----
            MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC6Vrm0mO2lSCQw
            k4pdCUPcPwq8bB8x4zHOWWpD6+AQgqXpKlQEqSjrC6NVqXKHip1mPA8QE/fOpxhd
            yk3Y2B7VKcvk/5Xq4EaqVslc+Ghve27RnJeY04KgKYuRFCoTeUxm+B/z2IMKr0e8
            IY96Q0HD+azYpyCeBk0wqi3kgHs6Md/C1W8evNvKOcfY7GzrTBCxM7CFuRevod/4
            vti9IVc+pbRO1/8j+DPYBk//Ta2iw0pBOnKfUtoqXhgVIXgw+citPa8hIcdZbUrP
            TMq/66w3LXe4EFChKuikN5KEe88u3OcZdPBlIamhbwti+tx/qTynoqIov/xW2rwe
            OQxo7XjbAgMBAAECggEAME70lSgCkFOMIlXVzLnusGZdo6zKR5Y1nuAahyJbNByS
            48iYAJ9UXt9lCHvGF/KtTMhsRUhP+fDjBcnBdeLN14ie9i720G41k8qtKJ+z/5b6
            C3iz6qiHGHu81a9rGyJa1uUj74Vlr7ryd4kh19og7ixIDeECOUW79E5iWHegutyp
            t4OKRCPK1w5BDMCnowVOXxZaR97kWGhJOFx+GMuV2A2L03gm/BjgjNb9qg/PqXOJ
            /hsheJw1DWFV/y9tmIRFaz9o6wotBAsoZgbGu3fxEls5Kmvr3swnedzxOzsuL0Gz
            I6pEO/dmX+WXam+1Mo++QFNLv7x7n2g8IKCERugSiQKBgQD9s8pe7flb2Q9ULebd
            C2R375xW8ZQ9zWATRtQFFn/NLj166sejUMHJ0QZZrb+/4xYDVHwjjO+7vQpDsgNx
            DT2UZmG0rN3Wz1h3Lmu9uTd7uDxzBYU9zXBoI3XDnvjlq2y7J5hAHUHa6Pnv76A1
            UJpGsS1hscrcGLVqmTLAe72+4wKBgQC8BsCar5VycbAgd3VinhWTdjD8LGkxX/Is
            wQTdFCMR/6laqqlrg4n/WwOhiM5tntehxUIAwZYeeI/QboRM05B6458YvXXsojdq
            Fk+BRCsGMKmm6q633s9jecRgL/W/mOkl639g8NBOQqHSdPjTtBaI72QJT4AdqQ67
            a/z6nBjHqQKBgFSfd80aS6abTEWj2fG5LxXiUp+djPjgXD+RzH619oMV/WPWlCih
            c0JB+oBHOEJlGJ6bu5yQEhbpA1d5NTSsWfH6BHUjhAt2tedrEH0EHsGhvmgPW1Y2
            BFx4F3vctuDEwUvb9SjNmX3PYC7sGuAttogF6UFA8I1hoIGiAA+8NppJAoGAVj1W
            m9xK1Hn2iX2hFoFhbgg4wYDxIpdaMVK6k1gIGdpEZ/R8znY/liK9kJp56+d+CZG7
            CzO/UeyEMdpuzfn/e43pS+SiMM3aUss23hhRD37EYW2kg2srffm8q010DtPoo97W
            xrTNJggDxs6lzhv8dgQuwuJ25aPDwQzvtFZiOzkCgYEAsQtdeNnYHY3ng4tJITgF
            R3V7HWEJmT5KCZeQXwqqLQj8YgHRtpz1VogSJJjxswJTJ8tUCFLZkjhp0MMp5Kus
            ED9mjAtPv7UxOyG5FO5/vPWp5jKdbs4JYG8BOg6NjVDwcE30fYk2MtqspfdonLX1
            7Q9h/7Se+5+BQcQLZVDib00=
            -----END PRIVATE KEY-----
            """;

    /**
     * Self-signed X.509 certificate for the test IDP (CN=test-saml-idp.example.org), generated
     * alongside {@link #IDP_PRIVATE_KEY}. Also embedded as a DER base64 value inside
     * {@link #IDP_METADATA} so that Spring Security can verify assertion signatures.
     */
    private static final String IDP_CERTIFICATE = """
            -----BEGIN CERTIFICATE-----
            MIIDKTCCAhGgAwIBAgIUaIrvisXjWSSnEFRm2MzUBeMcT/8wDQYJKoZIhvcNAQEL
            BQAwJDEiMCAGA1UEAwwZdGVzdC1zYW1sLWlkcC5leGFtcGxlLm9yZzAeFw0yNjA2
            MDQyMDI1MjZaFw0zNjA2MDEyMDI1MjZaMCQxIjAgBgNVBAMMGXRlc3Qtc2FtbC1p
            ZHAuZXhhbXBsZS5vcmcwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC6
            Vrm0mO2lSCQwk4pdCUPcPwq8bB8x4zHOWWpD6+AQgqXpKlQEqSjrC6NVqXKHip1m
            PA8QE/fOpxhdyk3Y2B7VKcvk/5Xq4EaqVslc+Ghve27RnJeY04KgKYuRFCoTeUxm
            +B/z2IMKr0e8IY96Q0HD+azYpyCeBk0wqi3kgHs6Md/C1W8evNvKOcfY7GzrTBCx
            M7CFuRevod/4vti9IVc+pbRO1/8j+DPYBk//Ta2iw0pBOnKfUtoqXhgVIXgw+cit
            Pa8hIcdZbUrPTMq/66w3LXe4EFChKuikN5KEe88u3OcZdPBlIamhbwti+tx/qTyn
            oqIov/xW2rweOQxo7XjbAgMBAAGjUzBRMB0GA1UdDgQWBBTd9Zb48hd5bMLVsHKs
            n7o1xo42DDAfBgNVHSMEGDAWgBTd9Zb48hd5bMLVsHKsn7o1xo42DDAPBgNVHRMB
            Af8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQBGjL1XCr38xiyCKuxiHaMInhpI
            CucJo+k/vdYBU+H9rJOnHbUFswz8ufPkLOOeMdx7DbU8E8ePP2Vbilb129lfgocL
            2WUYJKoFE6yBs37VTnzqWPu+ynjguib1Aa0kqBGal4ylZkHoDH2FlQ5r38ab5p8i
            pRwkq/5v4+B1MmOSbRV2chFHBoa0oHSxsmpSxoQ2TgBElsr9GeLvr73dxANcT8W0
            rQKI7o+EPOmXcwTJktnfCrwJjN/UsH8t6DZ6eSp/1xKNHio5baEqI9uWDCOdSSu4
            fkyQqd14HeQqOjNDr2lF+h0LVW6zW0YKFytJPq4sk7ZfPuZk6ID6HFzfg7wl
            -----END CERTIFICATE-----
            """;

    /**
     * Minimal SAML IDP metadata containing {@link #IDP_ENTITY_ID} and the DER base64 form of
     * {@link #IDP_CERTIFICATE}. The certificate must match the private key used to sign assertions
     * so that signature verification succeeds once the correct registration is resolved.
     */
    private static final String IDP_METADATA = """
            <?xml version="1.0"?>
            <md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                                 entityID="https://test-saml-idp.example.org/metadata">
                <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
                    <md:KeyDescriptor use="signing">
                        <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
                            <ds:X509Data>
                                <ds:X509Certificate>MIIDKTCCAhGgAwIBAgIUaIrvisXjWSSnEFRm2MzUBeMcT/8wDQYJKoZIhvcNAQELBQAwJDEiMCAGA1UEAwwZdGVzdC1zYW1sLWlkcC5leGFtcGxlLm9yZzAeFw0yNjA2MDQyMDI1MjZaFw0zNjA2MDEyMDI1MjZaMCQxIjAgBgNVBAMMGXRlc3Qtc2FtbC1pZHAuZXhhbXBsZS5vcmcwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC6Vrm0mO2lSCQwk4pdCUPcPwq8bB8x4zHOWWpD6+AQgqXpKlQEqSjrC6NVqXKHip1mPA8QE/fOpxhdyk3Y2B7VKcvk/5Xq4EaqVslc+Ghve27RnJeY04KgKYuRFCoTeUxm+B/z2IMKr0e8IY96Q0HD+azYpyCeBk0wqi3kgHs6Md/C1W8evNvKOcfY7GzrTBCxM7CFuRevod/4vti9IVc+pbRO1/8j+DPYBk//Ta2iw0pBOnKfUtoqXhgVIXgw+citPa8hIcdZbUrPTMq/66w3LXe4EFChKuikN5KEe88u3OcZdPBlIamhbwti+tx/qTynoqIov/xW2rweOQxo7XjbAgMBAAGjUzBRMB0GA1UdDgQWBBTd9Zb48hd5bMLVsHKsn7o1xo42DDAfBgNVHSMEGDAWgBTd9Zb48hd5bMLVsHKsn7o1xo42DDAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQBGjL1XCr38xiyCKuxiHaMInhpICucJo+k/vdYBU+H9rJOnHbUFswz8ufPkLOOeMdx7DbU8E8ePP2Vbilb129lfgocL2WUYJKoFE6yBs37VTnzqWPu+ynjguib1Aa0kqBGal4ylZkHoDH2FlQ5r38ab5p8ipRwkq/5v4+B1MmOSbRV2chFHBoa0oHSxsmpSxoQ2TgBElsr9GeLvr73dxANcT8W0rQKI7o+EPOmXcwTJktnfCrwJjN/UsH8t6DZ6eSp/1xKNHio5baEqI9uWDCOdSSu4fkyQqd14HeQqOjNDr2lF+h0LVW6zW0YKFytJPq4sk7ZfPuZk6ID6HFzfg7wl</ds:X509Certificate>
                            </ds:X509Data>
                        </ds:KeyInfo>
                    </md:KeyDescriptor>
                    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                                           Location="https://test-saml-idp.example.org/sso/saml"/>
                </md:IDPSSODescriptor>
            </md:EntityDescriptor>
            """;

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private JdbcIdentityProviderProvisioning jdbcIdentityProviderProvisioning;

    /**
     * Verifies that a SAML IDP stored in the DB without {@code external_key} set (simulating a
     * URL-type bootstrap IDP whose {@code idpEntityId} was never populated) can still authenticate
     * a user when a SAML response arrives at the legacy SSO alias endpoint.
     *
     * <p>Without the fix in {@code ConfiguratorRelyingPartyRegistrationRepository}, the IDP cannot
     * be matched by issuer because {@code idpEntityId} (sourced from {@code external_key}) is
     * {@code null}. The {@code defaultRepo} then returns a stub registration whose asserting-party
     * entity ID is the SP itself, causing {@code Saml2AuthenticationException[invalid_issuer]} and
     * a redirect to {@code /uaa/saml_error}.
     */
    @Test
    void samlResponse_fromBootstrapIdpWithNullExternalKey_authenticatesSuccessfully() throws Exception {
        // Persist a SAML IDP whose external_key will be null, simulating a URL-type bootstrap IDP
        // stored by BootstrapSamlIdentityProviderData without calling setIdpEntityId().
        SamlIdentityProviderDefinition def = new SamlIdentityProviderDefinition()
                .setMetaDataLocation(IDP_METADATA)
                .setIdpEntityAlias("test-bootstrap-idp")
                .setZoneId(IdentityZone.getUaaZoneId());
        // Intentionally NOT calling def.setIdpEntityId(IDP_ENTITY_ID): this leaves external_key
        // null in the DB, reproducing the state created by URL-type bootstrap IDPs.

        IdentityProvider<SamlIdentityProviderDefinition> idp = new IdentityProvider<SamlIdentityProviderDefinition>()
                .setType(OriginKeys.SAML)
                .setOriginKey("test-bootstrap-idp")
                .setActive(true)
                .setName("Test Bootstrap SAML IDP")
                .setIdentityZoneId(IdentityZone.getUaaZoneId())
                .setConfig(def);
        jdbcIdentityProviderProvisioning.create(idp, IdentityZone.getUaaZoneId());

        // Build a SAML response signed with this IDP's own private key. The matching certificate
        // is embedded in IDP_METADATA, so once the correct registration is resolved the signature
        // verification will pass. Key material is passed as PEM strings to avoid introducing a
        // dependency on spring-security-saml2-service-provider in this module.
        Response samlResponse = responseWithAssertions(IDP_ENTITY_ID, IDP_PRIVATE_KEY, IDP_CERTIFICATE);
        String encodedSamlResponse = serializedResponse(samlResponse);

        // POST to the legacy ACS URL. The fix in ConfiguratorRelyingPartyRegistrationRepository
        // resolves the entity ID from the stored metadata XML when external_key is null, finds the
        // IDP, builds the correct RelyingPartyRegistration, and authentication succeeds.
        MockHttpSession session = (MockHttpSession) mockMvc.perform(
                        post("/uaa/saml/SSO/alias/integration-saml-entity-id")
                                .contextPath("/uaa")
                                .header(HOST, "localhost:8080")
                                .param("SAMLResponse", encodedSamlResponse))
                .andDo(print())
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/uaa/"))
                .andReturn().getRequest().getSession(false);

        // Verify the user is actually authenticated. UAA stores the security context in the
        // zone-namespaced sub-session (ZonePathHttpSession) keyed by context path "/uaa". Reading
        // it requires MockMvcUtils.getZoneSession(), which applies the same prefix that
        // ZoneContextPathSessionRequestWrapper used when storing it — the same pattern used
        // throughout other UAA MockMvc tests (e.g. PasswordChangeEndpointMockMvcTests).
        assertThat(session).isNotNull();
        SecurityContext ctx = (SecurityContext) MockMvcUtils.getZoneSession(session, "/uaa")
                .getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);
        assertThat(ctx).isNotNull();
        assertThat(ctx.getAuthentication().isAuthenticated()).isTrue();
        assertThat(ctx.getAuthentication().getName()).isEqualTo("test@saml.user");
    }
}
