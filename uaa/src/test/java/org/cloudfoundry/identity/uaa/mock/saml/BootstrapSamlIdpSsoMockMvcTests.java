package org.cloudfoundry.identity.uaa.mock.saml;

import org.cloudfoundry.identity.uaa.DefaultTestContext;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.JdbcIdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.SamlIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
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
 * Regression tests: a SAML IDP bootstrapped from {@code uaa.yml} with a URL-type
 * metadata location cannot be resolved when a SAML response arrives at the legacy alias endpoint.
 *
 * <p><b>Root cause:</b> {@code BootstrapSamlIdentityProviderData.setIdentityProviders} only calls
 * {@code def.setIdpEntityId(...)} for {@code DATA} (inline XML) metadata, never for {@code URL}
 * type. {@link org.cloudfoundry.identity.uaa.provider.JdbcIdentityProviderProvisioning} stores
 * {@code external_key = saml.getIdpEntityId()}, so URL-type bootstrap IDPs end up with
 * {@code external_key = null}.
 *
 * <p>This manifests in two distinct failure modes depending on which ACS URL the IDP uses:
 * <ol>
 *   <li><b>IDP-alias URL</b> ({@code /saml/SSO/alias/{idpAlias}}): The SP-alias {@code endsWith}
 *       check in {@code resolveFromRequest} fails, the resolver returns {@code null}, and Spring
 *       Security throws {@code relying_party_registration_not_found}. Fixed by adding a fallback
 *       in {@link org.cloudfoundry.identity.uaa.provider.saml.UaaRelyingPartyRegistrationResolver}
 *       that uses the URL alias as the registration ID.</li>
 *   <li><b>SP-alias URL</b> ({@code /saml/SSO/alias/{spAlias}}): The issuer is extracted from
 *       the SAML response body and used as the registration ID; because {@code external_key} is
 *       null the entity-ID-based lookup fails, the default-stub registration is returned instead,
 *       and Spring Security throws {@code invalid_issuer}. Fixed by
 *       {@link org.cloudfoundry.identity.uaa.provider.saml.ConfiguratorRelyingPartyRegistrationRepository}
 *       falling back to resolving the entity ID on-the-fly from the stored metadata.</li>
 * </ol>
 */
@DefaultTestContext
class BootstrapSamlIdpSsoMockMvcTests {

    /** Entity ID advertised in {@link #IDP_METADATA}. */
    private static final String IDP_ENTITY_ID = "https://test-saml-idp.example.org/metadata";

    /**
     * Alias (origin key) of the test IDP.
     *
     * <p>The SP entity-ID alias from the default test properties is
     * {@code "integration-saml-entity-id"}. {@code "test-bootstrap-idp"} does <em>not</em> end
     * with that string, so when it appears as the last path segment of the ACS URL,
     * {@code resolveFromRequest}'s {@code endsWith} check fails and — without the fix in
     * {@code UaaRelyingPartyRegistrationResolver} — the resolver returns {@code null}.
     */
    private static final String IDP_ALIAS = "test-bootstrap-idp";

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
     * Self-signed X.509 certificate for the test IDP (CN=test-saml-idp.example.org).
     * Also embedded as DER base64 in {@link #IDP_METADATA}.
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

    @BeforeEach
    void setUp() {
        // Persist a SAML IDP without calling setIdpEntityId(): this leaves external_key null,
        // reproducing exactly the state that BootstrapSamlIdentityProviderData creates for
        // URL-type metadata IDPs configured in uaa.yml.
        SamlIdentityProviderDefinition def = new SamlIdentityProviderDefinition()
                .setMetaDataLocation(IDP_METADATA)
                .setIdpEntityAlias(IDP_ALIAS)
                .setZoneId(IdentityZone.getUaaZoneId());

        IdentityProvider<SamlIdentityProviderDefinition> idp = new IdentityProvider<SamlIdentityProviderDefinition>()
                .setType(OriginKeys.SAML)
                .setOriginKey(IDP_ALIAS)
                .setActive(true)
                .setName("Test Bootstrap SAML IDP")
                .setIdentityZoneId(IdentityZone.getUaaZoneId())
                .setConfig(def);
        jdbcIdentityProviderProvisioning.create(idp, IdentityZone.getUaaZoneId());
    }

    @AfterEach
    void tearDown() {
        jdbcIdentityProviderProvisioning.deleteByOrigin(IDP_ALIAS, IdentityZone.getUaaZoneId());
    }

    /**
     * <b>Failure mode 1 — IDP-alias ACS URL ({@code relying_party_registration_not_found}).</b>
     *
     * <p>When the IDP posts its SAML response to {@code /saml/SSO/alias/test-bootstrap-idp}
     * (the IDP alias), {@code resolveFromRequest} checks whether the URL path ends with the SP
     * entity-ID alias ({@code "integration-saml-entity-id"}). It does not, so without the fix
     * {@code relyingPartyRegistrationId} stays {@code null}, the resolver returns {@code null},
     * and Spring Security logs:
     * <pre>
     *   Saml2AuthenticationException{error=[relying_party_registration_not_found]
     *     No relying party registration found}
     * </pre>
     *
     * <p>The fix in {@link org.cloudfoundry.identity.uaa.provider.saml.UaaRelyingPartyRegistrationResolver}
     * adds a fallback: when the {@code endsWith} check fails but a {@code SAMLResponse} parameter
     * is present, the URL alias is used as the registration ID.
     * {@link org.cloudfoundry.identity.uaa.provider.saml.ConfiguratorRelyingPartyRegistrationRepository}
     * then finds the IDP by origin key and authentication succeeds.
     */
    @Test
    void samlResponse_viaIdpAliasUrl_authenticatesSuccessfully() throws Exception {
        Response samlResponse = responseWithAssertions(IDP_ENTITY_ID, IDP_PRIVATE_KEY, IDP_CERTIFICATE);
        String encodedSamlResponse = serializedResponse(samlResponse);

        MockHttpSession session = (MockHttpSession) mockMvc.perform(
                        post("/uaa/saml/SSO/alias/" + IDP_ALIAS)
                                .contextPath("/uaa")
                                .header(HOST, "localhost:8080")
                                .param("SAMLResponse", encodedSamlResponse))
                .andDo(print())
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/uaa/"))
                .andReturn().getRequest().getSession(false);

        assertAuthenticated(session);
    }

    /**
     * <b>Failure mode 2 — SP-alias ACS URL ({@code invalid_issuer}).</b>
     *
     * <p>When the IDP posts to the canonical SP ACS URL
     * ({@code /saml/SSO/alias/integration-saml-entity-id}), {@code resolveFromRequest} correctly
     * extracts the issuer ({@link #IDP_ENTITY_ID}) from the SAML response body and uses it as
     * the registration ID. The lookup then calls
     * {@code configurator.getIdentityProviderDefinitionsForIssuer}, which queries by
     * {@code external_key}. Because {@code external_key} is {@code null} for URL-type bootstrap
     * IDPs, the query returns nothing. The loop also fails ({@code idpEntityId == null}), the
     * {@code defaultRepo} returns a stub registration whose asserting-party entity ID is the SP
     * itself, and Spring Security logs:
     * <pre>
     *   Saml2AuthenticationException{error=[invalid_issuer]
     *     Invalid issuer [https://test-saml-idp.example.org/metadata] ...}
     * </pre>
     *
     * <p>The fix in
     * {@link org.cloudfoundry.identity.uaa.provider.saml.ConfiguratorRelyingPartyRegistrationRepository}
     * resolves the entity ID on-the-fly from the stored metadata XML when {@code idpEntityId}
     * (sourced from {@code external_key}) is {@code null}, so the correct registration is found
     * and authentication succeeds.
     */
    @Test
    void samlResponse_viaSpAliasUrl_authenticatesSuccessfully() throws Exception {
        Response samlResponse = responseWithAssertions(IDP_ENTITY_ID, IDP_PRIVATE_KEY, IDP_CERTIFICATE);
        String encodedSamlResponse = serializedResponse(samlResponse);

        MockHttpSession session = (MockHttpSession) mockMvc.perform(
                        post("/uaa/saml/SSO/alias/integration-saml-entity-id")
                                .contextPath("/uaa")
                                .header(HOST, "localhost:8080")
                                .param("SAMLResponse", encodedSamlResponse))
                .andDo(print())
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/uaa/"))
                .andReturn().getRequest().getSession(false);

        assertAuthenticated(session);
    }

    /**
     * Asserts the user is authenticated by reading the {@link org.springframework.security.core.context.SecurityContext}
     * from the zone-namespaced sub-session. UAA stores session attributes under a context-path
     * prefix via {@link org.cloudfoundry.identity.uaa.zone.ZonePathHttpSession};
     * {@link MockMvcUtils#getZoneSession} applies the matching prefix — the same pattern used
     * throughout other UAA MockMvc tests (e.g. {@code PasswordChangeEndpointMockMvcTests}).
     */
    private void assertAuthenticated(MockHttpSession session) {
        assertThat(session).isNotNull();
        SecurityContext ctx = (SecurityContext) MockMvcUtils.getZoneSession(session, "/uaa")
                .getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);
        assertThat(ctx).isNotNull();
        assertThat(ctx.getAuthentication().isAuthenticated()).isTrue();
        assertThat(ctx.getAuthentication().getName()).isEqualTo("test@saml.user");
    }
}
