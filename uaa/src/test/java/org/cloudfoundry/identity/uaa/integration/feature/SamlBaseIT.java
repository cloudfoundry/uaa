package org.cloudfoundry.identity.uaa.integration.feature;

import com.fasterxml.jackson.core.type.TypeReference;
import org.apache.commons.lang.StringUtils;
import org.cloudfoundry.identity.uaa.ServerRunning;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.integration.util.IntegrationTestUtils;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.SamlIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.saml.idp.SamlServiceProvider;
import org.cloudfoundry.identity.uaa.provider.saml.idp.SamlServiceProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.saml.idp.SamlTestUtils;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneSwitchingFilter;
import org.openqa.selenium.WebDriver;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;
import java.util.List;
import static org.junit.Assert.assertNotNull;

@ContextConfiguration(classes = DefaultIntegrationTestConfig.class)
public class SamlBaseIT {

    @Value("${integration.test.base_url}")
    String baseUrl;

    public static final String IDP_ENTITY_ID = "cloudfoundry-saml-login";

    ServerRunning serverRunning = ServerRunning.isRunning();

    protected final SamlTestUtils samlTestUtils = new SamlTestUtils();

    @Autowired
    WebDriver webDriver;

    protected RestTemplate getIdentityClient() {
        return IntegrationTestUtils.getClientCredentialsTemplate(
                IntegrationTestUtils.getClientCredentialsResource(
                        baseUrl, new String[]{"zones.write", "zones.read", "scim.zones"}, "identity", "identitysecret")
        );
    }



    public static SamlIdentityProviderDefinition createLocalSamlIdpDefinition(String alias, String zoneId) {
        String url;
        if (StringUtils.isNotEmpty(zoneId) && !zoneId.equals("uaa")) {
            url = "http://" + zoneId + ".localhost:8080/uaa/saml/idp/metadata";
        } else {
            url = "http://localhost:8080/uaa/saml/idp/metadata";
        }
        String idpMetaData = getIdpMetadata(url);
        return SamlTestUtils.createLocalSamlIdpDefinition(alias, zoneId, idpMetaData);
    }

    public static String getIdpMetadata(String url) {
        RestTemplate client = new RestTemplate();
        MultiValueMap<String, String> headers = new LinkedMultiValueMap<>();
        headers.add("Accept", "application/samlmetadata+xml");
        HttpEntity<String> getHeaders = new HttpEntity<>(headers);
        ResponseEntity<String> metadataResponse = client.exchange(url, HttpMethod.GET, getHeaders, String.class);

        return metadataResponse.getBody();
    }

    protected IdentityProvider<SamlIdentityProviderDefinition> getSamlIdentityProvider(String spZoneId, String spZoneAdminToken, SamlIdentityProviderDefinition samlIdentityProviderDefinition) {
        IdentityProvider<SamlIdentityProviderDefinition> idp = new IdentityProvider<>();
        idp.setIdentityZoneId(spZoneId);
        idp.setType(OriginKeys.SAML);
        idp.setActive(true);
        idp.setConfig(samlIdentityProviderDefinition);
        idp.setOriginKey(samlIdentityProviderDefinition.getIdpEntityAlias());
        idp.setName("Local SAML IdP for samlidpzone");
        idp = IntegrationTestUtils.createOrUpdateProvider(spZoneAdminToken, baseUrl, idp);
        assertNotNull(idp.getId());
        return idp;
    }

    protected SamlServiceProvider getSamlServiceProvider(String idpZoneId, String idpZoneAdminToken, SamlServiceProviderDefinition samlServiceProviderDefinition, String entityId, String local_saml_sp_for_testzone2, String baseUrl) {
        SamlServiceProvider sp = new SamlServiceProvider();
        sp.setIdentityZoneId(idpZoneId);
        sp.setActive(true);
        sp.setConfig(samlServiceProviderDefinition);
        sp.setEntityId(entityId);
        sp.setName(local_saml_sp_for_testzone2);
        sp = createOrUpdateSamlServiceProvider(idpZoneAdminToken, baseUrl, sp);
        return sp;
    }



    public static SamlServiceProviderDefinition createLocalSamlSpDefinition(String alias, String zoneId) {

        String url;
        if (StringUtils.isNotEmpty(zoneId) && !zoneId.equals("uaa")) {
            url = "http://" + zoneId + ".localhost:8080/uaa/saml/metadata/alias/" + zoneId + "." + alias;
        } else {
            url = "http://localhost:8080/uaa/saml/metadata/alias/" + alias;
        }

        String spMetaData = getIdpMetadata(url);
        SamlServiceProviderDefinition def = new SamlServiceProviderDefinition();
        def.setMetaDataLocation(spMetaData);
        def.setNameID("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress");
        def.setSingleSignOnServiceIndex(0);
        def.setMetadataTrustCheck(false);
        def.setEnableIdpInitiatedSso(true);
        return def;
    }

    public static SamlServiceProvider createOrUpdateSamlServiceProvider(String accessToken, String url,
                                                                        SamlServiceProvider provider) {
        RestTemplate client = new RestTemplate();
        MultiValueMap<String, String> headers = new LinkedMultiValueMap<>();
        headers.add("Accept", MediaType.APPLICATION_JSON_VALUE);
        headers.add("Authorization", "bearer " + accessToken);
        headers.add("Content-Type", MediaType.APPLICATION_JSON_VALUE);
        headers.add(IdentityZoneSwitchingFilter.HEADER, provider.getIdentityZoneId());
        List<SamlServiceProvider> existing = getSamlServiceProviders(accessToken, url, provider.getIdentityZoneId());
        if (existing != null) {
            for (SamlServiceProvider p : existing) {
                if (p.getEntityId().equals(provider.getEntityId())
                        && p.getIdentityZoneId().equals(provider.getIdentityZoneId())) {
                    provider.setId(p.getId());
                    HttpEntity<SamlServiceProvider> putHeaders = new HttpEntity<SamlServiceProvider>(provider, headers);
                    ResponseEntity<String> providerPut = client.exchange(url + "/saml/service-providers/{id}",
                            HttpMethod.PUT, putHeaders, String.class, provider.getId());
                    if (providerPut.getStatusCode() == HttpStatus.OK) {
                        return JsonUtils.readValue(providerPut.getBody(), SamlServiceProvider.class);
                    }
                }
            }
        }

        HttpEntity<SamlServiceProvider> postHeaders = new HttpEntity<SamlServiceProvider>(provider, headers);
        ResponseEntity<String> providerPost = client.exchange(url + "/saml/service-providers/{id}", HttpMethod.POST,
                postHeaders, String.class, provider.getId());
        if (providerPost.getStatusCode() == HttpStatus.CREATED) {
            return JsonUtils.readValue(providerPost.getBody(), SamlServiceProvider.class);
        }
        throw new IllegalStateException(
                "Invalid result code returned, unable to create identity provider:" + providerPost.getStatusCode());
    }

    public static List<SamlServiceProvider> getSamlServiceProviders(String zoneAdminToken, String url, String zoneId) {
        RestTemplate client = new RestTemplate();
        MultiValueMap<String, String> headers = new LinkedMultiValueMap<>();
        headers.add("Accept", MediaType.APPLICATION_JSON_VALUE);
        headers.add("Authorization", "bearer " + zoneAdminToken);
        headers.add("Content-Type", MediaType.APPLICATION_JSON_VALUE);
        headers.add(IdentityZoneSwitchingFilter.HEADER, zoneId);
        HttpEntity<String> getHeaders = new HttpEntity<String>(headers);
        ResponseEntity<String> providerGet = client.exchange(url + "/saml/service-providers", HttpMethod.GET, getHeaders,
                String.class);
        if (providerGet != null && providerGet.getStatusCode() == HttpStatus.OK) {
            return JsonUtils.readValue(providerGet.getBody(), new TypeReference<List<SamlServiceProvider>>() {
                // Do nothing.
            });
        }
        return null;
    }
}
