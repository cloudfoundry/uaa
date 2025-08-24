package org.cloudfoundry.identity.uaa.provider.saml;

import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.cloudfoundry.identity.uaa.cache.StaleUrlCache;
import org.cloudfoundry.identity.uaa.cache.UrlContentCache;
import org.cloudfoundry.identity.uaa.impl.config.RestTemplateConfig;
import org.cloudfoundry.identity.uaa.util.TimeService;
import org.cloudfoundry.identity.uaa.util.TimeServiceImpl;
import org.cloudfoundry.identity.uaa.util.UaaHttpRequestUtils;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.web.client.RestTemplate;

@Slf4j
@EnableConfigurationProperties({SamlConfigProps.class})
@Configuration
@Data
public class SamlConfiguration {

    @Value("${login.entityID:unit-test-sp}")
    private String samlEntityID = "unit-test-sp";
    @Value("${login.idpMetadataURL:null}")
    private String metaDataUrl;
    @Value("${login.idpMetadata:null}")
    private String metaData;
    @Value("${login.idpEntityAlias:null}")
    private String legacyIdpIdentityAlias;
    @SuppressWarnings("java:S6857") // Properly formatted default
    @Value("${login.saml.nameID:'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified'}")
    private String legacyNameId = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified";
    @Value("${login.saml.assertionConsumerIndex:0}")
    private int legacyAssertionConsumerIndex;
    @Value("${login.saml.metadataTrustCheck:true}")
    private boolean legacyMetadataTrustCheck = true;
    @Value("${login.showSamlLoginLink:true}")
    private boolean legacyShowSamlLink = true;

    /**
     * Sets the timeout in milliseconds retrieving an HTTP connection, used when fetching URL metadata
     * Defaults to 10,000ms (10 seconds)
     */
    @Value("${login.saml.socket.connectionManagerTimeout:10000}")
    private int socketConnectionTimeout = 10_000;

    /**
     * Sets the timeout in milliseconds reading data from an HTTP connection, used when fetching URL metadata
     * Defaults to 10,000ms (10 seconds)
     */
    @Value("${login.saml.socket.soTimeout:10000}")
    private int socketReadTimeout = 10_000;

    @Bean
    public String samlEntityID() {
        return samlEntityID;
    }

    @Bean
    public BootstrapSamlIdentityProviderData bootstrapMetaDataProviders(SamlConfigProps samlConfigProps,
            final @Qualifier("metaDataProviders") SamlIdentityProviderConfigurator metaDataProviders) {
        BootstrapSamlIdentityProviderData idpData = new BootstrapSamlIdentityProviderData(metaDataProviders);
        idpData.setIdentityProviders(samlConfigProps.getEnvironmentProviders());
        if (isNotNull(metaData)) {
            idpData.setLegacyIdpMetaData(metaData);
        } else if (isNotNull(metaDataUrl)) {
            idpData.setLegacyIdpMetaData(metaDataUrl);
        }
        idpData.setLegacyIdpIdentityAlias(legacyIdpIdentityAlias);
        idpData.setLegacyNameId(legacyNameId);
        idpData.setLegacyAssertionConsumerIndex(legacyAssertionConsumerIndex);
        idpData.setLegacyMetadataTrustCheck(legacyMetadataTrustCheck);
        idpData.setLegacyShowSamlLink(legacyShowSamlLink);
        return idpData;
    }

    private boolean isNotNull(String value) {
        if (value == null) {
            return false;
        }
        return !value.isEmpty() && !"null".equals(value);
    }

    @Bean
    public SignatureAlgorithm getSignatureAlgorithm(SamlConfigProps samlConfigProps) {
        try {
            return SignatureAlgorithm.valueOf(samlConfigProps.getSignatureAlgorithm());
        } catch (IllegalArgumentException e) {
            // default to INVALID (SHA256), if the signature algorithm is not valid
            SignatureAlgorithm defaultSignatureAlgorithm = SignatureAlgorithm.INVALID;
            log.error("Invalid signature algorithm: '{}', defaulting to {}", samlConfigProps.getSignatureAlgorithm(), defaultSignatureAlgorithm, e);
            return defaultSignatureAlgorithm;
        }
    }

    @Bean
    public boolean signSamlMetaData(SamlConfigProps samlConfigProps) {
        return samlConfigProps.getSignMetaData();
    }

    @Bean
    public TimeService timeService() {
        return new TimeServiceImpl();
    }

    @Bean
    public UrlContentCache urlContentCache(TimeService timeService) {
        return new StaleUrlCache(timeService);
    }

    @Bean
    public FixedHttpMetaDataProvider fixedHttpMetaDataProvider(
            @Qualifier("restTemplateConfig") RestTemplateConfig restTemplateConfig,
            UrlContentCache urlContentCache) {
        // create SAML custom configuration, because of own timeout settings
        ClientHttpRequestFactory trustingRequestFactory = UaaHttpRequestUtils.createRequestFactory(true, socketConnectionTimeout, socketReadTimeout, restTemplateConfig);
        ClientHttpRequestFactory nonTrustingRequestFactory = UaaHttpRequestUtils.createRequestFactory(false, socketConnectionTimeout, socketReadTimeout, restTemplateConfig);
        return new FixedHttpMetaDataProvider(new RestTemplate(trustingRequestFactory), new RestTemplate(nonTrustingRequestFactory), urlContentCache);
    }
}
