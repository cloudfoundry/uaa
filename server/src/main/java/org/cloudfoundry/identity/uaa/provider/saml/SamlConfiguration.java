package org.cloudfoundry.identity.uaa.provider.saml;

import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.ssl.TrustStrategy;
import org.cloudfoundry.identity.uaa.cache.StaleUrlCache;
import org.cloudfoundry.identity.uaa.cache.UrlContentCache;
import org.cloudfoundry.identity.uaa.oauth.provider.CompositeTokenGranter;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2RequestFactory;
import org.cloudfoundry.identity.uaa.oauth.provider.token.AuthorizationServerTokenServices;
import org.cloudfoundry.identity.uaa.oauth.token.Saml2TokenGranter;
import org.cloudfoundry.identity.uaa.security.beans.SecurityContextAccessor;
import org.cloudfoundry.identity.uaa.util.TimeService;
import org.cloudfoundry.identity.uaa.util.TimeServiceImpl;
import org.cloudfoundry.identity.uaa.zone.MultitenantClientServices;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.web.client.RestTemplate;

import javax.net.ssl.SSLContext;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;

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
    private int legacyAssertionConsumerIndex = 0;
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

    @Autowired
    @Bean
    public BootstrapSamlIdentityProviderData bootstrapMetaDataProviders(SamlConfigProps samlConfigProps,
                                                                        final @Qualifier("metaDataProviders") SamlIdentityProviderConfigurator metaDataProviders) {
        BootstrapSamlIdentityProviderData idpData = new BootstrapSamlIdentityProviderData(metaDataProviders);
        idpData.setIdentityProviders(samlConfigProps.getProviders());
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
        return !value.isEmpty() && !value.equals("null");
    }

    @Autowired
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

    @Autowired
    @Bean
    public boolean signSamlMetaData(SamlConfigProps samlConfigProps) {
        return samlConfigProps.getSignMetaData();
    }

    @Bean
    public TimeService timeService() {
        return new TimeServiceImpl();
    }

    @Autowired
    @Bean
    public UrlContentCache urlContentCache(TimeService timeService) {
        return new StaleUrlCache(timeService);
    }

    @Bean
    public RestTemplate trustingRestTemplate() throws NoSuchAlgorithmException, KeyStoreException, KeyManagementException {
        // skip ssl validation
        TrustStrategy acceptingTrustStrategy = (x509Certificates, s) -> true;
        SSLContext sslContext = org.apache.http.ssl.SSLContexts.custom().loadTrustMaterial(null, acceptingTrustStrategy).build();
        SSLConnectionSocketFactory csf = new SSLConnectionSocketFactory(sslContext, new NoopHostnameVerifier());
        CloseableHttpClient httpClient = HttpClients.custom().setSSLSocketFactory(csf).build();
        HttpComponentsClientHttpRequestFactory requestFactory = new HttpComponentsClientHttpRequestFactory();
        requestFactory.setHttpClient(httpClient);

        RestTemplateBuilder restTemplateBuilder = new RestTemplateBuilder();
        return restTemplateBuilder
                .setConnectTimeout(Duration.ofMillis(socketConnectionTimeout))
                .setReadTimeout(Duration.ofMillis(socketReadTimeout))
                .requestFactory(() -> requestFactory)
                .build();
    }

    @Bean
    public RestTemplate nonTrustingRestTemplate() {
        RestTemplateBuilder restTemplateBuilder = new RestTemplateBuilder();
        return restTemplateBuilder
                .setConnectTimeout(Duration.ofMillis(socketConnectionTimeout))
                .setReadTimeout(Duration.ofMillis(socketReadTimeout))
                .build();
    }

    @Autowired
    @Bean
    public FixedHttpMetaDataProvider fixedHttpMetaDataProvider(@Qualifier("trustingRestTemplate") RestTemplate trustingRestTemplate,
                                                               @Qualifier("nonTrustingRestTemplate") RestTemplate nonTrustingRestTemplate,
                                                               UrlContentCache urlContentCache) {
        return new FixedHttpMetaDataProvider(trustingRestTemplate, nonTrustingRestTemplate, urlContentCache);
    }
}

/* --- previous saml- XML configuration ---

    <bean id="samlFilter" class="org.springframework.security.web.FilterChainProxy">
        <security:filter-chain-map request-matcher="ant">
            <security:filter-chain pattern="/saml/login/**" filters="samlEntryPoint"/>
            <security:filter-chain pattern="/saml/logout/**" filters="samlLogoutFilter"/>
            <security:filter-chain pattern="/saml/metadata/**" filters="metadataDisplayFilter"/>
            <security:filter-chain pattern="/saml/SSO/**"
                                   filters="samlSecurityContextPersistenceFilter,samlWebSSOProcessingFilter"/>
            <security:filter-chain pattern="/saml/SingleLogout/**"
                                   filters="samlSecurityContextPersistenceFilter,samlLogoutProcessingFilter"/>
            <security:filter-chain pattern="/saml/discovery/**" filters="samlIDPDiscovery"/>
        </security:filter-chain-map>
    </bean>

    <!-- Logger for SAML messages and events -->
    <bean id="samlLogger" class="org.springframework.security.saml.log.SAMLDefaultLogger"/>

    <bean id="exceptionTranslationFilter" class="org.springframework.security.web.access.ExceptionTranslationFilter">
        <constructor-arg ref="samlEntryPoint"/>
    </bean>

    <bean name="metadataFetchingHttpClientTimer" class="java.util.Timer">
        <constructor-arg value="true"/>
    </bean>

    <!-- Provider of default SAML Context -->
    <bean id="basicContextProvider" class="org.springframework.security.saml.context.SAMLContextProviderImpl"
          primary="true">
        <property name="metadataResolver" ref="nonCachingSPMetadataCredentialsResolver"/>
        <property name="keyManager" ref="zoneAwareSamlSpKeyManager"/>
        <property name="storageFactory">
            <bean class="org.cloudfoundry.identity.uaa.provider.saml.SamlSessionStorageFactory"/>
        </property>
    </bean>

    <bean id="redirectSavingSamlContextProvider"
          class="org.cloudfoundry.identity.uaa.authentication.RedirectSavingSamlContextProvider">
        <constructor-arg name="contextProviderDelegate" ref="basicContextProvider"/>
    </bean>

    <bean id="samlMaxAuthenticationAge" class="java.lang.Integer">
        <constructor-arg value="${login.saml.maxAuthenticationAge:864000}"/>
    </bean>

    <!-- SAML 2.0 Logout Profile -->
    <bean id="basicLogoutProfile" class="org.springframework.security.saml.websso.SingleLogoutProfileImpl">
        <property name="metadata" ref="metadata"/>
        <property name="processor" ref="processor"/>
    </bean>

    <!-- Initialization of OpenSAML library -->
    <bean class="org.springframework.security.saml.SAMLBootstrap"/>

--- end of previous xml configuration --- */