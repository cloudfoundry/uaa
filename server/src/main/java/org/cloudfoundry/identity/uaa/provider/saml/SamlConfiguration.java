package org.cloudfoundry.identity.uaa.provider.saml;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@EnableConfigurationProperties({SamlConfigProps.class})
@Configuration
public class SamlConfiguration {

    @Value("${login.entityID:unit-test-sp}")
    private String samlEntityID;
    @Value("${login.idpMetadataURL:null}")
    private String metaDataUrl;
    @Value("${login.idpEntityAlias:null}")
    private String legacyIdpIdentityAlias;
    @Value("${login.saml.nameID:urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified}")
    private String legacyNameId;
    @Value("${login.saml.assertionConsumerIndex:0}")
    private int legacyAssertionConsumerIndex;
    @Value("${login.saml.metadataTrustCheck:true}")
    private boolean legacyMetadataTrustCheck;
    @Value("${login.showSamlLoginLink:true}")
    private boolean legacyShowSamlLink;

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
        idpData.setLegacyIdpMetaData(metaDataUrl);
        idpData.setLegacyIdpIdentityAlias(legacyIdpIdentityAlias);
        idpData.setLegacyNameId(legacyNameId);
        idpData.setLegacyAssertionConsumerIndex(legacyAssertionConsumerIndex);
        idpData.setLegacyMetadataTrustCheck(legacyMetadataTrustCheck);
        idpData.setLegacyShowSamlLink(legacyShowSamlLink);
        return idpData;
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

   @Value("${login.saml.signatureAlgorithm:SHA12}")
    private String signatureAlgorithm;

    @Bean
    public SamlConfigurationBean defaultSamlConfig(@Value("${login.saml.signatureAlgorithm:SHA12}") String signatureAlgorithm) {
        SamlConfigurationBean samlConfigurationBean = new SamlConfigurationBean();
        SamlConfigurationBean.SignatureAlgorithm signatureAlgorithmEnum = SamlConfigurationBean.SignatureAlgorithm.valueOf(signatureAlgorithm);
        samlConfigurationBean.setSignatureAlgorithm(signatureAlgorithmEnum);
        return samlConfigurationBean;
    }

    <!-- Register authentication manager with SAML provider -->
    <security:authentication-manager id="samlAuthenticationManager">
        <security:authentication-provider ref="samlAuthenticationProvider"/>
    </security:authentication-manager>

    <bean id="samlSecurityContextPersistenceFilter"
          class="org.springframework.security.web.context.SecurityContextPersistenceFilter"/>

    <!-- Logger for SAML messages and events -->
    <bean id="samlLogger" class="org.springframework.security.saml.log.SAMLDefaultLogger"/>

    <!-- Entry point to initialize authentication, default values taken from
        properties file -->
    <bean id="samlEntryPoint" class="org.cloudfoundry.identity.uaa.provider.saml.LoginSamlEntryPoint">
        <property name="defaultProfileOptions">
            <bean class="org.springframework.security.saml.websso.WebSSOProfileOptions">
                <property name="includeScoping" value="false"/>
                <property name="nameID"
                          value="${login.saml.nameID:urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified}"/>
                <property name="assertionConsumerIndex" value="${login.saml.assertionConsumerIndex:0}"/>
                <property name="relayState" value="cloudfoundry-uaa-sp"/>
            </bean>
        </property>
        <property name="providerDefinitionList" ref="metaDataProviders"/>
        <property name="contextProvider" ref="basicContextProvider"/>
        <property name="metadata" ref="metadata"/>
    </bean>

    <bean id="exceptionTranslationFilter" class="org.springframework.security.web.access.ExceptionTranslationFilter">
        <constructor-arg ref="samlEntryPoint"/>
    </bean>

    <!-- IDP Discovery Service -->
    <bean id="samlIDPDiscovery" class="org.cloudfoundry.identity.uaa.provider.saml.LoginSamlDiscovery">
        <property name="contextProvider" ref="basicContextProvider"/>
        <property name="metadata" ref="metadata"/>
    </bean>

    <bean id="samlSPAlias" class="java.lang.String">
        <constructor-arg value="${login.saml.entityIDAlias:${login.entityID:unit-test-sp}}"/>
    </bean>

    <bean id="extendedMetaData" class="org.springframework.security.saml.metadata.ExtendedMetadata">
        <property name="idpDiscoveryEnabled" value="true"/>
        <property name="alias"
                  value="#{T(org.cloudfoundry.identity.uaa.util.UaaStringUtils).getHostIfArgIsURL(@samlSPAlias)}"/>
        <property name="signMetadata" value="${login.saml.signMetaData:true}"/>
    </bean>

    <bean id="zoneAwareMetadataGenerator"
          class="org.cloudfoundry.identity.uaa.provider.saml.ZoneAwareMetadataGenerator">
        <property name="extendedMetadata" ref="extendedMetaData"/>
        <property name="requestSigned" value="${login.saml.signRequest:true}"/>
        <property name="wantAssertionSigned" value="${login.saml.wantAssertionSigned:true}"/>
        <property name="entityBaseURL" value="${login.entityBaseURL:http://localhost:8080/uaa}"/>
        <property name="entityId" ref="samlEntityID"/>
        <property name="keyManager" ref="zoneAwareSamlSpKeyManager"/>
    </bean>


    <!-- Filter automatically generates default SP metadata -->
    <bean id="metadataGeneratorFilter" class="org.springframework.security.saml.metadata.MetadataGeneratorFilter">
        <constructor-arg ref="zoneAwareMetadataGenerator"/>
        <property name="manager" ref="metadata"/>
        <property name="displayFilter" ref="metadataDisplayFilter"/>
    </bean>

    <!-- The filter is waiting for connections on URL suffixed with filterSuffix
        and presents SP metadata there -->

    <bean id="metadataDisplayFilter" class="org.cloudfoundry.identity.uaa.provider.saml.ZoneAwareMetadataDisplayFilter">
        <constructor-arg name="generator" ref="zoneAwareMetadataGenerator"/>
        <property name="manager" ref="metadata"/>
        <property name="contextProvider" ref="basicContextProvider"/>
        <property name="keyManager" ref="zoneAwareSamlSpKeyManager"/>
    </bean>

    <!--<bean id="metadata" class="org.springframework.security.saml.metadata.CachingMetadataManager">-->
    <!--<constructor-arg>-->
    <!--<bean factory-bean="metaDataProviders" factory-method="getSamlIdentityProviders"/>-->
    <!--</constructor-arg>-->
    <!--</bean>-->
    <bean id="metadata" class="org.cloudfoundry.identity.uaa.provider.saml.NonSnarlMetadataManager"
          depends-on="idpBootstrap, metaDataProviders, identityZoneHolderInitializer"
          destroy-method="destroy">
        <constructor-arg name="configurator" ref="metaDataProviders"/>
        <property name="refreshCheckInterval" value="${login.saml.metadataRefreshInterval:0}"/>
        <property name="keyManager" ref="zoneAwareSamlSpKeyManager"/>
        <property name="metadataGenerator" ref="zoneAwareMetadataGenerator"/>
    </bean>

    <bean name="metadataFetchingHttpClientTimer" class="java.util.Timer">
        <constructor-arg value="true"/>
    </bean>

    <bean name="httpClientParams" class="org.apache.commons.httpclient.params.HttpClientParams">
        <property name="connectionManagerTimeout" value="${login.saml.socket.connectionManagerTimeout:10000}"/>
        <property name="soTimeout" value="${login.saml.socket.soTimeout:10000}"/>
    </bean>

    <bean id="samlLoginFailureHandler"
          class="org.cloudfoundry.identity.uaa.provider.saml.LoginSAMLAuthenticationFailureHandler">
        <property name="defaultFailureUrl" value="/saml_error"/>
    </bean>

    <bean id="nonCachingSPMetadataCredentialsResolver"
          class="org.cloudfoundry.identity.uaa.provider.saml.NonCachingMetadataCredentialResolver">
        <constructor-arg name="keyManager" ref="zoneAwareSamlSpKeyManager"/>
        <constructor-arg name="metadataProvider" ref="metadata"/>
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

    <!-- Processing filter for WebSSO profile messages -->
    <bean id="samlWebSSOProcessingFilter" class="org.springframework.security.saml.SAMLProcessingFilter">
        <property name="authenticationManager" ref="samlAuthenticationManager"/>
        <property name="authenticationSuccessHandler" ref="accountSavingAuthenticationSuccessHandler"/>
        <property name="authenticationFailureHandler" ref="samlLoginFailureHandler"/>
        <property name="contextProvider" ref="basicContextProvider"/>
        <property name="SAMLProcessor" ref="processor"/>
        <property name="sessionAuthenticationStrategy" ref="sessionFixationProtectionStrategy"/>
    </bean>

    <bean id="redirectSavingSamlContextProvider"
          class="org.cloudfoundry.identity.uaa.authentication.RedirectSavingSamlContextProvider">
        <constructor-arg name="contextProviderDelegate" ref="basicContextProvider"/>
    </bean>

    <!-- Class loading incoming SAML messages from httpRequest stream -->
    <bean id="processor" class="org.springframework.security.saml.processor.SAMLProcessorImpl">
        <constructor-arg>
            <list>
                <ref bean="redirectBinding"/>
                <ref bean="postBinding"/>
                <ref bean="assertionBinding"/>
                <ref bean="soapBinding"/>
                <ref bean="paosBinding"/>
                <ref bean="samlResponseLoggerBinding"/>
            </list>
        </constructor-arg>
    </bean>

    <bean id="samlMaxAuthenticationAge" class="java.lang.Integer">
        <constructor-arg value="${login.saml.maxAuthenticationAge:864000}"/>
    </bean>

    <!-- SAML 2.0 WebSSO Assertion Consumer -->
    <bean id="webSSOprofileConsumer" class="org.springframework.security.saml.websso.WebSSOProfileConsumerImpl">
        <property name="maxAuthenticationAge" ref="samlMaxAuthenticationAge"/>
        <property name="metadata" ref="metadata"/>
        <property name="processor" ref="processor"/>
    </bean>

    <!-- SAML 2.0 Holder-of-Key WebSSO Assertion Consumer -->
    <bean id="hokWebSSOprofileConsumer" class="org.springframework.security.saml.websso.WebSSOProfileConsumerHoKImpl">
        <property name="maxAuthenticationAge" ref="samlMaxAuthenticationAge"/>
        <property name="metadata" ref="metadata"/>
        <property name="processor" ref="processor"/>
    </bean>

    <!-- SAML 2.0 Web SSO profile -->
    <bean id="webSSOprofile" class="org.cloudfoundry.identity.uaa.provider.saml.SPWebSSOProfileImpl">
        <property name="metadata" ref="metadata"/>
        <property name="processor" ref="processor"/>
    </bean>

    <!-- SAML 2.0 Holder-of-Key Web SSO profile -->
    <bean id="hokWebSSOProfile" class="org.springframework.security.saml.websso.WebSSOProfileConsumerHoKImpl">
        <property name="maxAuthenticationAge" ref="samlMaxAuthenticationAge"/>
        <property name="metadata" ref="metadata"/>
        <property name="processor" ref="processor"/>
    </bean>

    <!-- SAML 2.0 Logout Profile -->
    <bean id="basicLogoutProfile" class="org.springframework.security.saml.websso.SingleLogoutProfileImpl">
        <property name="metadata" ref="metadata"/>
        <property name="processor" ref="processor"/>
    </bean>

    <!-- Bindings, encoders and decoders used for creating and parsing messages -->
    <bean id="postBinding" class="org.springframework.security.saml.processor.HTTPPostBinding">
        <constructor-arg ref="parserPool"/>
        <constructor-arg ref="velocityEngine"/>
    </bean>

    <bean id="assertionBinding" class="org.cloudfoundry.identity.uaa.authentication.SamlAssertionBinding">
        <constructor-arg ref="parserPool"/>
    </bean>

    <bean id="redirectBinding" class="org.springframework.security.saml.processor.HTTPRedirectDeflateBinding">
        <constructor-arg ref="parserPool"/>
    </bean>

    <!-- SAML 2.0 Bearer Grant Type -->
    <bean id="samlTokenGranter" class="org.cloudfoundry.identity.uaa.oauth.token.Saml2TokenGranter">
        <constructor-arg name="tokenServices" ref="tokenServices"/>
        <constructor-arg name="clientDetailsService" ref="jdbcClientDetailsService"/>
        <constructor-arg name="requestFactory" ref="authorizationRequestManager"/>
    </bean>

    <bean id="addSamlTokenGranter"
          class="org.cloudfoundry.identity.uaa.oauth.token.AddTokenGranter">
        <constructor-arg name="userTokenGranter" ref="samlTokenGranter"/>
        <constructor-arg name="compositeTokenGranter" ref="oauth2TokenGranter"/>
    </bean>

    <bean id="soapBinding" class="org.springframework.security.saml.processor.HTTPSOAP11Binding">
        <constructor-arg ref="parserPool"/>
    </bean>

    <bean id="paosBinding" class="org.springframework.security.saml.processor.HTTPPAOS11Binding">
        <constructor-arg ref="parserPool"/>
    </bean>

    <!-- Initialization of OpenSAML library -->
    <bean class="org.springframework.security.saml.SAMLBootstrap"/>

    <!-- Initialization of the velocity engine -->
    <bean id="velocityEngine" class="org.cloudfoundry.identity.uaa.util.velocity.VelocityFactory"
          factory-method="getEngine"/>

    <!-- XML parser pool needed for OpenSAML parsing -->
    <bean id="parserPool" class="org.opensaml.xml.parse.BasicParserPool" scope="singleton"/>


    <bean id="fixedHttpMetaDataProvider" class="org.cloudfoundry.identity.uaa.provider.saml.FixedHttpMetaDataProvider" />

    <beans profile="fileMetadata">
        <bean id="metaDataUrl" class="java.lang.String">
            <constructor-arg value="${login.idpMetadataFile:null}"/>
        </bean>
    </beans>

    <beans profile="configMetadata">
        <bean id="metaDataUrl" class="java.lang.String">
            <constructor-arg value="${login.idpMetadata:null}"/>
        </bean>
    </beans>

--- end of previous xml configuration --- */