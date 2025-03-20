package org.cloudfoundry.identity.uaa.oauth.provider.config.xml;

import org.cloudfoundry.identity.uaa.oauth.CheckTokenEndpoint;
import org.cloudfoundry.identity.uaa.oauth.UaaAuthorizationEndpoint;
import org.cloudfoundry.identity.uaa.oauth.UaaAuthorizationRequestManager;
import org.cloudfoundry.identity.uaa.oauth.UaaOauth2RequestValidator;
import org.cloudfoundry.identity.uaa.oauth.provider.CompositeTokenGranter;
import org.cloudfoundry.identity.uaa.oauth.provider.approval.DefaultUserApprovalHandler;
import org.cloudfoundry.identity.uaa.oauth.provider.client.ClientCredentialsTokenGranter;
import org.cloudfoundry.identity.uaa.oauth.provider.code.AuthorizationCodeTokenGranter;
import org.cloudfoundry.identity.uaa.oauth.provider.code.InMemoryAuthorizationCodeServices;
import org.cloudfoundry.identity.uaa.oauth.provider.endpoint.FrameworkEndpointHandlerMapping;
import org.cloudfoundry.identity.uaa.oauth.provider.endpoint.WhitelabelApprovalEndpoint;
import org.cloudfoundry.identity.uaa.oauth.provider.implicit.ImplicitTokenGranter;
import org.cloudfoundry.identity.uaa.oauth.provider.password.ResourceOwnerPasswordTokenGranter;
import org.cloudfoundry.identity.uaa.oauth.provider.refresh.RefreshTokenGranter;
import org.cloudfoundry.identity.uaa.oauth.token.UaaTokenEndpoint;
import org.springframework.beans.BeanMetadataElement;
import org.springframework.beans.factory.config.RuntimeBeanReference;
import org.springframework.beans.factory.config.TypedStringValue;
import org.springframework.beans.factory.support.AbstractBeanDefinition;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.support.ManagedList;
import org.springframework.beans.factory.support.ManagedMap;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.security.config.BeanIds;
import org.springframework.util.StringUtils;
import org.springframework.util.xml.DomUtils;
import org.w3c.dom.Element;

import java.util.List;

/**
 * Moved class AuthorizationServerBeanDefinitionParser implementation of from spring-security-oauth2 into UAA
 *
 * The class was taken over from the legacy project with minor refactorings
 * based on sonar.
 *
 * Scope: OAuth2 server setup in xml
 */
public class AuthorizationServerBeanDefinitionParser
        extends ProviderBeanDefinitionParser {

    private static final String DISABLED = "disabled";
    private static final String O_AUTH_2_REQUEST_VALIDATOR = "oAuth2RequestValidator";

    @Override
    protected AbstractBeanDefinition parseEndpointAndReturnFilter(Element element,
            ParserContext parserContext, String tokenServicesRef, String serializerRef) {

        String migrateClientDetailsRef = element.getAttribute("client-details-service-ref");
        //missing token-services-ref
        String migrateUserApprovalHandlerRef = element.getAttribute("user-approval-handler-ref");
        String migrateOAuth2RequestFactoryRef = element.getAttribute("authorization-request-manager-ref");
        String migrateOAuth2RequestValidatorRef = element.getAttribute("request-validator-ref");

        String tokenEndpointUrl = element.getAttribute("token-endpoint-url");
        String checkTokenUrl = element.getAttribute("check-token-endpoint-url");
        String enableCheckToken = element.getAttribute("check-token-enabled");
        String authorizationEndpointUrl = element
                .getAttribute("authorization-endpoint-url");
        String tokenGranterRef = element.getAttribute("token-granter-ref");
        String redirectStrategyRef = element.getAttribute("redirect-strategy-ref");


        String approvalPage = element.getAttribute("user-approval-page");
        String errorPage = element.getAttribute("error-page");
        String approvalParameter = element.getAttribute("approval-parameter-name");
        String redirectResolverRef = element.getAttribute("redirect-resolver-ref");



        // Create a bean definition speculatively for the auth endpoint
        BeanDefinitionBuilder authorizationEndpointBean = BeanDefinitionBuilder
                .genericBeanDefinition(UaaAuthorizationEndpoint.class);

        if (!StringUtils.hasText(migrateClientDetailsRef)) {
            parserContext.getReaderContext()
                    .error("ClientDetailsService must be provided", element);
            return null;
        }

        if (!StringUtils.hasText(migrateOAuth2RequestValidatorRef)) {
            migrateOAuth2RequestValidatorRef = "defaultOAuth2RequestValidator";
            BeanDefinitionBuilder oAuth2RequestValidator = BeanDefinitionBuilder
                    .rootBeanDefinition(UaaOauth2RequestValidator.class);
            parserContext.getRegistry().registerBeanDefinition(migrateOAuth2RequestValidatorRef,
                    oAuth2RequestValidator.getBeanDefinition());
        }
        authorizationEndpointBean.addPropertyReference(O_AUTH_2_REQUEST_VALIDATOR,
                migrateOAuth2RequestValidatorRef);

        if (!StringUtils.hasText(migrateOAuth2RequestFactoryRef)) {
            migrateOAuth2RequestFactoryRef = "oAuth2AuthorizationRequestManager";
            BeanDefinitionBuilder oAuth2RequestManager = BeanDefinitionBuilder
                    .rootBeanDefinition(UaaAuthorizationRequestManager.class);
            oAuth2RequestManager.addConstructorArgReference(migrateClientDetailsRef);
            parserContext.getRegistry().registerBeanDefinition(migrateOAuth2RequestFactoryRef,
                    oAuth2RequestManager.getBeanDefinition());
        }

        ManagedList<BeanMetadataElement> tokenGranters = null;
        if (!StringUtils.hasText(tokenGranterRef)) {
            tokenGranterRef = "oauth2TokenGranter";
            BeanDefinitionBuilder tokenGranterBean = BeanDefinitionBuilder
                    .rootBeanDefinition(CompositeTokenGranter.class);
            parserContext.getRegistry().registerBeanDefinition(tokenGranterRef,
                    tokenGranterBean.getBeanDefinition());
            tokenGranters = new ManagedList<>();
            tokenGranterBean.addConstructorArgValue(tokenGranters);
        }
        authorizationEndpointBean.addPropertyReference("tokenGranter", tokenGranterRef);

        boolean registerAuthorizationEndpoint = false;

        Element authorizationCodeElement = DomUtils.getChildElementByTagName(element,
                "authorization-code");

        if (authorizationCodeElement != null && !"true"
                .equalsIgnoreCase(authorizationCodeElement.getAttribute(DISABLED))) {
            // authorization code grant configuration.
            String authorizationCodeServices = authorizationCodeElement
                    .getAttribute("authorization-code-services-ref");
            String clientTokenCacheRef = authorizationCodeElement
                    .getAttribute("client-token-cache-ref");

            BeanDefinitionBuilder authorizationCodeTokenGranterBean = BeanDefinitionBuilder
                    .rootBeanDefinition(AuthorizationCodeTokenGranter.class);

            if (StringUtils.hasText(tokenServicesRef)) {
                authorizationCodeTokenGranterBean
                        .addConstructorArgReference(tokenServicesRef);
            }

            if (!StringUtils.hasText(authorizationCodeServices)) {
                authorizationCodeServices = "oauth2AuthorizationCodeServices";
                BeanDefinitionBuilder authorizationCodeServicesBean = BeanDefinitionBuilder
                        .rootBeanDefinition(InMemoryAuthorizationCodeServices.class);
                parserContext.getRegistry().registerBeanDefinition(
                        authorizationCodeServices,
                        authorizationCodeServicesBean.getBeanDefinition());
            }

            authorizationEndpointBean.addPropertyReference("authorizationCodeServices",
                    authorizationCodeServices);
            authorizationCodeTokenGranterBean
                    .addConstructorArgReference(authorizationCodeServices);
            authorizationCodeTokenGranterBean
                    .addConstructorArgReference(migrateClientDetailsRef);
            authorizationCodeTokenGranterBean
                    .addConstructorArgReference(migrateOAuth2RequestFactoryRef);

            if (StringUtils.hasText(clientTokenCacheRef)) {
                authorizationEndpointBean.addPropertyReference("clientTokenCache",
                        clientTokenCacheRef);
            }
            if (StringUtils.hasText(migrateOAuth2RequestFactoryRef)) {
                authorizationEndpointBean.addPropertyReference("oAuth2RequestFactory",
                        migrateOAuth2RequestFactoryRef);
            }

            if (tokenGranters != null) {
                tokenGranters.add(authorizationCodeTokenGranterBean.getBeanDefinition());
            }
            // end authorization code provider configuration.
            registerAuthorizationEndpoint = true;
        }

        if (tokenGranters != null) {
            Element refreshTokenElement = DomUtils.getChildElementByTagName(element,
                    "refresh-token");

            if (refreshTokenElement != null && !"true"
                    .equalsIgnoreCase(refreshTokenElement.getAttribute(DISABLED))) {
                BeanDefinitionBuilder refreshTokenGranterBean = BeanDefinitionBuilder
                        .rootBeanDefinition(RefreshTokenGranter.class);
                refreshTokenGranterBean.addConstructorArgReference(tokenServicesRef);
                refreshTokenGranterBean.addConstructorArgReference(migrateClientDetailsRef);
                refreshTokenGranterBean
                        .addConstructorArgReference(migrateOAuth2RequestFactoryRef);
                tokenGranters.add(refreshTokenGranterBean.getBeanDefinition());
            }
            Element implicitElement = DomUtils.getChildElementByTagName(element,
                    "implicit");
            if (implicitElement != null && !"true"
                    .equalsIgnoreCase(implicitElement.getAttribute(DISABLED))) {
                BeanDefinitionBuilder implicitGranterBean = BeanDefinitionBuilder
                        .rootBeanDefinition(ImplicitTokenGranter.class);
                implicitGranterBean.addConstructorArgReference(tokenServicesRef);
                implicitGranterBean.addConstructorArgReference(migrateClientDetailsRef);
                implicitGranterBean.addConstructorArgReference(migrateOAuth2RequestFactoryRef);
                tokenGranters.add(implicitGranterBean.getBeanDefinition());
                registerAuthorizationEndpoint = true;
            }
            Element clientCredentialsElement = DomUtils.getChildElementByTagName(element,
                    "client-credentials");
            if (clientCredentialsElement != null && !"true".equalsIgnoreCase(
                    clientCredentialsElement.getAttribute(DISABLED))) {
                BeanDefinitionBuilder clientCredentialsGranterBean = BeanDefinitionBuilder
                        .rootBeanDefinition(ClientCredentialsTokenGranter.class);
                clientCredentialsGranterBean.addConstructorArgReference(tokenServicesRef);
                clientCredentialsGranterBean.addConstructorArgReference(migrateClientDetailsRef);
                clientCredentialsGranterBean
                        .addConstructorArgReference(migrateOAuth2RequestFactoryRef);
                tokenGranters.add(clientCredentialsGranterBean.getBeanDefinition());
            }
            Element clientPasswordElement = DomUtils.getChildElementByTagName(element,
                    "password");
            if (clientPasswordElement != null && !"true"
                    .equalsIgnoreCase(clientPasswordElement.getAttribute(DISABLED))) {
                BeanDefinitionBuilder clientPasswordTokenGranter = BeanDefinitionBuilder
                        .rootBeanDefinition(ResourceOwnerPasswordTokenGranter.class);
                String migrateAuthenticationManagerRef = clientPasswordElement
                        .getAttribute("authentication-manager-ref");
                if (!StringUtils.hasText(migrateAuthenticationManagerRef)) {
                    migrateAuthenticationManagerRef = BeanIds.AUTHENTICATION_MANAGER;
                }
                clientPasswordTokenGranter
                        .addConstructorArgReference(migrateAuthenticationManagerRef);
                clientPasswordTokenGranter.addConstructorArgReference(tokenServicesRef);
                clientPasswordTokenGranter.addConstructorArgReference(migrateClientDetailsRef);
                clientPasswordTokenGranter
                        .addConstructorArgReference(migrateOAuth2RequestFactoryRef);
                tokenGranters.add(clientPasswordTokenGranter.getBeanDefinition());
            }
            List<Element> customGrantElements = DomUtils
                    .getChildElementsByTagName(element, "custom-grant");
            for (Element customGrantElement : customGrantElements) {
                if (!"true"
                        .equalsIgnoreCase(customGrantElement.getAttribute(DISABLED))) {
                    String customGranterRef = customGrantElement
                            .getAttribute("token-granter-ref");
                    tokenGranters.add(new RuntimeBeanReference(customGranterRef));
                }
            }
        }

        if (registerAuthorizationEndpoint) {

            BeanDefinitionBuilder approvalEndpointBean = BeanDefinitionBuilder
                    .rootBeanDefinition(WhitelabelApprovalEndpoint.class);
            parserContext.getRegistry().registerBeanDefinition("oauth2ApprovalEndpoint",
                    approvalEndpointBean.getBeanDefinition());

            if (StringUtils.hasText(redirectStrategyRef)) {
                authorizationEndpointBean.addPropertyReference("redirectStrategy",
                        redirectStrategyRef);
            }

            if (StringUtils.hasText(migrateUserApprovalHandlerRef)) {
                authorizationEndpointBean.addPropertyReference("userApprovalHandler",
                        migrateUserApprovalHandlerRef);
            }

            authorizationEndpointBean.addPropertyReference("clientDetailsService",
                    migrateClientDetailsRef);
            if (StringUtils.hasText(redirectResolverRef)) {
                authorizationEndpointBean.addPropertyReference("redirectResolver",
                        redirectResolverRef);
            }
            if (StringUtils.hasText(approvalPage)) {
                authorizationEndpointBean.addPropertyValue("userApprovalPage",
                        approvalPage);
            }
            if (StringUtils.hasText(errorPage)) {
                authorizationEndpointBean.addPropertyValue("errorPage", errorPage);
            }

            parserContext.getRegistry().registerBeanDefinition(
                    "uaaAuthorizationEndpoint",
                    authorizationEndpointBean.getBeanDefinition());
        }

        // configure the token endpoint
        BeanDefinitionBuilder tokenEndpointBean = BeanDefinitionBuilder
                .genericBeanDefinition(UaaTokenEndpoint.class);
        tokenEndpointBean.addPropertyReference("clientDetailsService", migrateClientDetailsRef);
        tokenEndpointBean.addPropertyReference("tokenGranter", tokenGranterRef);
        authorizationEndpointBean.addPropertyReference(O_AUTH_2_REQUEST_VALIDATOR,
                migrateOAuth2RequestValidatorRef);
        parserContext.getRegistry().registerBeanDefinition("uaaTokenEndpoint",
                tokenEndpointBean.getBeanDefinition());
        if (StringUtils.hasText(migrateOAuth2RequestFactoryRef)) {
            tokenEndpointBean.addPropertyReference("oAuth2RequestFactory",
                    migrateOAuth2RequestFactoryRef);
        }
        if (StringUtils.hasText(migrateOAuth2RequestValidatorRef)) {
            tokenEndpointBean.addPropertyReference(O_AUTH_2_REQUEST_VALIDATOR,
                    migrateOAuth2RequestValidatorRef);
        }

        // Register a handler mapping that can detect the auth server endpoints
        BeanDefinitionBuilder handlerMappingBean = BeanDefinitionBuilder
                .rootBeanDefinition(FrameworkEndpointHandlerMapping.class);
        ManagedMap<String, TypedStringValue> mappings = new ManagedMap<>();
        if (StringUtils.hasText(tokenEndpointUrl)
                || StringUtils.hasText(authorizationEndpointUrl)) {
            if (StringUtils.hasText(tokenEndpointUrl)) {
                mappings.put("/oauth/token",
                        new TypedStringValue(tokenEndpointUrl, String.class));
            }
            if (StringUtils.hasText(authorizationEndpointUrl)) {
                mappings.put("/oauth/authorize",
                        new TypedStringValue(authorizationEndpointUrl, String.class));
            }
            if (StringUtils.hasText(approvalPage)) {
                mappings.put("/oauth/confirm_access",
                        new TypedStringValue(approvalPage, String.class));
            }
        }
        if (StringUtils.hasText(enableCheckToken) && "true".equals(enableCheckToken)) {
            // configure the check token endpoint
            BeanDefinitionBuilder checkTokenEndpointBean = BeanDefinitionBuilder
                    .rootBeanDefinition(CheckTokenEndpoint.class);
            checkTokenEndpointBean.addConstructorArgReference(tokenServicesRef);
            parserContext.getRegistry().registerBeanDefinition("oauth2CheckTokenEndpoint",
                    checkTokenEndpointBean.getBeanDefinition());

            if (StringUtils.hasText(checkTokenUrl)) {
                mappings.put("/oauth/check_token",
                        new TypedStringValue(checkTokenUrl, String.class));
            }
        }
        if (!mappings.isEmpty()) {
            handlerMappingBean.addPropertyValue("mappings", mappings);
        }

        if (StringUtils.hasText(approvalParameter) && registerAuthorizationEndpoint) {
            if (!StringUtils.hasText(migrateUserApprovalHandlerRef)) {
                BeanDefinitionBuilder userApprovalHandler = BeanDefinitionBuilder
                        .rootBeanDefinition(DefaultUserApprovalHandler.class);
                userApprovalHandler.addPropertyValue("approvalParameter",
                        new TypedStringValue(approvalParameter, String.class));
                authorizationEndpointBean.addPropertyValue("userApprovalHandler",
                        userApprovalHandler.getBeanDefinition());
            }
            handlerMappingBean.addPropertyValue("approvalParameter", approvalParameter);
        }

        // We aren't defining a filter...
        return null;

    }

}
