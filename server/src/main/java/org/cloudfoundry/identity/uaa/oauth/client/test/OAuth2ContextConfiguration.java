package org.cloudfoundry.identity.uaa.oauth.client.test;



import org.cloudfoundry.identity.uaa.oauth.client.resource.BaseOAuth2ProtectedResourceDetails;
import org.cloudfoundry.identity.uaa.oauth.client.resource.ClientCredentialsResourceDetails;
import org.cloudfoundry.identity.uaa.oauth.client.resource.ImplicitResourceDetails;
import org.cloudfoundry.identity.uaa.oauth.client.resource.OAuth2ProtectedResourceDetails;
import org.cloudfoundry.identity.uaa.oauth.client.resource.ResourceOwnerPasswordResourceDetails;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Moved class implementation of from spring-security-oauth2 into UAA
 *
 * The class was taken over from the legacy project with minor refactorings
 * based on sonar.
 *
 * Scope: Test
 */
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.TYPE, ElementType.METHOD})
public @interface OAuth2ContextConfiguration {

    /**
     * The resource type to use when obtaining an access token. The value provided must be a concrete implementation of
     * {@link OAuth2ProtectedResourceDetails}. An instance will be constructed by the test framework and used to set up
     * an OAuth2 authentication context. The strategy used for instantiating the value provided might vary depending on
     * the consumer. Defaults to the value of {@link resource()} if not provided.
     * 
     * @see Password
     * @see Implicit
     * @see ClientCredentials
     * 
     * @return the resource type to use
     */
    Class<? extends OAuth2ProtectedResourceDetails> value() default OAuth2ProtectedResourceDetails.class;

    /**
     * The resource type to use when obtaining an access token. Defaults to {@link Password}. Intended to be used as an
     * alias for {@link #value()}.
     * 
     * @return the resource type to use
     */
    Class<? extends OAuth2ProtectedResourceDetails> resource() default Password.class;

    static class ResourceHelper {
        public static void initialize(OAuth2ProtectedResourceDetails source, BaseOAuth2ProtectedResourceDetails target) {
            target.setClientId(source.getClientId());
            target.setClientSecret(source.getClientSecret());
            target.setScope(source.getScope());
            target.setId(source.getId());
            target.setAccessTokenUri(source.getAccessTokenUri());
        }
    }

    /**
     * Set up an OAuth2 context for this test using client credentials grant type
     */
    static class ClientCredentials extends ClientCredentialsResourceDetails {
        public ClientCredentials(TestAccounts testAccounts) {
            ClientCredentialsResourceDetails resource = testAccounts.getDefaultClientCredentialsResource();
            ResourceHelper.initialize(resource, this);
        }
    }

    /**
     * Set up an OAuth2 context for this test using resource owner password grant type
     */
    static class Password extends ResourceOwnerPasswordResourceDetails {
        public Password(TestAccounts testAccounts) {
            ResourceOwnerPasswordResourceDetails resource = testAccounts.getDefaultResourceOwnerPasswordResource();
            ResourceHelper.initialize(resource, this);
            setUsername(resource.getUsername());
            setPassword(resource.getPassword());
        }
    }

    /**
     * Set up an OAuth2 context for this test using implicit grant type
     */
    static class Implicit extends ImplicitResourceDetails {
        public Implicit(TestAccounts testAccounts) {
            ImplicitResourceDetails resource = testAccounts.getDefaultImplicitResource();
            ResourceHelper.initialize(resource, this);
            setPreEstablishedRedirectUri(resource.getPreEstablishedRedirectUri());
        }
    }

    /**
     * Flag to indicate whether the access token should be initialized before the test method. If false then the test
     * method should access the protected resource or explicitly grab the access token before trying to use it. Default
     * is true, so test methods can just grab the access token if they need it.
     * 
     * @return flag to indicate whether the access token should be initialized before the test method
     */
    boolean initialize() default true;

}