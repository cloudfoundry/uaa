package org.cloudfoundry.identity.uaa;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.ratelimiting.config.AbstractRateLimiterConfigConfiguration;
import org.cloudfoundry.identity.uaa.ratelimiting.config.RateLimitingConfigLoader;
import org.cloudfoundry.identity.uaa.ratelimiting.core.config.exception.RateLimitingConfigException;
import org.cloudfoundry.identity.uaa.ratelimiting.core.http.CredentialIdTypeJWT;
import org.cloudfoundry.identity.uaa.ratelimiting.util.Null;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import static org.cloudfoundry.identity.uaa.ratelimiting.config.RateLimitingConfig.LoaderLogger;

/**
 * Spring based configuration to configure the RateLimitingConfigLoader
 * <p>
 * Note: some messy-bits in the super class
 * <p>
 * Example Source References:
 * file:///workspace/RateLimitingConfigNew.yaml (file local)
 * <a href="https://raw.githubusercontent.com/litesoft/RateLimiterExampleConfig/main/RateLimiters.yaml">https://raw.githubusercontent.com/litesoft/RateLimiterExampleConfig/main/RateLimiters.yaml</a> (url)
 */
@Configuration
public class RateLimiterConfigConfiguration extends AbstractRateLimiterConfigConfiguration {

    @Bean
    public RateLimitingConfigLoader loader() {
        return createLoader( new CredentialIdTypeJWT() );
    }

    protected LoaderLogger loaderLogger() {
        Log logger = LogFactory.getLog( RateLimitingConfigLoader.class );
        logger.info( "RateLimiting initializing (wd: " + System.getProperty( "user.dir" ) );
        return new LoaderLogger() {
            @Override
            public void logFetchingFrom( String source ) {
                logger.info( "RateLimitingConfig fetching from: " + source );
            }

            @Override
            public void logError( RateLimitingConfigException e ) {
                logger.error( messageWith( "", e ), e );
            }

            @Override
            public void logUnhandledError( Exception e ) {
                logger.error( messageWith( " (unhandled)", e ), e );
            }

            @Override
            public void logUpdate( String msg ) {
                logger.info( msg );
            }

            private String messageWith( String typePLus, Exception e ) {
                StringBuilder sb = new StringBuilder();
                sb.append( RateLimiterConfigConfiguration.class.getSimpleName() ).append( typePLus ).append( ": " );
                String eMessage = (e == null) ? "-No Exception-" : Null.defaultOn( e.getMessage(), "-No Message-" );
                String reference = Null.defaultOn( sourceReference, "-No sourceReference-" );
                if ( !eMessage.contains( reference ) ) {
                    sb.append( reference ).append( " | " );
                }
                return sb.append( eMessage ).toString();
            }
        };
    }
}
