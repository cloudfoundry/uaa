package org.cloudfoundry.identity.uaa.ratelimiting.config;

import lombok.RequiredArgsConstructor;
import org.cloudfoundry.identity.uaa.ratelimiting.core.config.exception.YamlRateLimitingConfigException;
import org.cloudfoundry.identity.uaa.ratelimiting.util.StringUtilities;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.Constructor;

@RequiredArgsConstructor
public class BindYaml<T> {
    private final Class<T> targetClass;
    private final String sourcedFrom;

    public static String removeLeadingEmptyDocuments( String yaml ) {
        if ( yaml != null ) {
            yaml = yaml.stripLeading();
            while ( yaml.startsWith( "---" ) ) {
                yaml = yaml.substring( 3 ).stripLeading();
                if ( yaml.startsWith( "{}" ) ) {
                    yaml = yaml.substring( 2 ).stripLeading();
                }
            }
        }
        return yaml;
    }

    public T bind( String yaml ) {
        T target = null;
        if ( yaml != null ) {
            Yaml yamlParser = new Yaml( new Constructor( targetClass ) );
            try {
                target = yamlParser.load( yaml );
            }
            catch ( RuntimeException e ) {
                String message = StringUtilities.toErrorMsg( e );
                String cleaned = message.replace( targetClass.getName(), targetClass.getSimpleName() );
                throw new YamlRateLimitingConfigException( yaml, sourcedFrom + ": " + cleaned );
            }
        }
        return target;
    }
}
