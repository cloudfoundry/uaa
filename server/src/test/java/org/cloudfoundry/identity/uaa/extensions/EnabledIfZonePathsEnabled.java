package org.cloudfoundry.identity.uaa.extensions;

import org.junit.jupiter.api.condition.EnabledIfSystemProperty;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Enables the annotated test class or method only when zone paths are enabled
 * ({@code -Dzones.paths.enabled=true}, which is the default).
 * <p>
 * When running with {@code -Dzones.paths.enabled=false}, tests annotated with this
 * annotation are skipped because the {@link org.cloudfoundry.identity.uaa.zone.ZonePathContextRewritingFilter}
 * returns 404 for all {@code /z/{subdomain}/} requests.
 */
@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
@EnabledIfSystemProperty(named = "zones.paths.enabled", matches = "true")
public @interface EnabledIfZonePathsEnabled {
}
