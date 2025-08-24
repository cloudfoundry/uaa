package org.cloudfoundry.identity.uaa.extensions.profiles;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.extension.BeforeTestExecutionCallback;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.platform.commons.util.AnnotationUtils;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import java.util.Arrays;
import java.util.List;

/**
 * Extension to disable tests based on whether a specific profile is active or not.
 * Disabling profiles takes precedence over enabling profiles.
 * Annotations on methods take precedence over annotations on classes.
 *
 * @see DisabledIfProfile
 * @see EnabledIfProfile
 */
public class ProfileSelectionExtension implements BeforeTestExecutionCallback {

    @Override
    public void beforeTestExecution(ExtensionContext context) {
        var activeProfiles = getActiveProfilesOrNull(context);
        if (activeProfiles == null) {
            return;
        }

        // Method, disabled
        var disabledIfProfile = context.getTestMethod()
                .flatMap(method -> AnnotationUtils.findAnnotation(method, DisabledIfProfile.class));
        if (disabledIfProfile.isPresent()) {
            skipIfExcludedProfilePresent(disabledIfProfile.get(), activeProfiles);
            return;
        }

        // Method, enabled
        var enabledIfProfile = context.getTestMethod()
                .flatMap(method -> AnnotationUtils.findAnnotation(method, EnabledIfProfile.class));
        if (enabledIfProfile.isPresent()) {
            skipIfProfileMissing(enabledIfProfile.get(), activeProfiles);
            return;
        }

        // Class, disabled
        var disabledIfProfileClass = context.getTestClass()
                .flatMap(c -> AnnotationUtils.findAnnotation(c, DisabledIfProfile.class, true));
        if (disabledIfProfileClass.isPresent()) {
            skipIfExcludedProfilePresent(disabledIfProfileClass.get(), activeProfiles);
            return;
        }

        // Class, enabled
        var enabledIfProfileClass = context.getTestClass()
                .flatMap(c -> AnnotationUtils.findAnnotation(c, EnabledIfProfile.class, true));
        if (enabledIfProfileClass.isPresent()) {
            skipIfProfileMissing(enabledIfProfileClass.get(), activeProfiles);
            return;
        }
    }

    private List<String> getActiveProfilesOrNull(ExtensionContext context) {
        try {
            var applicationContext = SpringExtension.getApplicationContext(context);
            return Arrays.asList(applicationContext.getEnvironment().getActiveProfiles());
        } catch (IllegalStateException ignore) {
            return null;
        }
    }

    private static void skipIfExcludedProfilePresent(DisabledIfProfile annotation, List<String> activeProfiles) {
        var excludedProfiles = Arrays.asList(annotation.value());
        var hasExcludedProfile = excludedProfiles.stream().anyMatch(activeProfiles::contains);
        var message = "Must NOT have one of the following profiles: %s. Active profiles: %s.".formatted(excludedProfiles, activeProfiles);
        Assumptions.assumeTrue(!hasExcludedProfile, message);
    }

    private static void skipIfProfileMissing(EnabledIfProfile annotation, List<String> activeProfiles) {
        var requiredProfile = Arrays.asList(annotation.value());
        var hasRequiredProfile = requiredProfile.stream().anyMatch(activeProfiles::contains);
        var message = "Must have one of the following profiles: %s. Active profiles: %s.".formatted(requiredProfile, activeProfiles);
        Assumptions.assumeTrue(hasRequiredProfile, message);
    }

}
