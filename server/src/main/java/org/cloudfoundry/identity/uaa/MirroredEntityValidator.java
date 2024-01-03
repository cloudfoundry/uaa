package org.cloudfoundry.identity.uaa;

import static org.cloudfoundry.identity.uaa.constants.OriginKeys.UAA;
import static org.springframework.util.StringUtils.hasText;

import org.cloudfoundry.identity.uaa.zone.IdentityZoneProvisioning;
import org.cloudfoundry.identity.uaa.zone.ZoneDoesNotExistsException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.lang.NonNull;
import org.springframework.lang.Nullable;
import org.springframework.stereotype.Component;

@Component
public class MirroredEntityValidator {
    private static final Logger LOGGER = LoggerFactory.getLogger(MirroredEntityValidator.class);

    private final IdentityZoneProvisioning identityZoneProvisioning;

    public MirroredEntityValidator(final IdentityZoneProvisioning identityZoneProvisioning) {
        this.identityZoneProvisioning = identityZoneProvisioning;
    }

    public <T extends MirroredEntity> boolean aliasPropertiesAreValid(
            @NonNull final T requestBody,
            @Nullable final T existingEntity
    ) {
        final boolean entityWasAlreadyMirrored = existingEntity != null && hasText(existingEntity.getAliasZid());

        if (entityWasAlreadyMirrored) {
            if (!hasText(existingEntity.getAliasId())) {
                // at this point, we expect both properties to be set -> if not, the entity is in an inconsistent state
                throw new IllegalStateException(String.format(
                        "Both alias ID and alias ZID expected to be set for existing entity of type '%s' with ID '%s' in zone '%s'.",
                        existingEntity.getClass().getSimpleName(),
                        existingEntity.getId(),
                        existingEntity.getZoneId()
                ));
            }

            // both properties must be left unchanged in the operation
            return existingEntity.getAliasId().equals(requestBody.getAliasId())
                    && existingEntity.getAliasZid().equals(requestBody.getAliasId());
        }

        // alias ID must not be set when a new mirroring is to be set up
        if (hasText(requestBody.getAliasId())) {
            return false;
        }

        // check if mirroring is necessary
        if (!hasText(requestBody.getAliasZid())) {
            return true;
        }

        // the referenced zone must exist
        try {
            identityZoneProvisioning.retrieve(requestBody.getAliasZid());
        } catch (final ZoneDoesNotExistsException e) {
            LOGGER.debug("Zone referenced in alias zone ID does not exist.");
            return false;
        }

        // 'identityZoneId' and 'aliasZid' must not be equal
        if (requestBody.getZoneId().equals(requestBody.getAliasZid())) {
            return false;
        }

        // one of the zones must be 'uaa'
        return requestBody.getZoneId().equals(UAA) || requestBody.getAliasZid().equals(UAA);
    }
}
