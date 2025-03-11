package org.cloudfoundry.identity.uaa.scim.beans;

import org.aspectj.lang.annotation.AfterReturning;
import org.aspectj.lang.annotation.AfterThrowing;
import org.aspectj.lang.annotation.Aspect;
import org.cloudfoundry.identity.uaa.account.event.PasswordChangeEventPublisher;
import org.cloudfoundry.identity.uaa.scim.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.event.ScimEventPublisher;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Component;

@Aspect
@Component
public class ScimAopConfig {

    private final PasswordChangeEventPublisher passwordEventPublisher;
    private final ScimEventPublisher scimEventPublisher;

    public ScimAopConfig(
            @Qualifier("passwordEventPublisher") PasswordChangeEventPublisher passwordEventPublisher,
            @Qualifier("scimEventPublisher") ScimEventPublisher scimEventPublisher
    ) {
        this.passwordEventPublisher = passwordEventPublisher;
        this.scimEventPublisher = scimEventPublisher;
    }

    @AfterReturning(pointcut = "execution(* *..ScimUserProvisioning+.changePassword(String, ..)) && args(userId,..) && bean(scimUserProvisioning)")
    public void passwordChange(String userId) {
        passwordEventPublisher.passwordChange(userId);
    }

    @AfterThrowing(pointcut = "execution(* *..PasswordChangeEndpoint+.changePassword(String, ..)) && args(userId,..) && bean(passwordChangeEndpoint)", throwing = "exception")
    public void passwordFailure(String userId, Exception exception) {
        passwordEventPublisher.passwordFailure(userId, exception);
    }

    @AfterReturning(pointcut = "execution(* *..ScimUserProvisioning+.createUser(..)) && bean(scimUserProvisioning)", returning = "user")
    public void userCreated(ScimUser user) {
        scimEventPublisher.userCreated(user);
    }

    @AfterReturning(pointcut = "execution(* *..ScimUserProvisioning+.update(..)) && bean(scimUserProvisioning)", returning = "user")
    public void userModified(ScimUser user) {
        scimEventPublisher.userModified(user);
    }

    @AfterReturning(pointcut = "execution(* *..ScimUserProvisioning+.verifyUser(..)) && bean(scimUserProvisioning)", returning = "user")
    public void userVerified(ScimUser user) {
        scimEventPublisher.userVerified(user);
    }

    @AfterReturning(pointcut = "execution(* *..ScimUserEndpoints+.deleteUser(..)) && bean(scimUserEndpoints)", returning = "user")
    public void userDeleted(ScimUser user) {
        scimEventPublisher.userDeleted(user);
    }

    @AfterReturning(pointcut = "execution(* *..ScimGroupEndpoints+.createGroup(..)) && bean(scimGroupEndpoints)", returning = "group")
    public void groupCreated(ScimGroup group) {
        scimEventPublisher.groupCreated(group);
    }

    @AfterReturning(pointcut = "execution(* *..ScimGroupEndpoints+.updateGroup(..)) && bean(scimGroupEndpoints)", returning = "group")
    public void groupModified(ScimGroup group) {
        scimEventPublisher.groupModified(group);
    }

    @AfterReturning(pointcut = "execution(* *..ScimGroupEndpoints+.deleteGroup(..)) && bean(scimGroupEndpoints)", returning = "group")
    public void groupDeleted(ScimGroup group) {
        scimEventPublisher.groupDeleted(group);
    }

    @AfterReturning(pointcut = "execution(* *..ScimGroupEndpoints+.addZoneManagers(..)) && bean(scimGroupEndpoints)", returning = "group")
    public void zoneManagersAdded(ScimGroup group) {
        scimEventPublisher.groupCreated(group);
    }

    @AfterReturning(pointcut = "execution(* *..ScimGroupEndpoints+.deleteZoneAdmin(..)) && bean(scimGroupEndpoints)", returning = "group")
    public void zoneAdminDeleted(ScimGroup group) {
        scimEventPublisher.groupModified(group);
    }

}
