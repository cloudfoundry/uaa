package org.cloudfoundry.identity.uaa.zone;

import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Before;
import org.springframework.context.annotation.EnableAspectJAutoProxy;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Component;

@Component("denyAccessToUaaAdvice")
@Aspect
@EnableAspectJAutoProxy(proxyTargetClass = true)
public class DenyAccessToUaaAdvice {

    @Before("execution(* *..IdentityZoneEndpoints+.updateIdentityZone(..)) and args(identityZone,*)")
    public void checkIdentityZone(IdentityZone identityZone) {
        if (identityZone != null && identityZone.isUaa()) {
            throw new AccessDeniedException("Access to UAA is not allowed.");
        }
    }

    @Before("execution(* *..IdentityZoneEndpoints+.updateIdentityZone(..)) and args(*,identityZoneId)" +
            " or execution(* *..IdentityZoneEndpoints+.createClient(..)) and args(identityZoneId,*)" +
            " or execution(* *..IdentityZoneEndpoints+.deleteClient(..)) and args(identityZoneId,*)")
    public void checkIdentityZoneId(String identityZoneId) {
        if (IdentityZone.getUaaZoneId().equals(identityZoneId)) {
            throw new AccessDeniedException("Access to UAA is not allowed.");
        }
    }

}
