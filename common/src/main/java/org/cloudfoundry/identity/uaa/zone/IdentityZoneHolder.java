package org.cloudfoundry.identity.uaa.zone;

public class IdentityZoneHolder {
    
    private static final ThreadLocal<IdentityZone> THREADLOCAL = new InheritableThreadLocal<IdentityZone>();
    
    public static IdentityZone get() {
        return THREADLOCAL.get();
    }
    
    public static void set(IdentityZone zone) {
        THREADLOCAL.set(zone);
    }
    
    public static void clear() {
        THREADLOCAL.remove();
    }

}
