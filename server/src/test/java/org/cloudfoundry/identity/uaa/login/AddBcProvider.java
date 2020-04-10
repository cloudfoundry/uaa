package org.cloudfoundry.identity.uaa.login;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Security;

public class AddBcProvider {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static void noop() {
    }


}
