package org.cloudfoundry.identity.uaa.oauth.token;

import org.cloudfoundry.identity.uaa.oauth.provider.CompositeTokenGranter;
import org.cloudfoundry.identity.uaa.oauth.provider.TokenGranter;

/**
 * This class just adds custom token granters to the
 * {@link CompositeTokenGranter} object that is created by the
 * <pre>&lt;oauth:authorization-server&gt;</pre> element
 */
public class AddTokenGranter {


    private final TokenGranter userTokenGranter;
    private final TokenGranter compositeTokenGranter;

    public AddTokenGranter(TokenGranter userTokenGranter, TokenGranter compositeTokenGranter) {
        this.userTokenGranter = userTokenGranter;
        this.compositeTokenGranter = compositeTokenGranter;
        if (compositeTokenGranter == null) {
            throw new NullPointerException("Expected non null "+CompositeTokenGranter.class.getName());
        } else if (compositeTokenGranter instanceof CompositeTokenGranter) {
            CompositeTokenGranter cg = (CompositeTokenGranter)compositeTokenGranter;
            cg.addTokenGranter(userTokenGranter);
        } else {
            throw new IllegalArgumentException(
                "Expected "+CompositeTokenGranter.class.getName()+
                " but received "+
                compositeTokenGranter.getClass().getName()
            );
        }
    }

}
