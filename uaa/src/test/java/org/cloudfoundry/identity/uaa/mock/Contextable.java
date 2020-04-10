
package org.cloudfoundry.identity.uaa.mock;

import org.springframework.web.context.support.XmlWebApplicationContext;

public interface Contextable {

    void inject(XmlWebApplicationContext context);

}
