

package org.cloudfoundry.identity.uaa.test;

import org.springframework.context.support.GenericApplicationContext;
import org.springframework.context.support.GenericXmlApplicationContext;
import org.springframework.test.context.support.GenericXmlContextLoader;

/**
 * A test context loader that also loads a parent context (from the first of the
 * locations provided).
 * 
 * @author Dave Syer
 * 
 */
public class ParentContextLoader extends GenericXmlContextLoader {

    private String parentLocation;

    @Override
    protected String[] modifyLocations(Class<?> clazz, String... locations) {
        String[] result = new String[locations.length - 1];
        System.arraycopy(locations, 1, result, 0, result.length);
        parentLocation = locations[0];
        return result;
    }

    @Override
    protected void customizeContext(GenericApplicationContext context) {
        GenericXmlApplicationContext parent = new GenericXmlApplicationContext();
        parent.setEnvironment(TestProfileEnvironment.getEnvironment());
        parent.load(parentLocation);
        parent.refresh();
        super.customizeContext(context);
        context.setParent(parent);
    }
}
