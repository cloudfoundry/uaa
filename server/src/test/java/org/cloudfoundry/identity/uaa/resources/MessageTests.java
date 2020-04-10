

package org.cloudfoundry.identity.uaa.resources;

import static org.junit.Assert.assertEquals;

import org.cloudfoundry.identity.uaa.resources.ActionResult;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.junit.Test;

/**
 * 
 * @author Dave Syer
 * 
 */
public class MessageTests {

    @Test
    public void testSerialize() {
        assertEquals("{\"status\":\"ok\",\"message\":\"done\"}", JsonUtils.writeValueAsString(new ActionResult("ok", "done")));
    }

    @Test
    public void testDeserialize() {
        String value = "{\"status\":\"ok\",\"message\":\"done\"}";
        ActionResult message = JsonUtils.readValue(value, ActionResult.class);
        assertEquals(new ActionResult("ok", "done"), message);
    }

}
