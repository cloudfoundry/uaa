package org.cloudfoundry.identity.uaa.error;

import org.junit.Test;

import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

public class UaaExceptionTests {

    @Test
    public void testGetErrorCode() {
        UaaException x = new UaaException("msg", new Exception());
        assertEquals("unknown_error", x.getErrorCode());
        x = new UaaException("msg");
        assertEquals("unknown_error", x.getErrorCode());
        x = new UaaException("msg", 500);
        assertEquals("unknown_error", x.getErrorCode());
        x = new UaaException("Error", "description", 500);
        assertEquals("Error", x.getErrorCode());
    }

    @Test
    public void testGetHttpStatus() {
        UaaException x = new UaaException("msg", new Exception());
        assertEquals(400, x.getHttpStatus());
        x = new UaaException("msg");
        assertEquals(400, x.getHttpStatus());
        x = new UaaException("msg", 500);
        assertEquals(500, x.getHttpStatus());
        x = new UaaException("Error", "description", 500);
        assertEquals(500, x.getHttpStatus());

        assertNotNull(x.getSummary());
    }

    @Test
    public void testAddAdditionalInformation() {

    }


    @Test
    public void testValueOf() {
        Map<String, String> params = new HashMap<>();
        params.put("error", "error");
        params.put("error_description", "error_description");
        params.put("status", "403");
        params.put("additional1", "additional1");
        params.put("additional2", "additional2");
        UaaException x = UaaException.valueOf(params);
        assertEquals("error", x.getErrorCode());
        assertEquals("error_description", x.getMessage());
        assertEquals(403, x.getHttpStatus());
        assertEquals("additional1", x.getAdditionalInformation().get("additional1"));
        assertEquals("additional2", x.getAdditionalInformation().get("additional2"));

        params.put("status","test");
        x = UaaException.valueOf(params);
        assertEquals("error", x.getErrorCode());
        assertEquals("error_description", x.getMessage());
        assertEquals(400, x.getHttpStatus());
        assertEquals("additional1", x.getAdditionalInformation().get("additional1"));
        assertEquals("additional2", x.getAdditionalInformation().get("additional2"));
        assertNull(x.getAdditionalInformation().get("additional3"));

        x.addAdditionalInformation("additional3", "additional3");
        assertEquals("additional1", x.getAdditionalInformation().get("additional1"));
        assertEquals("additional2", x.getAdditionalInformation().get("additional2"));
        assertEquals("additional3", x.getAdditionalInformation().get("additional3"));

        assertNotNull(x.getSummary());
        assertTrue(x.getSummary().contains("error=\"error\""));
        assertTrue(x.getSummary().contains("additional3=\"additional3\""));
    }

    @Test
    public void testToString() {
        UaaException x = new UaaException("test");
        assertNotNull(x.toString());
    }


}