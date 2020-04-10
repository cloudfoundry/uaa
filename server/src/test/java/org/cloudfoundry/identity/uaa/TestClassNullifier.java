package org.cloudfoundry.identity.uaa;

import org.cloudfoundry.identity.uaa.util.NullifyFields;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.springframework.web.servlet.view.InternalResourceViewResolver;

public class TestClassNullifier {

    private volatile static Class<?> clazz;

    @Before
    public void trackClass() {
        clazz = this.getClass();
    }

    @After
    public void nullifyInstanceFields() throws Exception {
        NullifyFields.nullifyFields(this.getClass(), this, false);
    }

    @AfterClass
    public static void nullifyClassFields() throws Exception {
        NullifyFields.nullifyFields(clazz, null, true);
        clazz = null;
        System.gc();
    }

    public static InternalResourceViewResolver getResolver() {
        InternalResourceViewResolver viewResolver = new InternalResourceViewResolver();
        viewResolver.setPrefix("/WEB-INF/jsp");
        viewResolver.setSuffix(".jsp");
        return viewResolver;
    }
}
