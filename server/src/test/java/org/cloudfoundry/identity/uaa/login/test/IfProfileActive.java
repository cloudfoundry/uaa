
package org.cloudfoundry.identity.uaa.login.test;

@java.lang.annotation.Documented
@java.lang.annotation.Inherited
@java.lang.annotation.Retention(java.lang.annotation.RetentionPolicy.RUNTIME)
@java.lang.annotation.Target({java.lang.annotation.ElementType.TYPE, java.lang.annotation.ElementType.METHOD})
public @interface IfProfileActive {
    java.lang.String value() default "";
}
