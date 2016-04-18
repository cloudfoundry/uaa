package org.cloudfoundry.identity.uaa.test;

import org.springframework.restdocs.request.ParameterDescriptor;
import org.springframework.restdocs.snippet.Attributes;

import static org.springframework.restdocs.snippet.Attributes.key;

public final class SnippetUtils {
    private SnippetUtils() {}

    public static ConstrainableParameter parameterWithName(String name) {
        return new ConstrainableParameter(name);
    }

    public static class ConstrainableParameter extends ParameterDescriptor {
        private ConstrainableParameter(String name) {
            super(name);
        }

        public ParameterDescriptor required() {
            return attributes(key("constraints").value("Required"));
        }

        public ParameterDescriptor optional(Object defaultValue) {
            if(defaultValue == null) {
                defaultValue = "";
            }
            Attributes.Attribute[] attrs = new Attributes.Attribute[] { key("constraints").value("Optional"), key("default").value(defaultValue) };
            return attributes(attrs);
        }
    }
}
