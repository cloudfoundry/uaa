package org.cloudfoundry.identity.uaa.test;

import org.springframework.restdocs.payload.FieldDescriptor;
import org.springframework.restdocs.payload.JsonFieldType;
import org.springframework.restdocs.request.ParameterDescriptor;
import org.springframework.restdocs.snippet.Attributes;

import static org.springframework.restdocs.snippet.Attributes.key;

public final class SnippetUtils {

    public static final Attributes.AttributeBuilder type = key("type");
    public static final Attributes.AttributeBuilder constraints = key("constraints");
    public static final Attributes.AttributeBuilder defaultvalue = key("default");
    public static final String REQUIRED = "Required";
    public static final String OPTIONAL = "Optional";

    private SnippetUtils() {}

    public static ConstrainableParameter parameterWithName(String name) {
        return new ConstrainableParameter(name);
    }

    public static ConstrainableField fieldWithPath(String name) {
        return new ConstrainableField(name);
    }

    public static class ConstrainableParameter extends ParameterDescriptor {
        private ConstrainableParameter(String name) {
            super(name);
        }

        public ConstrainableParameter required() {
            return (ConstrainableParameter)attributes(constraints.value(REQUIRED));
        }

        public ConstrainableParameter optional(Object defaultValue) {
            if(defaultValue == null) {
                defaultValue = "";
            }
            Attributes.Attribute[] attrs = new Attributes.Attribute[] { constraints.value(OPTIONAL), defaultvalue.value(defaultValue) };
            return (ConstrainableParameter)attributes(attrs);
        }

        public ConstrainableParameter type(JsonFieldType fieldType) {
            return (ConstrainableParameter)attributes(type.value(fieldType));
        }

    }


    public static class ConstrainableField extends FieldDescriptor {
        private ConstrainableField(String name) {
            super(name);
        }

        public ConstrainableField required() {
            return  (ConstrainableField)attributes(constraints.value(REQUIRED));
        }

        public ConstrainableField optional(Object defaultValue) {
            super.optional();
            if(defaultValue == null) {
                defaultValue = "";
            }
            Attributes.Attribute[] attrs = new Attributes.Attribute[] {constraints.value(OPTIONAL), defaultvalue.value(defaultValue) };
            return (ConstrainableField)attributes(attrs);
        }
        public ConstrainableField type(JsonFieldType fieldType) {
            return (ConstrainableField)attributes(type.value(fieldType));
        }

    }
}
