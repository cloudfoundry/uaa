package org.cloudfoundry.identity.uaa.test;

import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.springframework.restdocs.headers.HeaderDescriptor;
import org.springframework.restdocs.payload.FieldDescriptor;
import org.springframework.restdocs.payload.JsonFieldType;
import org.springframework.restdocs.request.ParameterDescriptor;
import org.springframework.restdocs.snippet.Attributes;

import java.util.Arrays;

import static org.springframework.restdocs.snippet.Attributes.key;
import static org.springframework.util.StringUtils.hasText;

public final class SnippetUtils {

    public static final Attributes.AttributeBuilder type = key("type");
    public static final Attributes.AttributeBuilder constraints = key("constraints");
    public static final String REQUIRED = "Required";
    public static final String OPTIONAL = "Optional";

    private SnippetUtils() {
    }

    public static ConstrainableHeader headerWithName(String name) {
        return new ConstrainableHeader(name);
    }

    public static ConstrainableParameter parameterWithName(String name) {
        return new ConstrainableParameter(name);
    }

    public static ConstrainableField fieldWithPath(String name) {
        return new ConstrainableField(name);
    }

    public static final class ConstrainableParameter extends ParameterDescriptor {
        private ConstrainableParameter(String name) {
            super(name);
        }

        public ConstrainableParameter required() {
            return (ConstrainableParameter) attributes(constraints.value(REQUIRED));
        }

        public ConstrainableParameter optional(String defaultValue) {
            Attributes.Attribute[] attrs = new Attributes.Attribute[]{key("constraints").value(hasText(defaultValue) ? "Optional (defaults to `" + defaultValue + "`)" : OPTIONAL)};
            return (ConstrainableParameter) attributes(attrs);
        }

        public ConstrainableParameter type(JsonFieldType fieldType) {
            return (ConstrainableParameter) attributes(type.value(fieldType));
        }
    }

    public static final class ConstrainableHeader extends HeaderDescriptor {
        private ConstrainableHeader(String name) {
            super(name);
        }

        public ConstrainableHeader required() {
            return (ConstrainableHeader) attributes(constraints.value(REQUIRED));
        }

        public ConstrainableHeader optional(String defaultValue) {
            super.optional();
            Attributes.Attribute[] attrs = new Attributes.Attribute[]{key("constraints").value(hasText(defaultValue) ? "Optional (defaults to `" + defaultValue + "`)" : OPTIONAL)};
            return (ConstrainableHeader) attributes(attrs);
        }

        public ConstrainableHeader type(JsonFieldType fieldType) {
            return (ConstrainableHeader) attributes(type.value(fieldType));
        }
    }

    public static final class ConstrainableField extends FieldDescriptor {
        private ConstrainableField(String name) {
            super(name);
        }

        public ConstrainableField required() {
            return  (ConstrainableField) attributes(constraints.value(REQUIRED));
        }

        public ConstrainableField optional(Object defaultValue) {
            super.optional();
            String defaultValueText;
            if (defaultValue == null) {
                defaultValueText = "";
            } else {
                defaultValueText = JsonUtils.writeValueAsString(defaultValue);
            }

            Attributes.Attribute[] attrs = new Attributes.Attribute[]{key("constraints").value(hasText(defaultValueText) ? "Optional (defaults to `" + defaultValueText + "`)" : OPTIONAL)};
            return (ConstrainableField) attributes(attrs).optional();
        }

        public ConstrainableField constrained(String constraint) {
            Attributes.Attribute[] attrs = new Attributes.Attribute[]{key("constraints").value(constraint)};
            return (ConstrainableField) attributes(attrs).optional();
        }
    }

    private static class SubField extends FieldDescriptor {
        public SubField(String path, FieldDescriptor subFieldDescriptor) {
            super(path + "." + subFieldDescriptor.getPath());
            type(subFieldDescriptor.getType());
            description(subFieldDescriptor.getDescription());
            if (subFieldDescriptor.isIgnored()) {
                ignored();
            }
            attributes(
                    subFieldDescriptor.getAttributes().entrySet().stream()
                            .map(e -> key(e.getKey()).value(e.getValue()))
                            .toArray(Attributes.Attribute[]::new)
            );
            if (subFieldDescriptor.isOptional()) {
                optional();
            }
        }
    }

    public static FieldDescriptor[] subFields(String path, FieldDescriptor... fieldDescriptors) {
        return Arrays.stream(fieldDescriptors).map(field -> new SubField(path, field)).toArray(FieldDescriptor[]::new);
    }
}
