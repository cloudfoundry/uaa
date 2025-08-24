/*
 * *****************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/

package org.cloudfoundry.identity.uaa.config;

import org.cloudfoundry.identity.uaa.config.YamlBindingTests.OAuthConfiguration.OAuthConfigurationValidator;
import org.junit.jupiter.api.Test;
import org.springframework.beans.BeanWrapperImpl;
import org.springframework.beans.MutablePropertyValues;
import org.springframework.beans.PropertyValue;
import org.springframework.beans.factory.config.YamlPropertiesFactoryBean;
import org.springframework.context.support.StaticMessageSource;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.util.StringUtils;
import org.springframework.validation.BindingResult;
import org.springframework.validation.DataBinder;
import org.springframework.validation.FieldError;
import org.springframework.validation.beanvalidation.LocalValidatorFactoryBean;

import jakarta.validation.Constraint;
import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;
import jakarta.validation.Payload;
import jakarta.validation.constraints.NotNull;
import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.Target;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import static java.lang.annotation.RetentionPolicy.RUNTIME;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * @author Dave Syer
 */
class YamlBindingTests {

    @Test
    void bindString() {
        VanillaTarget target = new VanillaTarget();
        bind(target, "foo: bar");
        assertThat(target.getFoo()).isEqualTo("bar");
    }

    @Test
    void bindNumber() {
        VanillaTarget target = new VanillaTarget();
        bind(target, "foo: bar\nvalue: 123");
        assertThat(target.getValue()).isEqualTo(123);
    }

    @Test
    void simpleValidation() {
        ValidatedTarget target = new ValidatedTarget();
        BindingResult result = bind(target, "");
        assertThat(result.getErrorCount()).isOne();
    }

    @Test
    void requiredFieldsValidation() {
        TargetWithValidatedMap target = new TargetWithValidatedMap();
        BindingResult result = bind(target, "info:\n  foo: bar");
        assertThat(result.getErrorCount()).isEqualTo(2);
        for (FieldError error : result.getFieldErrors()) {
            System.err.println(new StaticMessageSource().getMessage(error, Locale.getDefault()));
        }
    }

    @Test
    void bindNested() {
        TargetWithNestedObject target = new TargetWithNestedObject();
        bind(target, "nested:\n  foo: bar\n  value: 123");
        assertThat(target.getNested().getValue()).isEqualTo(123);
    }

    @Test
    void bindNestedMap() {
        TargetWithNestedMap target = new TargetWithNestedMap();
        bind(target, "nested:\n  foo: bar\n  value: 123");
        assertThat(target.getNested()).containsEntry("value", 123);
    }

    @Test
    void bindNestedMapBracketReferenced() {
        TargetWithNestedMap target = new TargetWithNestedMap();
        bind(target, "nested[foo]: bar\nnested[value]: 123");
        assertThat(target.getNested()).containsEntry("value", 123);
    }

    @SuppressWarnings("unchecked")
    @Test
    void bindDoubleNestedMap() {
        TargetWithNestedMap target = new TargetWithNestedMap();
        bind(target, "nested:\n  foo: bar\n  oof:\n    spam: bucket\n    value: 123");
        assertThat(((Map<String, Object>) target.getNested().get("oof"))).containsEntry("value", 123);
    }

    @Test
    void bindErrorTypeMismatch() {
        VanillaTarget target = new VanillaTarget();
        BindingResult result = bind(target, "foo: bar\nvalue: foo");
        assertThat(result.getErrorCount()).isOne();
    }

    @Test
    void bindErrorNotWritable() {
        VanillaTarget target = new VanillaTarget();
        assertThatThrownBy(() -> bind(target, "foo: bar\nreadonly: bar"))
                .isInstanceOf(Exception.class);
    }

    private BindingResult bind(Object target, String values) {
        YamlPropertiesFactoryBean factory = new YamlPropertiesFactoryBean();
        factory.setResources(new ByteArrayResource[]{new ByteArrayResource(values.getBytes())});
        Map<Object, Object> map = factory.getObject();
        DataBinder binder = new DataBinder(target) {

            @Override
            protected void doBind(MutablePropertyValues mpvs) {
                modifyProperties(mpvs, getTarget());
                super.doBind(mpvs);
            }

            private void modifyProperties(MutablePropertyValues mpvs, Object target) {

                List<PropertyValue> list = mpvs.getPropertyValueList();
                BeanWrapperImpl bw = new BeanWrapperImpl(target);

                for (int i = 0; i < list.size(); i++) {
                    PropertyValue pv = list.get(i);

                    String name = pv.getName();
                    StringBuilder builder = new StringBuilder();

                    for (String key : StringUtils.delimitedListToStringArray(name, ".")) {
                        if (builder.length() != 0) {
                            builder.append(".");
                        }
                        builder.append(key);
                        String base = builder.toString();
                        Class<?> type = bw.getPropertyType(base);
                        if (type != null && Map.class.isAssignableFrom(type)) {
                            String suffix = name.substring(base.length());
                            Map<String, Object> nested = new LinkedHashMap<>();
                            if (bw.getPropertyValue(base) != null) {
                                @SuppressWarnings("unchecked")
                                Map<String, Object> existing = (Map<String, Object>) bw.getPropertyValue(base);
                                nested = existing;
                            } else {
                                bw.setPropertyValue(base, nested);
                            }
                            Map<String, Object> value = nested;
                            String[] tree = StringUtils.delimitedListToStringArray(suffix, ".");
                            for (int j = 1; j < tree.length - 1; j++) {
                                String subtree = tree[j];
                                value.put(subtree, nested);
                                value = nested;
                            }
                            String refName = base + suffix.replaceAll("\\.([a-zA-Z0-9]*)", "[$1]");
                            mpvs.setPropertyValueAt(new PropertyValue(refName, pv.getValue()), i);
                            break;
                        }
                    }

                }

            }

        };
        binder.setIgnoreUnknownFields(false);
        LocalValidatorFactoryBean validatorFactoryBean = new LocalValidatorFactoryBean();
        validatorFactoryBean.afterPropertiesSet();
        binder.setValidator(validatorFactoryBean);
        binder.bind(new MutablePropertyValues(map));
        binder.validate();

        return binder.getBindingResult();
    }

    @Documented
    @Target({ElementType.TYPE})
    @Retention(RUNTIME)
    @Constraint(validatedBy = OAuthConfigurationValidator.class)
    public @interface ValidOAuthConfiguration {
    }

    @ValidOAuthConfiguration
    public static class OAuthConfiguration {

        private Client client;

        private Map<String, OAuthClient> clients;

        public Client getClient() {
            return client;
        }

        public void setClient(Client client) {
            this.client = client;
        }

        public Map<String, OAuthClient> getClients() {
            return clients;
        }

        public void setClients(Map<String, OAuthClient> clients) {
            this.clients = clients;
        }

        public static class Client {

            private List<String> autoapprove;

            public List<String> getAutoapprove() {
                return autoapprove;
            }

            public void setAutoapprove(List<String> autoapprove) {
                this.autoapprove = autoapprove;
            }

        }

        public static class OAuthClient {

            private String id;

            public String getId() {
                return id;
            }

            public void setId(String id) {
                this.id = id;
            }

        }

        public static class OAuthConfigurationValidator implements
                ConstraintValidator<ValidOAuthConfiguration, OAuthConfiguration> {

            @Override
            public void initialize(ValidOAuthConfiguration constraintAnnotation) {
            }

            @Override
            public boolean isValid(OAuthConfiguration value, ConstraintValidatorContext context) {
                boolean valid = true;
                if (value.client != null && value.client.autoapprove != null) {
                    if (value.clients != null) {
                        context.buildConstraintViolationWithTemplate(
                                        "Please use oauth.clients to specifiy autoapprove not client.autoapprove")
                                .addConstraintViolation();
                        valid = false;
                    }
                }
                return valid;
            }

        }

    }

    @Documented
    @Target({ElementType.FIELD})
    @Retention(RUNTIME)
    @Constraint(validatedBy = RequiredKeysValidator.class)
    public @interface RequiredKeys {

        String[] value();

        String message() default "Required keys are not provided for field";

        Class<?>[] groups() default {};

        Class<? extends Payload>[] payload() default {};

    }

    public static class RequiredKeysValidator implements ConstraintValidator<RequiredKeys, Map<String, Object>> {

        private String[] requiredKeys;

        @Override
        public void initialize(RequiredKeys constraintAnnotation) {
            requiredKeys = constraintAnnotation.value();
        }

        @Override
        public boolean isValid(Map<String, Object> value, ConstraintValidatorContext context) {
            boolean valid = true;
            for (String key : requiredKeys) {
                if (!value.containsKey(key)) {
                    context.buildConstraintViolationWithTemplate("Missing key ''" + key + "''")
                            .addConstraintViolation();
                    valid = false;
                }
            }
            return valid;
        }

    }

    public static class TargetWithValidatedMap {

        @RequiredKeys({"foo", "baz"})
        private Map<String, Object> info;

        public Map<String, Object> getInfo() {
            return info;
        }

        public void setInfo(Map<String, Object> nested) {
            this.info = nested;
        }
    }

    public static class TargetWithNestedMap {
        private Map<String, Object> nested;

        public Map<String, Object> getNested() {
            return nested;
        }

        public void setNested(Map<String, Object> nested) {
            this.nested = nested;
        }
    }

    public static class TargetWithNestedObject {
        private VanillaTarget nested;

        public VanillaTarget getNested() {
            return nested;
        }

        public void setNested(VanillaTarget nested) {
            this.nested = nested;
        }
    }

    public static class VanillaTarget {

        private String foo;

        private int value;

        public int getValue() {
            return value;
        }

        public void setValue(int value) {
            this.value = value;
        }

        public String getFoo() {
            return foo;
        }

        public void setFoo(String foo) {
            this.foo = foo;
        }

    }

    public static class ValidatedTarget {

        @NotNull
        private String foo;

        public String getFoo() {
            return foo;
        }

        public void setFoo(String foo) {
            this.foo = foo;
        }

    }
}
