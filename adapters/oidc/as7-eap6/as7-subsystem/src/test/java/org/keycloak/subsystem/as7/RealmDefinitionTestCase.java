/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.keycloak.subsystem.as7;


import org.jboss.dmr.ModelNode;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;


/**
 *
 * @author Stan Silvert ssilvert@redhat.com (C) 2013 Red Hat Inc.
 */
public class RealmDefinitionTestCase {

    private ModelNode model;

    @Before
    public void setUp() {
        model = new ModelNode();
        model.get("realm").set("demo");
        model.get("resource").set("customer-portal");
        model.get("realm-public-key").set("MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAs2njo0TT4UkMcp2Cq+6wcyEVZsyLJ+3bIG5pBPwzik3jUEPG3r7SlPJyx/x6wXUNDvI/x4Q7CKEh6Xm1oLXGStyHQWiFX9VuyTe4aR5VMWC6maezK2YsWVkXY0OGCi96J85qWHRGnIloaCKXr0vfyVsGmrAwnCmRj/aUiQTwZB54lQt0t9wgrT944vvCVoyAiThmIlMNdL87LNwjj5t50kKmPccCl7bjo4IvakDMhpJbvJbz7WWldoBWa7hlU8EmGpUhB3Q2pNqnUQBVKeYu67kfA9uLto6XK/UTpwVcIugveS5v8f/5ZhWM6oGNfam8JiJhD7zP3GYfSTpcYGDKrLnqdE7+bOxzYSXVqTS0dO2J20qr0J2qnykI+y/dpCiZDlhq0AChe142QkxA9zDbSmH89Oy6oJvdBnycSTNv2EzameRakxZyDI3Jc2zrc9e/76i3HPO1RK6ZItieEqg4sa/RUGbO3eaq8rdKUwrxGLuxighO11uZ5KcdOhW9PixFAgMBAAE=");
        model.get("auth-url").set("http://localhost:8080/auth-server/realms/demo/protocol/openid-connect/login");
        model.get("code-url").set("http://localhost:8080/auth-server/realms/demo/protocol/openid-connect/access/codes");
        model.get("expose-token").set(true);
        ModelNode credential = new ModelNode();
        credential.get("password").set("password");
        model.get("credentials").set(credential);
    }

    @Test
    public void testIsTruststoreSetIfRequired() throws Exception {
        model.get("ssl-required").set("none");
        model.get("disable-trust-manager").set(true);
        Assert.assertTrue(SharedAttributeDefinitons.validateTruststoreSetIfRequired(model));

        model.get("ssl-required").set("none");
        model.get("disable-trust-manager").set(false);
        Assert.assertTrue(SharedAttributeDefinitons.validateTruststoreSetIfRequired(model));

        model.get("ssl-required").set("all");
        model.get("disable-trust-manager").set(true);
        Assert.assertTrue(SharedAttributeDefinitons.validateTruststoreSetIfRequired(model));

        model.get("ssl-required").set("all");
        model.get("disable-trust-manager").set(false);
        Assert.assertFalse(SharedAttributeDefinitons.validateTruststoreSetIfRequired(model));

        model.get("ssl-required").set("external");
        model.get("disable-trust-manager").set(false);
        Assert.assertFalse(SharedAttributeDefinitons.validateTruststoreSetIfRequired(model));

        model.get("ssl-required").set("all");
        model.get("disable-trust-manager").set(false);
        model.get("truststore").set("foo");
        Assert.assertFalse(SharedAttributeDefinitons.validateTruststoreSetIfRequired(model));

        model.get("ssl-required").set("all");
        model.get("disable-trust-manager").set(false);
        model.get("truststore").set("foo");
        model.get("truststore-password").set("password");
        Assert.assertTrue(SharedAttributeDefinitons.validateTruststoreSetIfRequired(model));

        model.get("ssl-required").set("external");
        model.get("disable-trust-manager").set(false);
        model.get("truststore").set("foo");
        model.get("truststore-password").set("password");
        Assert.assertTrue(SharedAttributeDefinitons.validateTruststoreSetIfRequired(model));
    }

}
