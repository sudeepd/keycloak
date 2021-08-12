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
        model.get("realm-public-key").set("MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAiQI6Hatcex7EMNTrCkzfqgxh5L2PhII4I8ziZhmS5GWKMRNs4hn1ojmjPWb5TqswffYJdSDyP1iNnJogGdUzzF0r75x4AbHweCi3RnCInhXMXZZqz7nBUZ5DsNatTSU+kvSZ1ysKbGMd0fxHZltC7WsHvem2XIXpo15+vTvxSBbqmOOY77zHmhWhzwz/trR/lzokn0NTjWxkLeAZraCYl37/8zSOccrfbOw1a3OVzXGYBLfYY8rmNP+E1LCRLkAox9CGkQMPsT00xlrV3qalozifjxi0K1SFpmVinp4jYEvn5ByOiyd7ekncW/N1cAR6Bz3QpbXgb7Stm/dHyQqMd4L0ZPrIhQGLwY5M/FjUzuW8BSdOdEfSw2ZE5ONuCccb8njgh/RGM/db8XFn/LRhfjjvp3vSzBPDg7wLDCfhx1LmL9bVq1HDx7mRUk+Y3cAVelmItdTwE3PM9Ccu7nZv/Ayxa8kyr7ozvfGn0BYKwNQZvvXX3/vwU0vqWvaDnRTjAgMBAAE=");
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
