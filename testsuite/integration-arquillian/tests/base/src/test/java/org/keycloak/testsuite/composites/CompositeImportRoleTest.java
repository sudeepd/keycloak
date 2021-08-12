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
package org.keycloak.testsuite.composites;

import org.jboss.arquillian.graphene.page.Page;
import org.junit.Assert;
import org.junit.Test;
import org.keycloak.OAuth2Constants;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.testsuite.pages.LoginPage;
import org.keycloak.testsuite.util.OAuthClient.AccessTokenResponse;

import java.util.List;

import static org.keycloak.testsuite.admin.AbstractAdminTest.loadJson;

/**
 * @author <a href="mailto:sthorger@redhat.com">Stian Thorgersen</a>
 * @author Stan Silvert ssilvert@redhat.com (C) 2016 Red Hat Inc.
 */
public class CompositeImportRoleTest extends AbstractCompositeKeycloakTest {

    @Override
    public void addTestRealms(List<RealmRepresentation> testRealms) {
        RealmRepresentation testRealm = loadJson(getClass().getResourceAsStream("/testcomposite.json"), RealmRepresentation.class);
        testRealm.setId("test");
        testRealm.setPublicKey("MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAiQI6Hatcex7EMNTrCkzfqgxh5L2PhII4I8ziZhmS5GWKMRNs4hn1ojmjPWb5TqswffYJdSDyP1iNnJogGdUzzF0r75x4AbHweCi3RnCInhXMXZZqz7nBUZ5DsNatTSU+kvSZ1ysKbGMd0fxHZltC7WsHvem2XIXpo15+vTvxSBbqmOOY77zHmhWhzwz/trR/lzokn0NTjWxkLeAZraCYl37/8zSOccrfbOw1a3OVzXGYBLfYY8rmNP+E1LCRLkAox9CGkQMPsT00xlrV3qalozifjxi0K1SFpmVinp4jYEvn5ByOiyd7ekncW/N1cAR6Bz3QpbXgb7Stm/dHyQqMd4L0ZPrIhQGLwY5M/FjUzuW8BSdOdEfSw2ZE5ONuCccb8njgh/RGM/db8XFn/LRhfjjvp3vSzBPDg7wLDCfhx1LmL9bVq1HDx7mRUk+Y3cAVelmItdTwE3PM9Ccu7nZv/Ayxa8kyr7ozvfGn0BYKwNQZvvXX3/vwU0vqWvaDnRTjAgMBAAE=");
        testRealm.setPrivateKey("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");

        testRealms.add(testRealm);
    }

    @Page
    protected LoginPage loginPage;

    @Test
    public void testAppCompositeUser() throws Exception {
        oauth.realm("test");
        oauth.clientId("APP_COMPOSITE_APPLICATION");
        oauth.doLogin("APP_COMPOSITE_USER", "password");

        String code = oauth.getCurrentQuery().get(OAuth2Constants.CODE);
        AccessTokenResponse response = oauth.doAccessTokenRequest(code, "password");

        Assert.assertEquals(200, response.getStatusCode());

        Assert.assertEquals("Bearer", response.getTokenType());

        AccessToken token = oauth.verifyToken(response.getAccessToken());

        Assert.assertEquals(getUserId("APP_COMPOSITE_USER"), token.getSubject());

        Assert.assertEquals(1, token.getResourceAccess("APP_ROLE_APPLICATION").getRoles().size());
        Assert.assertEquals(1, token.getRealmAccess().getRoles().size());
        Assert.assertTrue(token.getResourceAccess("APP_ROLE_APPLICATION").isUserInRole("APP_ROLE_1"));
        Assert.assertTrue(token.getRealmAccess().isUserInRole("REALM_ROLE_1"));
    }


    @Test
    public void testRealmAppCompositeUser() throws Exception {
        oauth.realm("test");
        oauth.clientId("APP_ROLE_APPLICATION");
        oauth.doLogin("REALM_APP_COMPOSITE_USER", "password");

        String code = oauth.getCurrentQuery().get(OAuth2Constants.CODE);
        AccessTokenResponse response = oauth.doAccessTokenRequest(code, "password");

        Assert.assertEquals(200, response.getStatusCode());

        Assert.assertEquals("Bearer", response.getTokenType());

        AccessToken token = oauth.verifyToken(response.getAccessToken());

        Assert.assertEquals(getUserId("REALM_APP_COMPOSITE_USER"), token.getSubject());

        Assert.assertEquals(1, token.getResourceAccess("APP_ROLE_APPLICATION").getRoles().size());
        Assert.assertTrue(token.getResourceAccess("APP_ROLE_APPLICATION").isUserInRole("APP_ROLE_1"));
    }



    @Test
    public void testRealmOnlyWithUserCompositeAppComposite() throws Exception {
        oauth.realm("test");
        oauth.clientId("REALM_COMPOSITE_1_APPLICATION");
        oauth.doLogin("REALM_COMPOSITE_1_USER", "password");

        String code = oauth.getCurrentQuery().get(OAuth2Constants.CODE);
        AccessTokenResponse response = oauth.doAccessTokenRequest(code, "password");

        Assert.assertEquals(200, response.getStatusCode());

        Assert.assertEquals("Bearer", response.getTokenType());

        AccessToken token = oauth.verifyToken(response.getAccessToken());

        Assert.assertEquals(getUserId("REALM_COMPOSITE_1_USER"), token.getSubject());

        Assert.assertEquals(2, token.getRealmAccess().getRoles().size());
        Assert.assertTrue(token.getRealmAccess().isUserInRole("REALM_COMPOSITE_1"));
        Assert.assertTrue(token.getRealmAccess().isUserInRole("REALM_ROLE_1"));
    }

    @Test
    public void testRealmOnlyWithUserCompositeAppRole() throws Exception {
        oauth.realm("test");
        oauth.clientId("REALM_ROLE_1_APPLICATION");
        oauth.doLogin("REALM_COMPOSITE_1_USER", "password");

        String code = oauth.getCurrentQuery().get(OAuth2Constants.CODE);
        AccessTokenResponse response = oauth.doAccessTokenRequest(code, "password");

        Assert.assertEquals(200, response.getStatusCode());

        Assert.assertEquals("Bearer", response.getTokenType());

        AccessToken token = oauth.verifyToken(response.getAccessToken());

        Assert.assertEquals(getUserId("REALM_COMPOSITE_1_USER"), token.getSubject());

        Assert.assertEquals(1, token.getRealmAccess().getRoles().size());
        Assert.assertTrue(token.getRealmAccess().isUserInRole("REALM_ROLE_1"));
    }

    @Test
    public void testRealmOnlyWithUserRoleAppComposite() throws Exception {
        oauth.realm("test");
        oauth.clientId("REALM_COMPOSITE_1_APPLICATION");
        oauth.doLogin("REALM_ROLE_1_USER", "password");

        String code = oauth.getCurrentQuery().get(OAuth2Constants.CODE);
        AccessTokenResponse response = oauth.doAccessTokenRequest(code, "password");

        Assert.assertEquals(200, response.getStatusCode());

        Assert.assertEquals("Bearer", response.getTokenType());

        AccessToken token = oauth.verifyToken(response.getAccessToken());

        Assert.assertEquals(getUserId("REALM_ROLE_1_USER"), token.getSubject());

        Assert.assertEquals(1, token.getRealmAccess().getRoles().size());
        Assert.assertTrue(token.getRealmAccess().isUserInRole("REALM_ROLE_1"));
    }

}
