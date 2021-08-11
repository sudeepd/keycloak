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
import org.junit.Before;
import org.junit.Test;
import org.keycloak.OAuth2Constants;
import org.keycloak.admin.client.resource.ClientResource;
import org.keycloak.admin.client.resource.RoleResource;
import org.keycloak.admin.client.resource.UserResource;
import org.keycloak.common.enums.SslRequired;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;
import org.keycloak.testsuite.Assert;
import org.keycloak.testsuite.admin.ApiUtil;
import org.keycloak.testsuite.pages.LoginPage;
import org.keycloak.testsuite.util.ClientBuilder;
import org.keycloak.testsuite.util.OAuthClient.AccessTokenResponse;
import org.keycloak.testsuite.util.RealmBuilder;
import org.keycloak.testsuite.util.RoleBuilder;
import org.keycloak.testsuite.util.RolesBuilder;
import org.keycloak.testsuite.util.UserBuilder;

import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

/**
 * @author <a href="mailto:sthorger@redhat.com">Stian Thorgersen</a>
 * @author Stan Silvert ssilvert@redhat.com (C) 2016 Red Hat Inc.
 */
public class CompositeRoleTest extends AbstractCompositeKeycloakTest {

    @Override
    public void addTestRealms(List<RealmRepresentation> testRealms) {
        RealmBuilder realmBuilder = RealmBuilder.create()
                .name("test")
                .publicKey("MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAs2njo0TT4UkMcp2Cq+6wcyEVZsyLJ+3bIG5pBPwzik3jUEPG3r7SlPJyx/x6wXUNDvI/x4Q7CKEh6Xm1oLXGStyHQWiFX9VuyTe4aR5VMWC6maezK2YsWVkXY0OGCi96J85qWHRGnIloaCKXr0vfyVsGmrAwnCmRj/aUiQTwZB54lQt0t9wgrT944vvCVoyAiThmIlMNdL87LNwjj5t50kKmPccCl7bjo4IvakDMhpJbvJbz7WWldoBWa7hlU8EmGpUhB3Q2pNqnUQBVKeYu67kfA9uLto6XK/UTpwVcIugveS5v8f/5ZhWM6oGNfam8JiJhD7zP3GYfSTpcYGDKrLnqdE7+bOxzYSXVqTS0dO2J20qr0J2qnykI+y/dpCiZDlhq0AChe142QkxA9zDbSmH89Oy6oJvdBnycSTNv2EzameRakxZyDI3Jc2zrc9e/76i3HPO1RK6ZItieEqg4sa/RUGbO3eaq8rdKUwrxGLuxighO11uZ5KcdOhW9PixFAgMBAAE=")
                .privateKey("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")
                .ssoSessionIdleTimeout(3000)
                .accessTokenLifespan(10000)
                .ssoSessionMaxLifespan(10000)
                .accessCodeLifespanUserAction(1000)
                .accessCodeLifespan(1000)
                .sslRequired(SslRequired.EXTERNAL.toString());


        RoleRepresentation realmRole1 = RoleBuilder.create().name("REALM_ROLE_1").build();
        RoleRepresentation realmComposite1 = RoleBuilder.create()
                .name("REALM_COMPOSITE_1")
                .composite()
                .realmComposite(realmRole1)
                .build();

        RolesBuilder roles = RolesBuilder.create()
                .realmRole(realmRole1)
                .realmRole(RoleBuilder.create().name("REALM_ROLE_2").build())
                .realmRole(RoleBuilder.create().name("REALM_ROLE_3").build())
                .realmRole(realmComposite1);
        realmBuilder.roles(roles);

        UserBuilder realmCompositeUser = UserBuilder.create()
                .username("REALM_COMPOSITE_1_USER")
                .enabled(true)
                .password("password")
                .addRoles(realmComposite1.getName());
        realmBuilder.user(realmCompositeUser);

        UserBuilder realmRole1User = UserBuilder.create()
                .username("REALM_ROLE_1_USER")
                .enabled(true)
                .password("password")
                .addRoles(realmRole1.getName());
        realmBuilder.user(realmRole1User);

        ClientBuilder realmComposite1Application = ClientBuilder.create()
                .clientId("REALM_COMPOSITE_1_APPLICATION")
                .name("REALM_COMPOSITE_1_APPLICATION")
                .fullScopeEnabled(Boolean.FALSE)
                // addScopeMapping(realmComposite1)
                .redirectUris("http://localhost:8180/auth/realms/master/app/*", "https://localhost:8543/auth/realms/master/app/*")
                .baseUrl("http://localhost:8180/auth/realms/master/app/auth")
                .adminUrl("http://localhost:8180/auth/realms/master/app/logout")
                .secret("password");
        realmBuilder.client(realmComposite1Application);

        ClientBuilder realmRole1Application = ClientBuilder.create()
                .clientId("REALM_ROLE_1_APPLICATION")
                .name("REALM_ROLE_1_APPLICATION")
                .fullScopeEnabled(Boolean.FALSE)
                // addScopeMapping(realmRole1)
                .redirectUris("http://localhost:8180/auth/realms/master/app/*", "https://localhost:8543/auth/realms/master/app/*")
                .baseUrl("http://localhost:8180/auth/realms/master/app/auth")
                .adminUrl("http://localhost:8180/auth/realms/master/app/logout")
                .secret("password");
        realmBuilder.client(realmRole1Application);

        ClientBuilder appRoleApplication = ClientBuilder.create()
                .clientId("APP_ROLE_APPLICATION")
                .name("APP_ROLE_APPLICATION")
                .fullScopeEnabled(Boolean.FALSE)
                .redirectUris("http://localhost:8180/auth/realms/master/app/*", "https://localhost:8543/auth/realms/master/app/*")
                .baseUrl("http://localhost:8180/auth/realms/master/app/auth")
                .adminUrl("http://localhost:8180/auth/realms/master/app/logout")
                .defaultRoles("APP_ROLE_1", "APP_ROLE_2")
                .secret("password");
        realmBuilder.client(appRoleApplication);

        UserBuilder realmAppCompositeUser = UserBuilder.create()
                .username("REALM_APP_COMPOSITE_USER")
                .password("password");
        realmBuilder.user(realmAppCompositeUser);

        UserBuilder realmAppRoleUser = UserBuilder.create()
                .username("REALM_APP_ROLE_USER")
                .password("password")
                .addRoles("APP_ROLE_2");
        realmBuilder.user(realmAppRoleUser);

        ClientBuilder appCompositeApplication = ClientBuilder.create()
                .clientId("APP_COMPOSITE_APPLICATION")
                .name("APP_COMPOSITE_APPLICATION")
                .fullScopeEnabled(Boolean.FALSE)
                //.scopeMapping(appRole2)
                .defaultRoles("APP_COMPOSITE_ROLE")
                .redirectUris("http://localhost:8180/auth/realms/master/app/*", "https://localhost:8543/auth/realms/master/app/*")
                .baseUrl("http://localhost:8180/auth/realms/master/app/auth")
                .adminUrl("http://localhost:8180/auth/realms/master/app/logout")
                .secret("password");
        realmBuilder.client(appCompositeApplication);

        UserBuilder appCompositeUser = UserBuilder.create()
                .username("APP_COMPOSITE_USER")
                .password("password")
                .addRoles("REALM_COMPOSITE_1");
        realmBuilder.user(appCompositeUser);

        testRealms.add(realmBuilder.build());
    }

    @Before
    public void before() {
        if (testContext.isInitialized()) {
            return;
        }

        // addScopeMappings
        addRealmLevelScopeMapping("REALM_COMPOSITE_1_APPLICATION", "REALM_COMPOSITE_1");
        addRealmLevelScopeMapping("REALM_ROLE_1_APPLICATION", "REALM_ROLE_1");
        addClientLevelScopeMapping("APP_COMPOSITE_APPLICATION", "APP_ROLE_APPLICATION", "APP_ROLE_2");

        // createRealmAppCompositeRole
        ClientResource appRoleApplication = ApiUtil.findClientByClientId(testRealm(), "APP_ROLE_APPLICATION");
        RoleResource appRole1 = appRoleApplication.roles().get("APP_ROLE_1");

        RoleBuilder realmAppCompositeRole = RoleBuilder.create()
                .name("REALM_APP_COMPOSITE_ROLE");

        testRealm().roles().create(realmAppCompositeRole.build());
        String id = testRealm().roles().get("REALM_APP_COMPOSITE_ROLE").toRepresentation().getId();
        testRealm().rolesById().addComposites(id, Collections.singletonList(appRole1.toRepresentation()));

        // addRealmAppCompositeToUsers
        UserResource userRsc = ApiUtil.findUserByUsernameId(testRealm(), "REALM_APP_COMPOSITE_USER");
        RoleRepresentation realmAppCompositeRolee = testRealm().roles().get("REALM_APP_COMPOSITE_ROLE").toRepresentation();
        userRsc.roles().realmLevel().add(Collections.singletonList(realmAppCompositeRolee));

        // addRealmAppCompositeToUsers2
        userRsc = ApiUtil.findUserByUsernameId(testRealm(), "APP_COMPOSITE_USER");
        userRsc.roles().realmLevel().add(Collections.singletonList(realmAppCompositeRolee));

        ClientResource appCompositeApplication = ApiUtil.findClientByClientId(testRealm(), "APP_COMPOSITE_APPLICATION");
        RoleResource appCompositeRole = appCompositeApplication.roles().get("APP_COMPOSITE_ROLE");

        // addCompositeRolesToAppCompositeRoleInAppCompositeApplication
        List<RoleRepresentation> toAdd = new LinkedList<>();
        toAdd.add(testRealm().roles().get("REALM_ROLE_1").toRepresentation());
        toAdd.add(testRealm().roles().get("REALM_ROLE_2").toRepresentation());
        toAdd.add(testRealm().roles().get("REALM_ROLE_3").toRepresentation());

        ClientResource appRolesApplication = ApiUtil.findClientByClientId(testRealm(), "APP_ROLE_APPLICATION");
        RoleRepresentation appRole1Rep = appRolesApplication.roles().get("APP_ROLE_1").toRepresentation();
        toAdd.add(appRole1Rep);

        appCompositeRole.addComposites(toAdd);

        // Track that we initialized model already
        testContext.setInitialized(true);
    }

    private void addRealmLevelScopeMapping(String clientId, String roleName) {
        ClientResource client = ApiUtil.findClientByClientId(testRealm(), clientId);
        RoleRepresentation role = testRealm().roles().get(roleName).toRepresentation();
        client.getScopeMappings().realmLevel().add(Collections.singletonList(role));
    }

    private void addClientLevelScopeMapping(String targetClientId, String sourceClientId, String roleName) {
        ClientResource targetClient = ApiUtil.findClientByClientId(testRealm(), targetClientId);
        ClientResource sourceClient = ApiUtil.findClientByClientId(testRealm(), sourceClientId);
        RoleRepresentation role = sourceClient.roles().get(roleName).toRepresentation();
        targetClient.getScopeMappings().clientLevel(sourceClient.toRepresentation().getId()).add(Collections.singletonList(role));
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

        AccessTokenResponse refreshResponse = oauth.doRefreshTokenRequest(response.getRefreshToken(), "password");
        Assert.assertEquals(200, refreshResponse.getStatusCode());
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

        AccessTokenResponse refreshResponse = oauth.doRefreshTokenRequest(response.getRefreshToken(), "password");
        Assert.assertEquals(200, refreshResponse.getStatusCode());
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

        AccessTokenResponse refreshResponse = oauth.doRefreshTokenRequest(response.getRefreshToken(), "password");
        Assert.assertEquals(200, refreshResponse.getStatusCode());
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

        AccessTokenResponse refreshResponse = oauth.doRefreshTokenRequest(response.getRefreshToken(), "password");
        Assert.assertEquals(200, refreshResponse.getStatusCode());
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

        AccessTokenResponse refreshResponse = oauth.doRefreshTokenRequest(response.getRefreshToken(), "password");
        Assert.assertEquals(200, refreshResponse.getStatusCode());
    }

    
    // KEYCLOAK-4274
    @Test
    public void testRecursiveComposites() throws Exception {
        // This will create recursive composite mappings between "REALM_COMPOSITE_1" and "REALM_ROLE_1"
        RoleRepresentation realmComposite1 = testRealm().roles().get("REALM_COMPOSITE_1").toRepresentation();
        testRealm().roles().get("REALM_ROLE_1").addComposites(Collections.singletonList(realmComposite1));

        UserResource userResource = ApiUtil.findUserByUsernameId(testRealm(), "REALM_COMPOSITE_1_USER");
        List<RoleRepresentation> realmRoles = userResource.roles().realmLevel().listEffective();
        Assert.assertNames(realmRoles, "REALM_COMPOSITE_1", "REALM_ROLE_1");

        userResource = ApiUtil.findUserByUsernameId(testRealm(), "REALM_ROLE_1_USER");
        realmRoles = userResource.roles().realmLevel().listEffective();
        Assert.assertNames(realmRoles, "REALM_COMPOSITE_1", "REALM_ROLE_1");

        // Revert
        testRealm().roles().get("REALM_ROLE_1").deleteComposites(Collections.singletonList(realmComposite1));
    }

}
