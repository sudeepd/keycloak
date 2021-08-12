/*
 * Copyright 2019 Red Hat, Inc. and/or its affiliates
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
package org.keycloak.testsuite.oauth;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.keycloak.models.OAuth2DeviceConfig.DEFAULT_OAUTH2_DEVICE_CODE_LIFESPAN;
import static org.keycloak.models.OAuth2DeviceConfig.DEFAULT_OAUTH2_DEVICE_POLLING_INTERVAL;

import org.jboss.arquillian.graphene.page.Page;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.keycloak.admin.client.resource.ClientResource;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.models.OAuth2DeviceConfig;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.protocol.oidc.OIDCAdvancedConfigWrapper;
import org.keycloak.protocol.oidc.OIDCConfigAttributes;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.keycloak.testsuite.AbstractKeycloakTest;
import org.keycloak.testsuite.Assert;
import org.keycloak.testsuite.AssertEvents;
import org.keycloak.testsuite.admin.ApiUtil;
import org.keycloak.testsuite.pages.ErrorPage;
import org.keycloak.testsuite.pages.OAuth2DeviceVerificationPage;
import org.keycloak.testsuite.pages.OAuthGrantPage;
import org.keycloak.testsuite.util.ClientBuilder;
import org.keycloak.testsuite.util.OAuthClient;
import org.keycloak.testsuite.util.RealmBuilder;
import org.keycloak.testsuite.util.UserBuilder;

import java.util.List;

/**
 * @author <a href="mailto:h2-wada@nri.co.jp">Hiroyuki Wada</a>
 */
public class OAuth2DeviceAuthorizationGrantTest extends AbstractKeycloakTest {

    private static String userId;

    public static final String REALM_NAME = "test";
    public static final String DEVICE_APP = "test-device";
    public static final String DEVICE_APP_PUBLIC = "test-device-public";

    @Rule
    public AssertEvents events = new AssertEvents(this);

    @Page
    protected OAuth2DeviceVerificationPage verificationPage;

    @Page
    protected OAuthGrantPage grantPage;

    @Page
    protected ErrorPage errorPage;

    @Override
    public void addTestRealms(List<RealmRepresentation> testRealms) {
        RealmBuilder realm = RealmBuilder.create().name(REALM_NAME)
                .privateKey("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")
                .publicKey("MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAiQI6Hatcex7EMNTrCkzfqgxh5L2PhII4I8ziZhmS5GWKMRNs4hn1ojmjPWb5TqswffYJdSDyP1iNnJogGdUzzF0r75x4AbHweCi3RnCInhXMXZZqz7nBUZ5DsNatTSU+kvSZ1ysKbGMd0fxHZltC7WsHvem2XIXpo15+vTvxSBbqmOOY77zHmhWhzwz/trR/lzokn0NTjWxkLeAZraCYl37/8zSOccrfbOw1a3OVzXGYBLfYY8rmNP+E1LCRLkAox9CGkQMPsT00xlrV3qalozifjxi0K1SFpmVinp4jYEvn5ByOiyd7ekncW/N1cAR6Bz3QpbXgb7Stm/dHyQqMd4L0ZPrIhQGLwY5M/FjUzuW8BSdOdEfSw2ZE5ONuCccb8njgh/RGM/db8XFn/LRhfjjvp3vSzBPDg7wLDCfhx1LmL9bVq1HDx7mRUk+Y3cAVelmItdTwE3PM9Ccu7nZv/Ayxa8kyr7ozvfGn0BYKwNQZvvXX3/vwU0vqWvaDnRTjAgMBAAE=")
                .testEventListener();


        ClientRepresentation app = ClientBuilder.create()
                .id(KeycloakModelUtils.generateId())
                .clientId("test-device")
                .secret("secret")
                .attribute(OAuth2DeviceConfig.OAUTH2_DEVICE_AUTHORIZATION_GRANT_ENABLED, "true")
                .build();
        realm.client(app);

        ClientRepresentation appPublic = ClientBuilder.create().id(KeycloakModelUtils.generateId()).publicClient()
            .clientId(DEVICE_APP_PUBLIC).attribute(OAuth2DeviceConfig.OAUTH2_DEVICE_AUTHORIZATION_GRANT_ENABLED, "true")
            .build();
        realm.client(appPublic);

        userId = KeycloakModelUtils.generateId();
        UserRepresentation user = UserBuilder.create()
                .id(userId)
                .username("device-login")
                .email("device-login@localhost")
                .password("password")
                .build();
        realm.user(user);

        testRealms.add(realm.build());
    }

    @Before
    public void resetConfig() {
        RealmRepresentation realm = getAdminClient().realm(REALM_NAME).toRepresentation();
        realm.setOAuth2DeviceCodeLifespan(60);
        realm.setOAuth2DevicePollingInterval(5);
        getAdminClient().realm(REALM_NAME).update(realm);
    }

    @Test
    public void testConfidentialClient() throws Exception {
        // Device Authorization Request from device
        oauth.realm(REALM_NAME);
        oauth.clientId(DEVICE_APP);
        OAuthClient.DeviceAuthorizationResponse response = oauth.doDeviceAuthorizationRequest(DEVICE_APP, "secret");

        Assert.assertEquals(200, response.getStatusCode());
        assertNotNull(response.getDeviceCode());
        assertNotNull(response.getUserCode());
        assertNotNull(response.getVerificationUri());
        assertNotNull(response.getVerificationUriComplete());
        Assert.assertEquals(60, response.getExpiresIn());
        Assert.assertEquals(5, response.getInterval());

        // Verify user code from verification page using browser
        openVerificationPage(response.getVerificationUri());
        verificationPage.assertCurrent();
        verificationPage.submit(response.getUserCode());

        loginPage.assertCurrent();

        // Do Login
        oauth.fillLoginForm("device-login", "password");

        // Consent
        grantPage.assertCurrent();
        grantPage.assertGrants(OAuthGrantPage.PROFILE_CONSENT_TEXT, OAuthGrantPage.EMAIL_CONSENT_TEXT, OAuthGrantPage.ROLES_CONSENT_TEXT);
        grantPage.accept();

        verificationPage.assertApprovedPage();

        // Token request from device
        OAuthClient.AccessTokenResponse tokenResponse = oauth.doDeviceTokenRequest(DEVICE_APP, "secret", response.getDeviceCode());

        Assert.assertEquals(200, tokenResponse.getStatusCode());

        String tokenString = tokenResponse.getAccessToken();
        assertNotNull(tokenString);
        AccessToken token = oauth.verifyToken(tokenString);

        assertNotNull(token);
    }

    @Test
    public void testPublicClient() throws Exception {
        // Device Authorization Request from device
        oauth.realm(REALM_NAME);
        oauth.clientId(DEVICE_APP_PUBLIC);
        OAuthClient.DeviceAuthorizationResponse response = oauth.doDeviceAuthorizationRequest(DEVICE_APP_PUBLIC, null);

        Assert.assertEquals(200, response.getStatusCode());
        assertNotNull(response.getDeviceCode());
        assertNotNull(response.getUserCode());
        assertNotNull(response.getVerificationUri());
        assertNotNull(response.getVerificationUriComplete());
        Assert.assertEquals(60, response.getExpiresIn());
        Assert.assertEquals(5, response.getInterval());

        openVerificationPage(response.getVerificationUriComplete());

        // Do Login
        oauth.fillLoginForm("device-login", "password");

        // Consent
        grantPage.accept();

        // Token request from device
        OAuthClient.AccessTokenResponse tokenResponse = oauth.doDeviceTokenRequest(DEVICE_APP_PUBLIC, null, response.getDeviceCode());

        Assert.assertEquals(200, tokenResponse.getStatusCode());

        String tokenString = tokenResponse.getAccessToken();
        assertNotNull(tokenString);
        AccessToken token = oauth.verifyToken(tokenString);

        assertNotNull(token);
    }

    @Test
    public void testNoRefreshToken() throws Exception {
        ClientResource client = ApiUtil.findClientByClientId(adminClient.realm(REALM_NAME), DEVICE_APP);
        ClientRepresentation clientRepresentation = client.toRepresentation();
        clientRepresentation.getAttributes().put(OIDCConfigAttributes.USE_REFRESH_TOKEN, "false");
        client.update(clientRepresentation);
        // Device Authorization Request from device
        oauth.realm(REALM_NAME);
        oauth.clientId(DEVICE_APP);
        OAuthClient.DeviceAuthorizationResponse response = oauth.doDeviceAuthorizationRequest(DEVICE_APP, "secret");

        // Verify user code from verification page using browser
        openVerificationPage(response.getVerificationUri());
        verificationPage.submit(response.getUserCode());

        // Do Login
        oauth.fillLoginForm("device-login", "password");

        // Consent
        grantPage.accept();

        // Token request from device
        OAuthClient.AccessTokenResponse tokenResponse = oauth.doDeviceTokenRequest(DEVICE_APP, "secret",
            response.getDeviceCode());

        Assert.assertEquals(200, tokenResponse.getStatusCode());

        assertNotNull(tokenResponse.getAccessToken());
        assertNull(tokenResponse.getRefreshToken());

        clientRepresentation.getAttributes().put(OIDCConfigAttributes.USE_REFRESH_TOKEN, "true");
        client.update(clientRepresentation);
    }

    @Test
    public void testConsentCancel() throws Exception {
        // Device Authorization Request from device
        oauth.realm(REALM_NAME);
        oauth.clientId(DEVICE_APP);
        OAuthClient.DeviceAuthorizationResponse response = oauth.doDeviceAuthorizationRequest(DEVICE_APP, "secret");

        Assert.assertEquals(200, response.getStatusCode());
        assertNotNull(response.getDeviceCode());
        assertNotNull(response.getUserCode());
        assertNotNull(response.getVerificationUri());
        assertNotNull(response.getVerificationUriComplete());
        Assert.assertEquals(60, response.getExpiresIn());
        Assert.assertEquals(5, response.getInterval());

        openVerificationPage(response.getVerificationUriComplete());
        loginPage.assertCurrent();

        // Do Login
        oauth.fillLoginForm("device-login", "password");

        // Consent
        grantPage.assertCurrent();
        grantPage.assertGrants(OAuthGrantPage.PROFILE_CONSENT_TEXT, OAuthGrantPage.EMAIL_CONSENT_TEXT, OAuthGrantPage.ROLES_CONSENT_TEXT);
        grantPage.cancel();

        verificationPage.assertDeniedPage();
 
        OAuthClient.AccessTokenResponse tokenResponse = oauth.doDeviceTokenRequest(DEVICE_APP, "secret", response.getDeviceCode());

        Assert.assertEquals(400, tokenResponse.getStatusCode());
        Assert.assertEquals("access_denied", tokenResponse.getError());
    }

    @Test
    public void testInvalidUserCode() throws Exception {
        // Device Authorization Request from device
        oauth.realm(REALM_NAME);
        oauth.clientId(DEVICE_APP);
        OAuthClient.DeviceAuthorizationResponse response = oauth.doDeviceAuthorizationRequest(DEVICE_APP, "secret");

        Assert.assertEquals(200, response.getStatusCode());
        assertNotNull(response.getDeviceCode());
        assertNotNull(response.getUserCode());
        assertNotNull(response.getVerificationUri());
        assertNotNull(response.getVerificationUriComplete());
        Assert.assertEquals(60, response.getExpiresIn());
        Assert.assertEquals(5, response.getInterval());

        openVerificationPage(response.getVerificationUri());
        verificationPage.submit("x");

        verificationPage.assertInvalidUserCodePage();
    }

    @Test
    public void testExpiredUserCodeTest() throws Exception {
        // Device Authorization Request from device
        oauth.realm(REALM_NAME);
        oauth.clientId(DEVICE_APP);
        OAuthClient.DeviceAuthorizationResponse response = oauth.doDeviceAuthorizationRequest(DEVICE_APP, "secret");

        Assert.assertEquals(200, response.getStatusCode());
        assertNotNull(response.getDeviceCode());
        assertNotNull(response.getUserCode());
        assertNotNull(response.getVerificationUri());
        assertNotNull(response.getVerificationUriComplete());
        Assert.assertEquals(60, response.getExpiresIn());
        Assert.assertEquals(5, response.getInterval());

        try {
            setTimeOffset(610);
            openVerificationPage(response.getVerificationUriComplete());
        } finally {
            resetTimeOffset();
        }

        verificationPage.assertInvalidUserCodePage();
    }

    @Test
    public void testInvalidDeviceCode() throws Exception {
        // Device Authorization Request from device
        oauth.realm(REALM_NAME);
        oauth.clientId(DEVICE_APP);
        OAuthClient.DeviceAuthorizationResponse response = oauth.doDeviceAuthorizationRequest(DEVICE_APP, "secret");

        Assert.assertEquals(200, response.getStatusCode());
        assertNotNull(response.getDeviceCode());
        assertNotNull(response.getUserCode());
        assertNotNull(response.getVerificationUri());
        assertNotNull(response.getVerificationUriComplete());
        Assert.assertEquals(60, response.getExpiresIn());
        Assert.assertEquals(5, response.getInterval());

        openVerificationPage(response.getVerificationUriComplete());
        loginPage.assertCurrent();

        // Do Login
        oauth.fillLoginForm("device-login", "password");

        // Consent
        grantPage.assertCurrent();
        grantPage.assertGrants(OAuthGrantPage.PROFILE_CONSENT_TEXT, OAuthGrantPage.EMAIL_CONSENT_TEXT, OAuthGrantPage.ROLES_CONSENT_TEXT);
        grantPage.accept();

        // Token request from device
        OAuthClient.AccessTokenResponse tokenResponse = oauth.doDeviceTokenRequest(DEVICE_APP, "secret", "x");

        Assert.assertEquals(400, tokenResponse.getStatusCode());
        Assert.assertEquals("invalid_grant", tokenResponse.getError());
    }

    @Test
    public void testSuccessVerificationUriComplete() throws Exception {
        // Device Authorization Request from device
        oauth.realm(REALM_NAME);
        oauth.clientId(DEVICE_APP);
        OAuthClient.DeviceAuthorizationResponse response = oauth.doDeviceAuthorizationRequest(DEVICE_APP, "secret");

        Assert.assertEquals(200, response.getStatusCode());
        assertNotNull(response.getDeviceCode());
        assertNotNull(response.getUserCode());
        assertNotNull(response.getVerificationUri());
        assertNotNull(response.getVerificationUriComplete());
        Assert.assertEquals(60, response.getExpiresIn());
        Assert.assertEquals(5, response.getInterval());

        openVerificationPage(response.getVerificationUriComplete());
        loginPage.assertCurrent();

        // Do Login
        oauth.fillLoginForm("device-login", "password");

        // Consent
        grantPage.assertCurrent();
        grantPage.assertGrants(OAuthGrantPage.PROFILE_CONSENT_TEXT, OAuthGrantPage.EMAIL_CONSENT_TEXT, OAuthGrantPage.ROLES_CONSENT_TEXT);
        grantPage.accept();

        verificationPage.assertApprovedPage();

        // Token request from device
        OAuthClient.AccessTokenResponse tokenResponse = oauth.doDeviceTokenRequest(DEVICE_APP, "secret", response.getDeviceCode());

        Assert.assertEquals(200, tokenResponse.getStatusCode());
    }

    @Test
    public void testExpiredDeviceCode() throws Exception {
        // Device Authorization Request from device
        oauth.realm(REALM_NAME);
        oauth.clientId(DEVICE_APP);
        OAuthClient.DeviceAuthorizationResponse response = oauth.doDeviceAuthorizationRequest(DEVICE_APP, "secret");

        Assert.assertEquals(200, response.getStatusCode());
        assertNotNull(response.getDeviceCode());
        assertNotNull(response.getUserCode());
        assertNotNull(response.getVerificationUri());
        assertNotNull(response.getVerificationUriComplete());
        Assert.assertEquals(60, response.getExpiresIn());
        Assert.assertEquals(5, response.getInterval());

        try {
            setTimeOffset(610);
            // Token request from device
            OAuthClient.AccessTokenResponse tokenResponse = oauth.doDeviceTokenRequest(DEVICE_APP, "secret",
                response.getDeviceCode());

            Assert.assertEquals(400, tokenResponse.getStatusCode());
            Assert.assertEquals("expired_token", tokenResponse.getError());
        } finally {
            resetTimeOffset();
        }
    }

    @Test
    public void testDeviceCodeLifespanPerClient() throws Exception {
        ClientResource client = ApiUtil.findClientByClientId(adminClient.realm(REALM_NAME), DEVICE_APP);
        ClientRepresentation clientRepresentation = client.toRepresentation();
        // Device Authorization Request from device
        oauth.realm(REALM_NAME);
        oauth.clientId(DEVICE_APP);
        OAuthClient.DeviceAuthorizationResponse response = oauth.doDeviceAuthorizationRequest(DEVICE_APP, "secret");

        Assert.assertEquals(200, response.getStatusCode());
        assertNotNull(response.getDeviceCode());
        assertNotNull(response.getUserCode());
        assertNotNull(response.getVerificationUri());
        assertNotNull(response.getVerificationUriComplete());
        Assert.assertEquals(60, response.getExpiresIn());
        Assert.assertEquals(5, response.getInterval());

        clientRepresentation.getAttributes().put(OAuth2DeviceConfig.OAUTH2_DEVICE_CODE_LIFESPAN_PER_CLIENT, "120");
        clientRepresentation.getAttributes().put(OAuth2DeviceConfig.OAUTH2_DEVICE_POLLING_INTERVAL_PER_CLIENT, "600000");
        client.update(clientRepresentation);

        response = oauth.doDeviceAuthorizationRequest(DEVICE_APP, "secret");
        Assert.assertEquals(120, response.getExpiresIn());
        OAuthClient.AccessTokenResponse tokenResponse;

        try {
            setTimeOffset(100);
            // Token request from device
            tokenResponse = oauth.doDeviceTokenRequest(DEVICE_APP, "secret", response.getDeviceCode());

            Assert.assertEquals(400, tokenResponse.getStatusCode());
            Assert.assertEquals("authorization_pending", tokenResponse.getError());

            setTimeOffset(125);
            // Token request from device
            tokenResponse = oauth.doDeviceTokenRequest(DEVICE_APP, "secret", response.getDeviceCode());

            Assert.assertEquals(400, tokenResponse.getStatusCode());
            Assert.assertEquals("expired_token", tokenResponse.getError());
        } finally {
            resetTimeOffset();
        }

        clientRepresentation.getAttributes().put(OAuth2DeviceConfig.OAUTH2_DEVICE_CODE_LIFESPAN_PER_CLIENT, "");
        clientRepresentation.getAttributes().put(OAuth2DeviceConfig.OAUTH2_DEVICE_POLLING_INTERVAL_PER_CLIENT, "");
        client.update(clientRepresentation);
    }

    @Test
    public void testDevicePollingIntervalPerClient() throws Exception {
        getTestingClient().testing().setTestingInfinispanTimeService();
        ClientResource client = ApiUtil.findClientByClientId(adminClient.realm(REALM_NAME), DEVICE_APP);
        ClientRepresentation clientRepresentation = client.toRepresentation();
        // Device Authorization Request from device
        oauth.realm(REALM_NAME);
        oauth.clientId(DEVICE_APP);
        OAuthClient.DeviceAuthorizationResponse response = oauth.doDeviceAuthorizationRequest(DEVICE_APP, "secret");

        Assert.assertEquals(200, response.getStatusCode());
        assertNotNull(response.getDeviceCode());
        assertNotNull(response.getUserCode());
        assertNotNull(response.getVerificationUri());
        assertNotNull(response.getVerificationUriComplete());
        Assert.assertEquals(60, response.getExpiresIn());
        Assert.assertEquals(5, response.getInterval());

        clientRepresentation.getAttributes().put(OAuth2DeviceConfig.OAUTH2_DEVICE_POLLING_INTERVAL_PER_CLIENT, "10");
        client.update(clientRepresentation);

        response = oauth.doDeviceAuthorizationRequest(DEVICE_APP, "secret");
        Assert.assertEquals(10, response.getInterval());

        try {
            // Token request from device
            OAuthClient.AccessTokenResponse tokenResponse = oauth.doDeviceTokenRequest(DEVICE_APP, "secret",
                response.getDeviceCode());

            Assert.assertEquals(400, tokenResponse.getStatusCode());
            Assert.assertEquals("authorization_pending", tokenResponse.getError());

            // Token request from device
            tokenResponse = oauth.doDeviceTokenRequest(DEVICE_APP, "secret", response.getDeviceCode());

            Assert.assertEquals(400, tokenResponse.getStatusCode());
            Assert.assertEquals("slow_down", tokenResponse.getError());

            setTimeOffset(7);

            // Token request from device
            tokenResponse = oauth.doDeviceTokenRequest(DEVICE_APP, "secret", response.getDeviceCode());

            Assert.assertEquals(400, tokenResponse.getStatusCode());
            Assert.assertEquals("slow_down", tokenResponse.getError());

            setTimeOffset(10);

            // Token request from device
            tokenResponse = oauth.doDeviceTokenRequest(DEVICE_APP, "secret", response.getDeviceCode());

            Assert.assertEquals(400, tokenResponse.getStatusCode());
            Assert.assertEquals("authorization_pending", tokenResponse.getError());
        } finally {
            getTestingClient().testing().revertTestingInfinispanTimeService();
            clientRepresentation.getAttributes().put(OAuth2DeviceConfig.OAUTH2_DEVICE_POLLING_INTERVAL_PER_CLIENT, "");
            client.update(clientRepresentation);
        }
    }

    @Test
    public void testPooling() throws Exception {
        getTestingClient().testing().setTestingInfinispanTimeService();

        try {
            RealmRepresentation realm = getAdminClient().realm(REALM_NAME).toRepresentation();
            realm.setOAuth2DeviceCodeLifespan(600);
            getAdminClient().realm(REALM_NAME).update(realm);
            // Device Authorization Request from device
            oauth.realm(REALM_NAME);
            oauth.clientId(DEVICE_APP);
            OAuthClient.DeviceAuthorizationResponse response = oauth.doDeviceAuthorizationRequest(DEVICE_APP, "secret");

            Assert.assertEquals(600, response.getExpiresIn());
            Assert.assertEquals(5, response.getInterval());

            // Polling token request from device
            OAuthClient.AccessTokenResponse tokenResponse = oauth.doDeviceTokenRequest(DEVICE_APP, "secret", response.getDeviceCode());

            // Not approved yet
            Assert.assertEquals(400, tokenResponse.getStatusCode());
            Assert.assertEquals("authorization_pending", tokenResponse.getError());

            // Polling again without waiting
            tokenResponse = oauth.doDeviceTokenRequest(DEVICE_APP, "secret", response.getDeviceCode());

            // Slow down
            Assert.assertEquals(400, tokenResponse.getStatusCode());
            Assert.assertEquals("slow_down", tokenResponse.getError());

            // Wait the interval
            setTimeOffset(5);

            // Polling again
            tokenResponse = oauth.doDeviceTokenRequest(DEVICE_APP, "secret", response.getDeviceCode());

            // Not approved yet
            Assert.assertEquals(400, tokenResponse.getStatusCode());
            Assert.assertEquals("authorization_pending", tokenResponse.getError());

            // Change the interval setting of the realm from 5 seconds to 10 seconds.
            realm.setOAuth2DevicePollingInterval(10);
            getAdminClient().realm(REALM_NAME).update(realm);

            // Checking the new interval is applied
            response = oauth.doDeviceAuthorizationRequest(DEVICE_APP, "secret");

            Assert.assertEquals(600, response.getExpiresIn());
            Assert.assertEquals(10, response.getInterval());

            // Polling token request from device
            tokenResponse = oauth.doDeviceTokenRequest(DEVICE_APP, "secret", response.getDeviceCode());

            // Not approved yet
            Assert.assertEquals(400, tokenResponse.getStatusCode());
            Assert.assertEquals("authorization_pending", tokenResponse.getError());

            // Wait
            setTimeOffset(10);

            // Polling again without waiting
            tokenResponse = oauth.doDeviceTokenRequest(DEVICE_APP, "secret", response.getDeviceCode());

            // Slow down
            Assert.assertEquals(400, tokenResponse.getStatusCode());
            Assert.assertEquals("slow_down", tokenResponse.getError());

            // Wait
            setTimeOffset(15);

            // Polling again
            tokenResponse = oauth.doDeviceTokenRequest(DEVICE_APP, "secret", response.getDeviceCode());

            // Not approved yet
            Assert.assertEquals(400, tokenResponse.getStatusCode());
            Assert.assertEquals("authorization_pending", tokenResponse.getError());
        } finally {
            getTestingClient().testing().revertTestingInfinispanTimeService();
        }
    }

    @Test
    public void testUpdateConfig() {
        RealmResource realm = getAdminClient().realm(REALM_NAME);
        RealmRepresentation rep = realm.toRepresentation();

        rep.setOAuth2DevicePollingInterval(DEFAULT_OAUTH2_DEVICE_POLLING_INTERVAL);
        rep.setOAuth2DeviceCodeLifespan(DEFAULT_OAUTH2_DEVICE_CODE_LIFESPAN);

        realm.update(rep);
        rep = realm.toRepresentation();

        Assert.assertEquals(DEFAULT_OAUTH2_DEVICE_POLLING_INTERVAL, rep.getOAuth2DevicePollingInterval().intValue());
        Assert.assertEquals(DEFAULT_OAUTH2_DEVICE_CODE_LIFESPAN, rep.getOAuth2DeviceCodeLifespan().intValue());

        rep.setOAuth2DevicePollingInterval(10);
        rep.setOAuth2DeviceCodeLifespan(15);

        realm.update(rep);
        rep = realm.toRepresentation();

        Assert.assertEquals(10, rep.getOAuth2DevicePollingInterval().intValue());
        Assert.assertEquals(15, rep.getOAuth2DeviceCodeLifespan().intValue());
    }

    private void openVerificationPage(String verificationUri) {
        driver.navigate().to(verificationUri);
    }
}
