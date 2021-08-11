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
                .privateKey("MIIG/gIBADANBgkqhkiG9w0BAQEFAASCBugwggbkAgEAAoIBgQCzaeOjRNPhSQxynYKr7rBzIRVmzIsn7dsgbmkE/DOKTeNQQ8bevtKU8nLH/HrBdQ0O8j/HhDsIoSHpebWgtcZK3IdBaIVf1W7JN7hpHlUxYLqZp7MrZixZWRdjQ4YKL3onzmpYdEaciWhoIpevS9/JWwaasDCcKZGP9pSJBPBkHniVC3S33CCtP3ji+8JWjICJOGYiUw10vzss3COPm3nSQqY9xwKXtuOjgi9qQMyGklu8lvPtZaV2gFZruGVTwSYalSEHdDak2qdRAFUp5i7ruR8D24u2jpcr9ROnBVwi6C95Lm/x//lmFYzqgY19qbwmImEPvM/cZh9JOlxgYMqsuep0Tv5s7HNhJdWpNLR07YnbSqvQnaqfKQj7L92kKJkOWGrQAKF7XjZCTED3MNtKYfz07Lqgm90GfJxJM2/YTNqZ5FqTFnIMjclzbOtz17/vqLcc87VErpki2J4SqDixr9FQZs7d5qryt0pTCvEYu7GKCE7XW5nkpx06Fb0+LEUCAwEAAQKCAYBIBUXAEK0NTomUqO3/nr1uOeWhcpKZ4L2J80htG+CEsGeDnPGEEQ3vhLPW299bMWWgjlZT/RzFhgla8+SZMt76xjP1acPAiKkEVT3N1MNWIwJFFDC0RzueUkk1K7Hu/MgImq/N+j8uL2qeAuTpFYgsCEJKblfVGEq6g710k2r8hc7Z5dNgyxjC8yvP0khc/eHLM7ysIrLQHsPeajBMQZlRcjfRrMW5qU0QIf5upLx1eOMifWZF8fvN6g7HByqFyI6YhzCAP5CzThhKslstxZhy6fm8BVk/YTzK6aiJpOYDggm7dC2F45LclQmo0a2sRxBRr5pkcW1NANzRb6wC8ciTUV0EmhA2odJTTcveJ7yaCU4+aUzXHlhmX/avMLJLEX3zR+d4JWB5msLtG8pdPv7vSThDK5dQm+xMAHpLYuDsTtLH4zgl6+TRHRIHtnTLZRdGNGxdM4mrq45Tpb2lC5PWqKfhvFeE+meYNA+JxYRCxl7ADR0XKLjOsuDHrb+9U4ECgcEA/xiFhdoGxeJb07WqdlKbnZUPa2bTHQOUW+v6+9EbIiBwLvPZxfyhD4arBdyr1OiTZlRUcUR336ZEskmIAfRatPt7GOc43sBJ2YN67J95OGye5Dh1It9oIHU2wrFzMMYPo8jD2xq0P2I39laqd0r5k7Q1Zx1VUph/GL49jdcQIJa+UU1ceaivw0gaMV9Xv1/pJjSDH7wgZT4CJ2M4T2iu/E1Gdy7sUBitFCLcar+729O+4DKcvNzC7TEYACJwuDwJAoHBALQMsTsma1F0qNIAnbMkCbSkTr+9G0OJadd8KN4kGp7ZIkwAMRs58o01Lkgtjn/grnG5nRpJnlZehv+Z8Cx3nPPfIKJzISK5SiMEBYiVv97VxLS/+bhqijlWUQqv1ZIPCTHU3s+3y9kMVggW1W3JCaB9rKdsWaAwKLiRCmzDSOCfWV36cRtzzeof7+cBlWZKlXrowQg7weBIwGeWZF+NnCLzKE9PYfARXNs8WRDDlCFweg4GdK31hJI5V/3n3G61XQKBwHMrCv1HVc95RqPqXK9W1FLsvS1sGtv6hbyKaaHO4kUiCAPqq+MrDzwHPKdE3X8eEY4dfJI2qzgZxOIJOJJJU7pp30V6/r3yamT9az3xMbU7tPCsXJYF7ujYgoSbwLnAcccsGOCOydnj6ggZUJTTEKKStZl8MM09dAQjv36OHgXYiMwD9UAn3FJ59vlbZi5MiuJoytpFAQs0V5yYuw9+36Gg8bNVR/NRcLKqmoDHV3UDwCVQNFs///E+POuyoNlMoQKBwQCN1PnAKLGdhxJ963JO7fKfVFecfzF88EBqOSpQY4x82XtE91m3otxJFD2TKh/46FtCxv7U+G08iFY7/13NCaSgD4K7tYnCuseF8eMSBzUQKsE7yYbEGVktdat9ianp1uJdWNz0MErqfec/lA0o4Jcu0BE0CgxIPee2DLtzlhpQp/ZUK7bx8zWgWuw2w26XF+XM3pFBFSHStjyq3TPQedMnTPjSESyLWoIVSeK3a/nCpcHgToGXj7KRJY8FOqLQqxkCgcEA+IlOpFIKNmzt0m+jk1XexidQcpktLN6YaUy/P+dSuwQXIhxB5SNRWcodeMIbPhSGNrvZ2Tt6nCyEY0WQRcDgoDsTtV5veDVaHaPtMpRbw5rqKzR8ccTRw4KVPCMajyKsQzm2n6tIgBrvI9AUob5JOUv7T5jln978+TDVAl3xVjd8MM59KfyRx00clSqTeb+bJwH1F8GI7teX2ITmVmuhsjwyYUD3wVPGuoim4JmzCnlOxXJ2oEXUq2soxQF+fPje")
                .publicKey("MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAs2njo0TT4UkMcp2Cq+6wcyEVZsyLJ+3bIG5pBPwzik3jUEPG3r7SlPJyx/x6wXUNDvI/x4Q7CKEh6Xm1oLXGStyHQWiFX9VuyTe4aR5VMWC6maezK2YsWVkXY0OGCi96J85qWHRGnIloaCKXr0vfyVsGmrAwnCmRj/aUiQTwZB54lQt0t9wgrT944vvCVoyAiThmIlMNdL87LNwjj5t50kKmPccCl7bjo4IvakDMhpJbvJbz7WWldoBWa7hlU8EmGpUhB3Q2pNqnUQBVKeYu67kfA9uLto6XK/UTpwVcIugveS5v8f/5ZhWM6oGNfam8JiJhD7zP3GYfSTpcYGDKrLnqdE7+bOxzYSXVqTS0dO2J20qr0J2qnykI+y/dpCiZDlhq0AChe142QkxA9zDbSmH89Oy6oJvdBnycSTNv2EzameRakxZyDI3Jc2zrc9e/76i3HPO1RK6ZItieEqg4sa/RUGbO3eaq8rdKUwrxGLuxighO11uZ5KcdOhW9PixFAgMBAAE=")
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
