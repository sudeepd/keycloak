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

package org.keycloak.testsuite.oauth;

import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.message.BasicNameValuePair;
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.junit.Rule;
import org.junit.Test;
import org.keycloak.OAuth2Constants;
import org.keycloak.OAuthErrorException;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.authentication.authenticators.client.ClientIdAndSecretAuthenticator;
import org.keycloak.connections.infinispan.InfinispanConnectionProvider;
import org.keycloak.crypto.Algorithm;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.jose.jws.JWSHeader;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.models.utils.TimeBasedOTP;
import org.keycloak.protocol.oidc.OIDCAdvancedConfigWrapper;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.RefreshToken;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.keycloak.testsuite.AbstractKeycloakTest;
import org.keycloak.testsuite.Assert;
import org.keycloak.testsuite.AssertEvents;
import org.keycloak.testsuite.admin.ApiUtil;
import org.keycloak.testsuite.util.ClientBuilder;
import org.keycloak.testsuite.util.ClientManager;
import org.keycloak.testsuite.util.OAuthClient;
import org.keycloak.testsuite.util.RealmBuilder;
import org.keycloak.testsuite.util.RealmManager;
import org.keycloak.testsuite.util.TokenSignatureUtil;
import org.keycloak.testsuite.util.UserBuilder;
import org.keycloak.testsuite.util.UserManager;

import java.io.UnsupportedEncodingException;
import java.security.Security;
import java.util.LinkedList;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;

/**
 * @author <a href="mailto:sthorger@redhat.com">Stian Thorgersen</a>
 */
public class ResourceOwnerPasswordCredentialsGrantTest extends AbstractKeycloakTest {

    private static String userId;

    private static String userId2;

    private static String userIdMultipleOTPs;

    private final TimeBasedOTP totp = new TimeBasedOTP();

    @Rule
    public AssertEvents events = new AssertEvents(this);

    @Override
    public void beforeAbstractKeycloakTest() throws Exception {
        super.beforeAbstractKeycloakTest();
        if (Security.getProvider("BCFIPS") == null) Security.addProvider(new BouncyCastleFipsProvider());
    }

    @Override
    public void addTestRealms(List<RealmRepresentation> testRealms) {
        RealmBuilder realm = RealmBuilder.create().name("test")
                .privateKey("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")
                .publicKey("MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAs2njo0TT4UkMcp2Cq+6wcyEVZsyLJ+3bIG5pBPwzik3jUEPG3r7SlPJyx/x6wXUNDvI/x4Q7CKEh6Xm1oLXGStyHQWiFX9VuyTe4aR5VMWC6maezK2YsWVkXY0OGCi96J85qWHRGnIloaCKXr0vfyVsGmrAwnCmRj/aUiQTwZB54lQt0t9wgrT944vvCVoyAiThmIlMNdL87LNwjj5t50kKmPccCl7bjo4IvakDMhpJbvJbz7WWldoBWa7hlU8EmGpUhB3Q2pNqnUQBVKeYu67kfA9uLto6XK/UTpwVcIugveS5v8f/5ZhWM6oGNfam8JiJhD7zP3GYfSTpcYGDKrLnqdE7+bOxzYSXVqTS0dO2J20qr0J2qnykI+y/dpCiZDlhq0AChe142QkxA9zDbSmH89Oy6oJvdBnycSTNv2EzameRakxZyDI3Jc2zrc9e/76i3HPO1RK6ZItieEqg4sa/RUGbO3eaq8rdKUwrxGLuxighO11uZ5KcdOhW9PixFAgMBAAE=")
                .testEventListener();


        ClientRepresentation app = ClientBuilder.create()
                .id(KeycloakModelUtils.generateId())
                .clientId("resource-owner")
                .directAccessGrants()
                .secret("secret")
                .build();
        realm.client(app);

        ClientRepresentation app2 = ClientBuilder.create()
                .id(KeycloakModelUtils.generateId())
                .clientId("resource-owner-public")
                .directAccessGrants()
                .publicClient()
                .build();
        realm.client(app2);

        ClientRepresentation app3 = ClientBuilder.create().id(KeycloakModelUtils.generateId())
            .clientId("resource-owner-refresh").directAccessGrants().secret("secret").build();
        OIDCAdvancedConfigWrapper.fromClientRepresentation(app3).setUseRefreshToken(false);
        realm.client(app3);

        UserBuilder defaultUser = UserBuilder.create()
                .id(KeycloakModelUtils.generateId())
                .username("test-user@localhost")
                .password("password");
        realm.user(defaultUser);

        userId = KeycloakModelUtils.generateId();
        UserRepresentation user = UserBuilder.create()
                .id(userId)
                .username("direct-login")
                .email("direct-login@localhost")
                .password("password")
                .build();
        realm.user(user);

        userId2 = KeycloakModelUtils.generateId();
        UserRepresentation user2 = UserBuilder.create()
                .id(userId2)
                .username("direct-login-otp")
                .password("password")
                .totpSecret("totpSecret")
                .build();
        realm.user(user2);

        userIdMultipleOTPs = KeycloakModelUtils.generateId();
        UserBuilder userBuilderMultipleOTPs = UserBuilder.create()
                .id(userIdMultipleOTPs)
                .username("direct-login-multiple-otps")
                .password("password")
                .totpSecret("firstOTPIsPreferredCredential");
        for (int i = 2; i <= 10; i++) userBuilderMultipleOTPs.totpSecret(String.format("%s-th OTP authenticator", i));
        realm.user(userBuilderMultipleOTPs.build());

        testRealms.add(realm.build());
    }

    @Test
    public void grantAccessTokenUsername() throws Exception {
        int authSessionsBefore = getAuthenticationSessionsCount();

        grantAccessToken("direct-login", "resource-owner");

        // Check that count of authSessions is same as before authentication (as authentication session was removed)
        Assert.assertEquals(authSessionsBefore, getAuthenticationSessionsCount());
    }

    @Test
    public void grantAccessTokenEmail() throws Exception {
        grantAccessToken("direct-login@localhost", "resource-owner");
    }

    @Test
    public void grantAccessTokenPublic() throws Exception {
        grantAccessToken("direct-login", "resource-owner-public");
    }

    @Test
    public void grantAccessTokenWithTotp() throws Exception {
        grantAccessToken(userId2, "direct-login-otp", "resource-owner", totp.generateTOTP("totpSecret"));
    }

    @Test
    public void grantAccessTokenWithMultipleTotp() throws Exception {
        // Confirm user can login with 1-th OTP since it's the preferred credential
        grantAccessToken(userIdMultipleOTPs, "direct-login-multiple-otps", "resource-owner", totp.generateTOTP("firstOTPIsPreferredCredential"));
        // For remaining OTP tokens HTTP 401 "Unauthorized" is the allowed / expected response
        oauth.clientId("resource-owner");
        for (int i = 2; i <= 10; i++) {
            String otp = totp.generateTOTP(String.format("%s-th OTP authenticator", i));
            OAuthClient.AccessTokenResponse response = oauth.doGrantAccessTokenRequest("secret", "direct-login-multiple-otps", "password", otp);
            assertEquals(401, response.getStatusCode());
        }
    }

    @Test
    public void grantAccessTokenMissingTotp() throws Exception {
        oauth.clientId("resource-owner");

        OAuthClient.AccessTokenResponse response = oauth.doGrantAccessTokenRequest("secret", "direct-login-otp", "password");

        assertEquals(401, response.getStatusCode());

        assertEquals("invalid_grant", response.getError());

        events.expectLogin()
                .client("resource-owner")
                .session((String) null)
                .clearDetails()
                .error(Errors.INVALID_USER_CREDENTIALS)
                .user(userId2)
                .assertEvent();
    }

    @Test
    public void grantAccessTokenInvalidTotp() throws Exception {
        int authSessionsBefore = getAuthenticationSessionsCount();

        oauth.clientId("resource-owner");

        OAuthClient.AccessTokenResponse response = oauth.doGrantAccessTokenRequest("secret", "direct-login-otp", "password", totp.generateTOTP("totpSecret2"));

        assertEquals(401, response.getStatusCode());

        assertEquals("invalid_grant", response.getError());

        events.expectLogin()
                .client("resource-owner")
                .session((String) null)
                .clearDetails()
                .error(Errors.INVALID_USER_CREDENTIALS)
                .user(userId2)
                .assertEvent();

        // Check that count of authSessions is same as before authentication (as authentication session was removed)
        Assert.assertEquals(authSessionsBefore, getAuthenticationSessionsCount());
    }

    private void grantAccessToken(String login, String clientId) throws Exception {
        grantAccessToken(userId, login, clientId, null);
    }

    private void grantAccessToken(String userId, String login, String clientId, String otp) throws Exception {
        oauth.clientId(clientId);

        OAuthClient.AccessTokenResponse response = oauth.doGrantAccessTokenRequest("secret", login, "password", otp);

        assertEquals(200, response.getStatusCode());

        AccessToken accessToken = oauth.verifyToken(response.getAccessToken());
        RefreshToken refreshToken = oauth.parseRefreshToken(response.getRefreshToken());

        events.expectLogin()
                .client(clientId)
                .user(userId)
                .session(accessToken.getSessionState())
                .detail(Details.GRANT_TYPE, OAuth2Constants.PASSWORD)
                .detail(Details.TOKEN_ID, accessToken.getId())
                .detail(Details.REFRESH_TOKEN_ID, refreshToken.getId())
                .detail(Details.USERNAME, login)
                .removeDetail(Details.CODE_ID)
                .removeDetail(Details.REDIRECT_URI)
                .removeDetail(Details.CONSENT)
                .assertEvent();

        Assert.assertTrue(login.equals(accessToken.getPreferredUsername()) || login.equals(accessToken.getEmail()));

        assertEquals(accessToken.getSessionState(), refreshToken.getSessionState());

        OAuthClient.AccessTokenResponse refreshedResponse = oauth.doRefreshTokenRequest(response.getRefreshToken(), "secret");

        AccessToken refreshedAccessToken = oauth.verifyToken(refreshedResponse.getAccessToken());
        RefreshToken refreshedRefreshToken = oauth.parseRefreshToken(refreshedResponse.getRefreshToken());

        assertEquals(accessToken.getSessionState(), refreshedAccessToken.getSessionState());
        assertEquals(accessToken.getSessionState(), refreshedRefreshToken.getSessionState());

        events.expectRefresh(refreshToken.getId(), refreshToken.getSessionState()).user(userId).client(clientId).assertEvent();
    }

    @Test
    public void grantRequest_ClientES256_RealmPS256() throws Exception {
    	conductGrantRequest(Algorithm.HS256, Algorithm.ES256, Algorithm.PS256);
    }

    @Test
    public void grantRequest_ClientPS256_RealmES256() throws Exception {
    	conductGrantRequest(Algorithm.HS256, Algorithm.PS256, Algorithm.ES256);
    }

    private void conductGrantRequest(String expectedRefreshAlg, String expectedAccessAlg, String realmTokenAlg) throws Exception {
        try {
            TokenSignatureUtil.changeRealmTokenSignatureProvider(adminClient, realmTokenAlg);
            TokenSignatureUtil.changeClientAccessTokenSignatureProvider(ApiUtil.findClientByClientId(adminClient.realm("test"), "resource-owner"), expectedAccessAlg);
            grantRequest(expectedRefreshAlg, expectedAccessAlg);
        } finally {
            TokenSignatureUtil.changeRealmTokenSignatureProvider(adminClient, Algorithm.RS256);
            TokenSignatureUtil.changeClientAccessTokenSignatureProvider(ApiUtil.findClientByClientId(adminClient.realm("test"), "resource-owner"), Algorithm.RS256);
        }
        return;
    }

    private void grantRequest(String expectedRefreshAlg, String expectedAccessAlg) throws Exception {
        String clientId = "resource-owner";
        String login = "direct-login";

        oauth.clientId(clientId);

        OAuthClient.AccessTokenResponse response = oauth.doGrantAccessTokenRequest("secret", login, "password", null);

        assertEquals(200, response.getStatusCode());

        AccessToken accessToken = oauth.verifyToken(response.getAccessToken());
        RefreshToken refreshToken = oauth.parseRefreshToken(response.getRefreshToken());
        JWSHeader header = new JWSInput(response.getAccessToken()).getHeader();

        assertEquals(expectedAccessAlg, header.getAlgorithm().name());
        assertEquals("JWT", header.getType());
        assertNull(header.getContentType());

        header = new JWSInput(response.getRefreshToken()).getHeader();
        assertEquals(expectedRefreshAlg, header.getAlgorithm().name());
        assertEquals("JWT", header.getType());
        assertNull(header.getContentType());

        events.expectLogin()
                .client(clientId)
                .user(userId)
                .session(accessToken.getSessionState())
                .detail(Details.GRANT_TYPE, OAuth2Constants.PASSWORD)
                .detail(Details.TOKEN_ID, accessToken.getId())
                .detail(Details.REFRESH_TOKEN_ID, refreshToken.getId())
                .detail(Details.USERNAME, login)
                .removeDetail(Details.CODE_ID)
                .removeDetail(Details.REDIRECT_URI)
                .removeDetail(Details.CONSENT)
                .assertEvent();

        Assert.assertTrue(login.equals(accessToken.getPreferredUsername()) || login.equals(accessToken.getEmail()));

        assertEquals(accessToken.getSessionState(), refreshToken.getSessionState());

        OAuthClient.AccessTokenResponse refreshedResponse = oauth.doRefreshTokenRequest(response.getRefreshToken(), "secret");

        AccessToken refreshedAccessToken = oauth.verifyToken(refreshedResponse.getAccessToken());
        RefreshToken refreshedRefreshToken = oauth.parseRefreshToken(refreshedResponse.getRefreshToken());

        assertEquals(accessToken.getSessionState(), refreshedAccessToken.getSessionState());
        assertEquals(accessToken.getSessionState(), refreshedRefreshToken.getSessionState());

        events.expectRefresh(refreshToken.getId(), refreshToken.getSessionState()).user(userId).client(clientId).assertEvent();
    }

    @Test
    public void grantAccessTokenLogout() throws Exception {
        oauth.clientId("resource-owner");

        OAuthClient.AccessTokenResponse response = oauth.doGrantAccessTokenRequest("secret", "test-user@localhost", "password");

        assertEquals(200, response.getStatusCode());

        AccessToken accessToken = oauth.verifyToken(response.getAccessToken());
        RefreshToken refreshToken = oauth.parseRefreshToken(response.getRefreshToken());

        events.expectLogin()
                .client("resource-owner")
                .session(accessToken.getSessionState())
                .detail(Details.GRANT_TYPE, OAuth2Constants.PASSWORD)
                .detail(Details.TOKEN_ID, accessToken.getId())
                .detail(Details.REFRESH_TOKEN_ID, refreshToken.getId())
                .removeDetail(Details.CODE_ID)
                .removeDetail(Details.REDIRECT_URI)
                .removeDetail(Details.CONSENT)
                .detail(Details.CLIENT_AUTH_METHOD, ClientIdAndSecretAuthenticator.PROVIDER_ID)
                .assertEvent();

        HttpResponse logoutResponse = oauth.doLogout(response.getRefreshToken(), "secret");
        assertEquals(204, logoutResponse.getStatusLine().getStatusCode());
        events.expectLogout(accessToken.getSessionState()).client("resource-owner").removeDetail(Details.REDIRECT_URI).assertEvent();

        response = oauth.doRefreshTokenRequest(response.getRefreshToken(), "secret");
        assertEquals(400, response.getStatusCode());
        assertEquals("invalid_grant", response.getError());

        events.expectRefresh(refreshToken.getId(), refreshToken.getSessionState()).client("resource-owner")
                .removeDetail(Details.TOKEN_ID)
                .removeDetail(Details.UPDATED_REFRESH_TOKEN_ID)
                .error(Errors.INVALID_TOKEN).assertEvent();
    }

    @Test
    public void grantAccessTokenInvalidClientCredentials() throws Exception {
        oauth.clientId("resource-owner");

        OAuthClient.AccessTokenResponse response = oauth.doGrantAccessTokenRequest("invalid", "test-user@localhost", "password");

        assertEquals(401, response.getStatusCode());

        assertEquals("unauthorized_client", response.getError());

        events.expectLogin()
                .client("resource-owner")
                .session((String) null)
                .clearDetails()
                .error(Errors.INVALID_CLIENT_CREDENTIALS)
                .user((String) null)
                .assertEvent();
    }

    @Test
    public void grantAccessTokenMissingClientCredentials() throws Exception {
        oauth.clientId("resource-owner");

        OAuthClient.AccessTokenResponse response = oauth.doGrantAccessTokenRequest(null, "test-user@localhost", "password");

        assertEquals(401, response.getStatusCode());

        assertEquals("unauthorized_client", response.getError());

        events.expectLogin()
                .client("resource-owner")
                .session((String) null)
                .clearDetails()
                .error(Errors.INVALID_CLIENT_CREDENTIALS)
                .user((String) null)
                .assertEvent();
    }

    @Test
    public void grantAccessTokenClientNotAllowed() throws Exception {

        ClientManager.realm(adminClient.realm("test")).clientId("resource-owner").directAccessGrant(false);

        oauth.clientId("resource-owner");

        OAuthClient.AccessTokenResponse response = oauth.doGrantAccessTokenRequest("secret", "test-user@localhost", "password");

        assertEquals(400, response.getStatusCode());

        assertEquals(OAuthErrorException.UNAUTHORIZED_CLIENT, response.getError());

        events.expectLogin()
                .client("resource-owner")
                .session((String) null)
                .clearDetails()
                .error(Errors.NOT_ALLOWED)
                .user((String) null)
                .assertEvent();

        ClientManager.realm(adminClient.realm("test")).clientId("resource-owner").directAccessGrant(true);

    }

    @Test
    public void grantAccessTokenVerifyEmail() throws Exception {
        int authSessionsBefore = getAuthenticationSessionsCount();

        RealmResource realmResource = adminClient.realm("test");
        RealmManager.realm(realmResource).verifyEmail(true);

        oauth.clientId("resource-owner");

        OAuthClient.AccessTokenResponse response = oauth.doGrantAccessTokenRequest("secret", "test-user@localhost", "password");

        assertEquals(400, response.getStatusCode());

        assertEquals("invalid_grant", response.getError());
        assertEquals("Account is not fully set up", response.getErrorDescription());

        events.expectLogin()
                .client("resource-owner")
                .session((String) null)
                .clearDetails()
                .error(Errors.RESOLVE_REQUIRED_ACTIONS)
                .user((String) null)
                .assertEvent();

        RealmManager.realm(realmResource).verifyEmail(false);
        UserManager.realm(realmResource).username("test-user@localhost").removeRequiredAction(UserModel.RequiredAction.VERIFY_EMAIL.toString());

        // Check that count of authSessions is same as before authentication (as authentication session was removed)
        Assert.assertEquals(authSessionsBefore, getAuthenticationSessionsCount());
    }
    
    @Test
    public void grantAccessTokenVerifyEmailInvalidPassword() throws Exception {

        RealmResource realmResource = adminClient.realm("test");
        RealmManager.realm(realmResource).verifyEmail(true);

        oauth.clientId("resource-owner");

        OAuthClient.AccessTokenResponse response = oauth.doGrantAccessTokenRequest("secret", "test-user@localhost", "bad-password");

        assertEquals(401, response.getStatusCode());

        assertEquals("invalid_grant", response.getError());
        assertEquals("Invalid user credentials", response.getErrorDescription());

        events.expectLogin()
                .client("resource-owner")
                .session((String) null)
                .detail(Details.GRANT_TYPE, OAuth2Constants.PASSWORD)
                .removeDetail(Details.CODE_ID)
                .removeDetail(Details.REDIRECT_URI)
                .removeDetail(Details.CONSENT)
                .error(Errors.INVALID_USER_CREDENTIALS)
                .assertEvent();

        RealmManager.realm(realmResource).verifyEmail(false);
        UserManager.realm(realmResource).username("test-user@localhost").removeRequiredAction(UserModel.RequiredAction.VERIFY_EMAIL.toString());

    }

    @Test
    public void grantAccessTokenExpiredPassword() throws Exception {

        RealmResource realmResource = adminClient.realm("test");
        RealmManager.realm(realmResource).passwordPolicy("forceExpiredPasswordChange(1)");

        try {
            setTimeOffset(60 * 60 * 48);

            oauth.clientId("resource-owner");

            OAuthClient.AccessTokenResponse response = oauth.doGrantAccessTokenRequest("secret", "test-user@localhost", "password");

            assertEquals(400, response.getStatusCode());

            assertEquals("invalid_grant", response.getError());
            assertEquals("Account is not fully set up", response.getErrorDescription());

            setTimeOffset(0);

            events.expectLogin()
                    .client("resource-owner")
                    .session((String) null)
                    .clearDetails()
                    .error(Errors.RESOLVE_REQUIRED_ACTIONS)
                    .user((String) null)
                    .assertEvent();
        } finally {
            RealmManager.realm(realmResource).passwordPolicy("");
            UserManager.realm(realmResource).username("test-user@localhost")
                    .removeRequiredAction(UserModel.RequiredAction.UPDATE_PASSWORD.toString());
        }
    }
    
    @Test
    public void grantAccessTokenExpiredPasswordInvalidPassword() throws Exception {

        RealmResource realmResource = adminClient.realm("test");
        RealmManager.realm(realmResource).passwordPolicy("forceExpiredPasswordChange(1)");

        try {
            setTimeOffset(60 * 60 * 48);

            oauth.clientId("resource-owner");

            OAuthClient.AccessTokenResponse response = oauth.doGrantAccessTokenRequest("secret", "test-user@localhost", "bad-password");

            assertEquals(401, response.getStatusCode());

            assertEquals("invalid_grant", response.getError());
            assertEquals("Invalid user credentials", response.getErrorDescription());

            events.expectLogin()
                    .client("resource-owner")
                    .session((String) null)
                    .detail(Details.GRANT_TYPE, OAuth2Constants.PASSWORD)
                    .removeDetail(Details.CODE_ID)
                    .removeDetail(Details.REDIRECT_URI)
                    .removeDetail(Details.CONSENT)
                    .error(Errors.INVALID_USER_CREDENTIALS)
                    .assertEvent();
        } finally {
            RealmManager.realm(realmResource).passwordPolicy("");
            UserManager.realm(realmResource).username("test-user@localhost")
                    .removeRequiredAction(UserModel.RequiredAction.UPDATE_PASSWORD.toString());
        }
    }

    @Test
    public void grantAccessTokenInvalidUserCredentials() throws Exception {
        oauth.clientId("resource-owner");

        OAuthClient.AccessTokenResponse response = oauth.doGrantAccessTokenRequest("secret", "test-user@localhost", "invalid");

        assertEquals(401, response.getStatusCode());

        assertEquals("invalid_grant", response.getError());
        assertEquals("Invalid user credentials", response.getErrorDescription());

        events.expectLogin()
                .client("resource-owner")
                .session((String) null)
                .detail(Details.GRANT_TYPE, OAuth2Constants.PASSWORD)
                .removeDetail(Details.CODE_ID)
                .removeDetail(Details.REDIRECT_URI)
                .removeDetail(Details.CONSENT)
                .error(Errors.INVALID_USER_CREDENTIALS)
                .assertEvent();
    }

    @Test
    public void grantAccessTokenUserNotFound() throws Exception {
        oauth.clientId("resource-owner");

        OAuthClient.AccessTokenResponse response = oauth.doGrantAccessTokenRequest("secret", "invalid", "invalid");

        assertEquals(401, response.getStatusCode());

        assertEquals("invalid_grant", response.getError());

        events.expectLogin()
                .client("resource-owner")
                .user((String) null)
                .session((String) null)
                .detail(Details.GRANT_TYPE, OAuth2Constants.PASSWORD)
                .detail(Details.USERNAME, "invalid")
                .removeDetail(Details.CODE_ID)
                .removeDetail(Details.REDIRECT_URI)
                .removeDetail(Details.CONSENT)
                .error(Errors.USER_NOT_FOUND)
                .assertEvent();
    }

    @Test
    public void grantAccessTokenMissingGrantType() throws Exception {
        oauth.clientId("resource-owner");

        try (CloseableHttpClient client = HttpClientBuilder.create().build()) {
            HttpPost post = new HttpPost(oauth.getResourceOwnerPasswordCredentialGrantUrl());
            post.addHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED);
            OAuthClient.AccessTokenResponse response = new OAuthClient.AccessTokenResponse(client.execute(post));

            assertEquals(400, response.getStatusCode());

            assertEquals("invalid_request", response.getError());
            assertEquals("Missing form parameter: grant_type", response.getErrorDescription());
        }
    }

    @Test
    public void grantAccessTokenUnsupportedGrantType() throws Exception {
        oauth.clientId("resource-owner");

        try (CloseableHttpClient client = HttpClientBuilder.create().build()) {
            HttpPost post = new HttpPost(oauth.getResourceOwnerPasswordCredentialGrantUrl());
            List<NameValuePair> parameters = new LinkedList<>();
            parameters.add(new BasicNameValuePair(OAuth2Constants.GRANT_TYPE, "unsupported_grant_type"));
            UrlEncodedFormEntity formEntity;
            try {
                formEntity = new UrlEncodedFormEntity(parameters, "UTF-8");
            } catch (UnsupportedEncodingException e) {
                throw new RuntimeException(e);
            }
            post.setEntity(formEntity);
            OAuthClient.AccessTokenResponse response = new OAuthClient.AccessTokenResponse(client.execute(post));

            assertEquals(400, response.getStatusCode());

            assertEquals(OAuthErrorException.UNSUPPORTED_GRANT_TYPE, response.getError());
            assertEquals("Unsupported grant_type", response.getErrorDescription());
        }
    }

    @Test
    public void grantAccessTokenNoRefreshToken() throws Exception {
        oauth.clientId("resource-owner-refresh");
        OAuthClient.AccessTokenResponse response = oauth.doGrantAccessTokenRequest("secret", "direct-login", "password", null);

        assertEquals(200, response.getStatusCode());

        assertNotNull(response.getAccessToken());
        assertNull(response.getRefreshToken());
    }

    private int getAuthenticationSessionsCount() {
        return testingClient.testing().cache(InfinispanConnectionProvider.AUTHENTICATION_SESSIONS_CACHE_NAME).size();
    }
}
