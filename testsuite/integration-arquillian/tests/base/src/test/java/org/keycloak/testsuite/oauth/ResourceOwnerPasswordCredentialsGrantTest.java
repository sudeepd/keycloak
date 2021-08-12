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
                .privateKey("MIIG/QIBADANBgkqhkiG9w0BAQEFAASCBucwggbjAgEAAoIBgQCJAjodq1x7HsQw1OsKTN+qDGHkvY+EgjgjzOJmGZLkZYoxE2ziGfWiOaM9ZvlOqzB99gl1IPI/WI2cmiAZ1TPMXSvvnHgBsfB4KLdGcIieFcxdlmrPucFRnkOw1q1NJT6S9JnXKwpsYx3R/EdmW0Ltawe96bZchemjXn69O/FIFuqY45jvvMeaFaHPDP+2tH+XOiSfQ1ONbGQt4BmtoJiXfv/zNI5xyt9s7DVrc5XNcZgEt9hjyuY0/4TUsJEuQCjH0IaRAw+xPTTGWtXepqWjOJ+PGLQrVIWmZWKeniNgS+fkHI6LJ3t6Sdxb83VwBHoHPdClteBvtK2b90fJCox3gvRk+siFAYvBjkz8WNTO5bwFJ050R9LDZkTk424JxxvyeOCH9EYz91vxcWf8tGF+OO+ne9LME8ODvAsMJ+HHUuYv1tWrUcPHuZFST5jdwBV6WYi11PATc8z0Jy7udm/8DLFryTKvujO98afQFgrA1Bm+9dff+/BTS+pa9oOdFOMCAwEAAQKCAYBR10634mD/+sTfFpDAOmNwxKzFYqaUVOUMHZsvuh8Q58bAwgXMmg0stplYWGacI45377x+hwut40vUPAzo4X5rmUxheWoGOTCX1lqEbTxukj7duLhdFWzxQETXIaWr64+RYSN0cHVtgVeS08wizGkSQVkCjNUuN5/0wsGacHAUy/ufEHWO34mr9TgO4ojtrqx4vXaa3DDQzeqZrMAqA0CjXm2t7bsZJkKIYiEW6piVfEF+sANGuTECf4/tLPvMUO4rVBppW0vQnJJbwwmlS0+xDnc8xPnpkfLYF1sckFw1Q+obzpUkWJzZihJln/2ZsLjr4h7Wb1E0mOXX/Dh+Tk1/b6u/Ld4lIrReHfK6qNj/axOrVq7AOVM/p84wRCRQ2ubJQK3LWjIsjRgNnIhyAsSBUwkqvPJZUO8d858OthkU9LnmXKUrTnriqn4LUYjJekw0eHkPV8tv1JbhuERjbiP9dPVFp2ngQ3ZtRhZ0+UDA0y63QGesdbknMhuXfDE9wQECgcEAw/mOZvzetk3sX41irDOkYUpIbSD8hgvD2xThCexmeNF+/lULDn/EmGYt3NkcuNE2S0i93I+aaAqkPRijpCZ+eYwtP3vb/dADVbHMrOysTFzxT0hDv6cpZr3HOGiTdqwoqCBPkeAuLe+1nscbo2wTN3jCixJojE+NH1RJtzrIxvgIOKQhorlK/jr+LG+1fjPV2sUWTzbacTsTXhvn6GqOMBDARfORaPNBLycYaU3/KyH4Gd1PlwhRsmF9fNTPFJJhAoHBALL5HobzCWD/Uuog4dA/wbF6Jf0ISJDUicCTXnp9AANIS/g3MsyUdHSPPyx09cCMoGD9MMIZYWQQS4raPmBT52YdNUaMQWNuXVXLs+oQ+gbjltnmglRRBDm36Vy82DAUVb6ySp/dVkJ1KmzK2bYlPR3evNU5b4tQH8y6bmyrVwazBizUaOkazG4eVoety+qvBsq8F1Knbjr6qZbIMlyIFHdBREjGpR+p19i1PmzTXClNEC6ix6h36XVKWfjJhlO1wwKBwQCkibJ15XlXtrTuxNZDnlg1FxkYBsn+AYK/PhhzLHgcmEf3YY+W7M8y5Rc8hU0IHx9mtfwyYp9RGx4p7bX27BrkEj0rP+LEhxFFsbIWvd8rfh1cY1/+WWr5R/0r7yFgUcsQ3Y/w+jfLeacTWDhsTSEVQd6UxS/iHihuVWZO4JwR8c11QNi8trWwHfepd2D6RKsYssC4YWWmC+OG8AcVq+EVmfrUwFslspbX8Ase3s2OeUbE8HsSY3m0OwYQ+NukegECgcAhSsQJ+GWzPGuRD+LRmTqPqBgu9H6DKnYhc4hsopoBAk7XcnUppyfuksL+oxcf5UjkIdUTFiOOuJVE1AosYw81aJODdw2m0F3eWtEx5kyMQYPLLtzpkFSH5BUt4hcZAn9cxM+q40JrhF4K9MUA4/Z1evyHcXK1aIcxzzBBWLIMlfq9FhoZ2plSlqQkAwles4ZA6jIwduLDZ+NqH/12Rv3/nQ11uDX5KN/0+OoO1lZbfHFZK4CWbw/neJg59krdgX8CgcBh70zCjbxYQMcXfvoGU8sKcL7aggQBQbK0T/JT5ZSHkGhc0aPsYMAEoDj6Q+pOOXItS6QaVjNuVpLvju2A0X52Xqi+RUs3E1vRQ23XrJM04lQE4aFh0RQStcYBdRmtnrWKBVpOZz2ZJWgJKOgwrCsY0cAmjnTNLREejfGXYF1xhxhSD+R6P2ErcS1UNcbBiuUiM1d0ZgXeoIvFAyLJOWPWKX0L2niNPpcR846EzgAyQKZ50THStAMAgWYIw06A2pE=")
                .publicKey("MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAiQI6Hatcex7EMNTrCkzfqgxh5L2PhII4I8ziZhmS5GWKMRNs4hn1ojmjPWb5TqswffYJdSDyP1iNnJogGdUzzF0r75x4AbHweCi3RnCInhXMXZZqz7nBUZ5DsNatTSU+kvSZ1ysKbGMd0fxHZltC7WsHvem2XIXpo15+vTvxSBbqmOOY77zHmhWhzwz/trR/lzokn0NTjWxkLeAZraCYl37/8zSOccrfbOw1a3OVzXGYBLfYY8rmNP+E1LCRLkAox9CGkQMPsT00xlrV3qalozifjxi0K1SFpmVinp4jYEvn5ByOiyd7ekncW/N1cAR6Bz3QpbXgb7Stm/dHyQqMd4L0ZPrIhQGLwY5M/FjUzuW8BSdOdEfSw2ZE5ONuCccb8njgh/RGM/db8XFn/LRhfjjvp3vSzBPDg7wLDCfhx1LmL9bVq1HDx7mRUk+Y3cAVelmItdTwE3PM9Ccu7nZv/Ayxa8kyr7ozvfGn0BYKwNQZvvXX3/vwU0vqWvaDnRTjAgMBAAE=")
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
