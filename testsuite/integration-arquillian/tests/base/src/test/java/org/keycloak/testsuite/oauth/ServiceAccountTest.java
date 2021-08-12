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

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.http.HttpResponse;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.hamcrest.Matchers;
import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.keycloak.admin.client.resource.UserResource;
import org.keycloak.authentication.authenticators.client.ClientIdAndSecretAuthenticator;
import org.keycloak.common.constants.ServiceAccountConstants;
import org.keycloak.crypto.Algorithm;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.events.EventType;
import org.keycloak.jose.jws.JWSHeader;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.protocol.oidc.OIDCConfigAttributes;
import org.keycloak.protocol.oidc.mappers.SHA256PairwiseSubMapper;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.RefreshToken;
import org.keycloak.representations.UserInfo;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.ProtocolMapperRepresentation;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.keycloak.testsuite.AbstractKeycloakTest;
import org.keycloak.testsuite.AssertEvents;
import org.keycloak.testsuite.admin.ApiUtil;
import org.keycloak.testsuite.util.ClientBuilder;
import org.keycloak.testsuite.util.ClientManager;
import org.keycloak.testsuite.util.OAuthClient;
import org.keycloak.testsuite.util.RealmBuilder;
import org.keycloak.testsuite.util.TokenSignatureUtil;
import org.keycloak.testsuite.util.UserBuilder;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.hasSize;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThat;

import javax.ws.rs.ClientErrorException;
import javax.ws.rs.core.Response;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class ServiceAccountTest extends AbstractKeycloakTest {

    private static String userId;
    private static String userName;

    @Rule
    public AssertEvents events = new AssertEvents(this);

    @Rule
    public ExpectedException expectedException = ExpectedException.none();


    @Override
    public void beforeAbstractKeycloakTest() throws Exception {
        super.beforeAbstractKeycloakTest();
    }

    @Override
    public void addTestRealms(List<RealmRepresentation> testRealms) {

        RealmBuilder realm = RealmBuilder.create().name("test")
                .privateKey("MIIG/QIBADANBgkqhkiG9w0BAQEFAASCBucwggbjAgEAAoIBgQCJAjodq1x7HsQw1OsKTN+qDGHkvY+EgjgjzOJmGZLkZYoxE2ziGfWiOaM9ZvlOqzB99gl1IPI/WI2cmiAZ1TPMXSvvnHgBsfB4KLdGcIieFcxdlmrPucFRnkOw1q1NJT6S9JnXKwpsYx3R/EdmW0Ltawe96bZchemjXn69O/FIFuqY45jvvMeaFaHPDP+2tH+XOiSfQ1ONbGQt4BmtoJiXfv/zNI5xyt9s7DVrc5XNcZgEt9hjyuY0/4TUsJEuQCjH0IaRAw+xPTTGWtXepqWjOJ+PGLQrVIWmZWKeniNgS+fkHI6LJ3t6Sdxb83VwBHoHPdClteBvtK2b90fJCox3gvRk+siFAYvBjkz8WNTO5bwFJ050R9LDZkTk424JxxvyeOCH9EYz91vxcWf8tGF+OO+ne9LME8ODvAsMJ+HHUuYv1tWrUcPHuZFST5jdwBV6WYi11PATc8z0Jy7udm/8DLFryTKvujO98afQFgrA1Bm+9dff+/BTS+pa9oOdFOMCAwEAAQKCAYBR10634mD/+sTfFpDAOmNwxKzFYqaUVOUMHZsvuh8Q58bAwgXMmg0stplYWGacI45377x+hwut40vUPAzo4X5rmUxheWoGOTCX1lqEbTxukj7duLhdFWzxQETXIaWr64+RYSN0cHVtgVeS08wizGkSQVkCjNUuN5/0wsGacHAUy/ufEHWO34mr9TgO4ojtrqx4vXaa3DDQzeqZrMAqA0CjXm2t7bsZJkKIYiEW6piVfEF+sANGuTECf4/tLPvMUO4rVBppW0vQnJJbwwmlS0+xDnc8xPnpkfLYF1sckFw1Q+obzpUkWJzZihJln/2ZsLjr4h7Wb1E0mOXX/Dh+Tk1/b6u/Ld4lIrReHfK6qNj/axOrVq7AOVM/p84wRCRQ2ubJQK3LWjIsjRgNnIhyAsSBUwkqvPJZUO8d858OthkU9LnmXKUrTnriqn4LUYjJekw0eHkPV8tv1JbhuERjbiP9dPVFp2ngQ3ZtRhZ0+UDA0y63QGesdbknMhuXfDE9wQECgcEAw/mOZvzetk3sX41irDOkYUpIbSD8hgvD2xThCexmeNF+/lULDn/EmGYt3NkcuNE2S0i93I+aaAqkPRijpCZ+eYwtP3vb/dADVbHMrOysTFzxT0hDv6cpZr3HOGiTdqwoqCBPkeAuLe+1nscbo2wTN3jCixJojE+NH1RJtzrIxvgIOKQhorlK/jr+LG+1fjPV2sUWTzbacTsTXhvn6GqOMBDARfORaPNBLycYaU3/KyH4Gd1PlwhRsmF9fNTPFJJhAoHBALL5HobzCWD/Uuog4dA/wbF6Jf0ISJDUicCTXnp9AANIS/g3MsyUdHSPPyx09cCMoGD9MMIZYWQQS4raPmBT52YdNUaMQWNuXVXLs+oQ+gbjltnmglRRBDm36Vy82DAUVb6ySp/dVkJ1KmzK2bYlPR3evNU5b4tQH8y6bmyrVwazBizUaOkazG4eVoety+qvBsq8F1Knbjr6qZbIMlyIFHdBREjGpR+p19i1PmzTXClNEC6ix6h36XVKWfjJhlO1wwKBwQCkibJ15XlXtrTuxNZDnlg1FxkYBsn+AYK/PhhzLHgcmEf3YY+W7M8y5Rc8hU0IHx9mtfwyYp9RGx4p7bX27BrkEj0rP+LEhxFFsbIWvd8rfh1cY1/+WWr5R/0r7yFgUcsQ3Y/w+jfLeacTWDhsTSEVQd6UxS/iHihuVWZO4JwR8c11QNi8trWwHfepd2D6RKsYssC4YWWmC+OG8AcVq+EVmfrUwFslspbX8Ase3s2OeUbE8HsSY3m0OwYQ+NukegECgcAhSsQJ+GWzPGuRD+LRmTqPqBgu9H6DKnYhc4hsopoBAk7XcnUppyfuksL+oxcf5UjkIdUTFiOOuJVE1AosYw81aJODdw2m0F3eWtEx5kyMQYPLLtzpkFSH5BUt4hcZAn9cxM+q40JrhF4K9MUA4/Z1evyHcXK1aIcxzzBBWLIMlfq9FhoZ2plSlqQkAwles4ZA6jIwduLDZ+NqH/12Rv3/nQ11uDX5KN/0+OoO1lZbfHFZK4CWbw/neJg59krdgX8CgcBh70zCjbxYQMcXfvoGU8sKcL7aggQBQbK0T/JT5ZSHkGhc0aPsYMAEoDj6Q+pOOXItS6QaVjNuVpLvju2A0X52Xqi+RUs3E1vRQ23XrJM04lQE4aFh0RQStcYBdRmtnrWKBVpOZz2ZJWgJKOgwrCsY0cAmjnTNLREejfGXYF1xhxhSD+R6P2ErcS1UNcbBiuUiM1d0ZgXeoIvFAyLJOWPWKX0L2niNPpcR846EzgAyQKZ50THStAMAgWYIw06A2pE=")
                .publicKey("MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAiQI6Hatcex7EMNTrCkzfqgxh5L2PhII4I8ziZhmS5GWKMRNs4hn1ojmjPWb5TqswffYJdSDyP1iNnJogGdUzzF0r75x4AbHweCi3RnCInhXMXZZqz7nBUZ5DsNatTSU+kvSZ1ysKbGMd0fxHZltC7WsHvem2XIXpo15+vTvxSBbqmOOY77zHmhWhzwz/trR/lzokn0NTjWxkLeAZraCYl37/8zSOccrfbOw1a3OVzXGYBLfYY8rmNP+E1LCRLkAox9CGkQMPsT00xlrV3qalozifjxi0K1SFpmVinp4jYEvn5ByOiyd7ekncW/N1cAR6Bz3QpbXgb7Stm/dHyQqMd4L0ZPrIhQGLwY5M/FjUzuW8BSdOdEfSw2ZE5ONuCccb8njgh/RGM/db8XFn/LRhfjjvp3vSzBPDg7wLDCfhx1LmL9bVq1HDx7mRUk+Y3cAVelmItdTwE3PM9Ccu7nZv/Ayxa8kyr7ozvfGn0BYKwNQZvvXX3/vwU0vqWvaDnRTjAgMBAAE=")
                .testEventListener();

        ClientRepresentation enabledApp = ClientBuilder.create()
                .id(KeycloakModelUtils.generateId())
                .clientId("service-account-cl-refresh-on")
                .secret("secret1")
                .serviceAccountsEnabled(true)
                .attribute(OIDCConfigAttributes.USE_REFRESH_TOKEN_FOR_CLIENT_CREDENTIALS_GRANT, "true")
                .build();

        realm.client(enabledApp);

        ClientRepresentation enabledAppWithSkipRefreshToken = ClientBuilder.create()
                .id(KeycloakModelUtils.generateId())
                .clientId("service-account-cl")
                .secret("secret1")
                .serviceAccountsEnabled(true)
                .build();

        realm.client(enabledAppWithSkipRefreshToken);

        ClientRepresentation disabledApp = ClientBuilder.create()
                .id(KeycloakModelUtils.generateId())
                .clientId("service-account-disabled")
                .secret("secret1")
                .build();

        realm.client(disabledApp);

        UserBuilder defaultUser = UserBuilder.create()
                .id(KeycloakModelUtils.generateId())
                .username("test-user@localhost");
        realm.user(defaultUser);

        userId = KeycloakModelUtils.generateId();
        userName = ServiceAccountConstants.SERVICE_ACCOUNT_USER_PREFIX + enabledApp.getClientId();

        UserBuilder serviceAccountUser = UserBuilder.create()
                .id(userId)
                .username(userName)
                .serviceAccountId(enabledApp.getClientId());
        realm.user(serviceAccountUser);

        testRealms.add(realm.build());
    }

    @Test
    public void clientCredentialsAuthSuccess() throws Exception {
        oauth.clientId("service-account-cl-refresh-on");

        OAuthClient.AccessTokenResponse response = oauth.doClientCredentialsGrantAccessTokenRequest("secret1");

        assertEquals(200, response.getStatusCode());

        // older clients which use client-credentials grant may create a refresh-token and session, see KEYCLOAK-9551.
        List<Map<String, String>> clientSessionStats = getAdminClient().realm(oauth.getRealm()).getClientSessionStats();
        assertThat(clientSessionStats, hasSize(1));
        Map<String, String> sessionStats = clientSessionStats.get(0);
        assertEquals(sessionStats.get("clientId"), oauth.getClientId());

        // Refresh token is for backwards compatibility only. It won't be in client credentials by default
        AccessToken accessToken = oauth.verifyToken(response.getAccessToken());
        RefreshToken refreshToken = oauth.parseRefreshToken(response.getRefreshToken());

        events.expectClientLogin()
                .client("service-account-cl-refresh-on")
                .user(userId)
                .session(accessToken.getSessionState())
                .detail(Details.TOKEN_ID, accessToken.getId())
                .detail(Details.REFRESH_TOKEN_ID, refreshToken.getId())
                .detail(Details.USERNAME, userName)
                .assertEvent();

        assertEquals(accessToken.getSessionState(), refreshToken.getSessionState());
        System.out.println("Access token other claims: " + accessToken.getOtherClaims());
        Assert.assertEquals("service-account-cl-refresh-on", accessToken.getOtherClaims().get(ServiceAccountConstants.CLIENT_ID));
        Assert.assertTrue(accessToken.getOtherClaims().containsKey(ServiceAccountConstants.CLIENT_ADDRESS));
        Assert.assertTrue(accessToken.getOtherClaims().containsKey(ServiceAccountConstants.CLIENT_HOST));

        OAuthClient.AccessTokenResponse refreshedResponse = oauth.doRefreshTokenRequest(response.getRefreshToken(), "secret1");

        AccessToken refreshedAccessToken = oauth.verifyToken(refreshedResponse.getAccessToken());
        RefreshToken refreshedRefreshToken = oauth.parseRefreshToken(refreshedResponse.getRefreshToken());

        assertEquals(accessToken.getSessionState(), refreshedAccessToken.getSessionState());
        assertEquals(accessToken.getSessionState(), refreshedRefreshToken.getSessionState());

        events.expectRefresh(refreshToken.getId(), refreshToken.getSessionState()).user(userId).client("service-account-cl-refresh-on").assertEvent();
    }

    // This is for the backwards compatibility only. By default, there won't be refresh token and hence there won't be availability for the logout
    @Test
    public void clientCredentialsLogout() throws Exception {
        oauth.clientId("service-account-cl-refresh-on");
        events.clear();

        OAuthClient.AccessTokenResponse response = oauth.doClientCredentialsGrantAccessTokenRequest("secret1");

        assertEquals(200, response.getStatusCode());

        AccessToken accessToken = oauth.verifyToken(response.getAccessToken());
        RefreshToken refreshToken = oauth.parseRefreshToken(response.getRefreshToken());

        events.expectClientLogin()
                .client("service-account-cl-refresh-on")
                .user(userId)
                .session(accessToken.getSessionState())
                .detail(Details.TOKEN_ID, accessToken.getId())
                .detail(Details.REFRESH_TOKEN_ID, refreshToken.getId())
                .detail(Details.USERNAME, userName)
                .detail(Details.CLIENT_AUTH_METHOD, ClientIdAndSecretAuthenticator.PROVIDER_ID)
                .assertEvent();

        HttpResponse logoutResponse = oauth.doLogout(response.getRefreshToken(), "secret1");
        assertEquals(204, logoutResponse.getStatusLine().getStatusCode());
        events.expectLogout(accessToken.getSessionState())
                .client("service-account-cl-refresh-on")
                .user(userId)
                .removeDetail(Details.REDIRECT_URI)
                .assertEvent();

        response = oauth.doRefreshTokenRequest(response.getRefreshToken(), "secret1");
        assertEquals(400, response.getStatusCode());
        assertEquals("invalid_grant", response.getError());

        events.expectRefresh(refreshToken.getId(), refreshToken.getSessionState())
                .client("service-account-cl-refresh-on")
                .user(userId)
                .removeDetail(Details.TOKEN_ID)
                .removeDetail(Details.UPDATED_REFRESH_TOKEN_ID)
                .error(Errors.INVALID_TOKEN).assertEvent();
    }

    @Test
    public void clientCredentialsInvalidClientCredentials() throws Exception {
        oauth.clientId("service-account-cl");

        OAuthClient.AccessTokenResponse response = oauth.doClientCredentialsGrantAccessTokenRequest("secret2");

        assertEquals(401, response.getStatusCode());

        assertEquals("unauthorized_client", response.getError());

        events.expectClientLogin()
                .client("service-account-cl")
                .session((String) null)
                .clearDetails()
                .error(Errors.INVALID_CLIENT_CREDENTIALS)
                .user((String) null)
                .assertEvent();
    }

    @Test
    public void clientCredentialsDisabledServiceAccount() throws Exception {
        oauth.clientId("service-account-disabled");

        OAuthClient.AccessTokenResponse response = oauth.doClientCredentialsGrantAccessTokenRequest("secret1");

        assertEquals(401, response.getStatusCode());

        assertEquals("unauthorized_client", response.getError());

        events.expectClientLogin()
                .client("service-account-disabled")
                .user((String) null)
                .session((String) null)
                .removeDetail(Details.USERNAME)
                .removeDetail(Details.RESPONSE_TYPE)
                .error(Errors.INVALID_CLIENT)
                .assertEvent();

    }

    @Test
    public void changeClientIdTest() throws Exception {

        ClientManager.realm(adminClient.realm("test")).clientId("service-account-cl-refresh-on").renameTo("updated-client");

        oauth.clientId("updated-client");

        OAuthClient.AccessTokenResponse response = oauth.doClientCredentialsGrantAccessTokenRequest("secret1");

        assertEquals(200, response.getStatusCode());

        AccessToken accessToken = oauth.verifyToken(response.getAccessToken());
        Assert.assertEquals("updated-client", accessToken.getOtherClaims().get(ServiceAccountConstants.CLIENT_ID));

        // Username updated after client ID changed
        events.expectClientLogin()
                .client("updated-client")
                .user(userId)
                .session(accessToken.getSessionState())
                .detail(Details.TOKEN_ID, accessToken.getId())
                .detail(Details.USERNAME, ServiceAccountConstants.SERVICE_ACCOUNT_USER_PREFIX + "updated-client")
                .assertEvent();


        ClientManager.realm(adminClient.realm("test")).clientId("updated-client").renameTo("service-account-cl-refresh-on");

    }

    @Test
    public void refreshTokenRefreshForDisabledServiceAccount() throws Exception {
        try {
            oauth.clientId("service-account-cl");
            OAuthClient.AccessTokenResponse response = oauth.doClientCredentialsGrantAccessTokenRequest("secret1");
            assertEquals(200, response.getStatusCode());

            ClientManager.realm(adminClient.realm("test")).clientId("service-account-cl").setServiceAccountsEnabled(false);

            response = oauth.doRefreshTokenRequest(response.getRefreshToken(), "secret1");
            assertEquals(400, response.getStatusCode());
        }
        finally {
            ClientManager.realm(adminClient.realm("test")).clientId("service-account-cl").setServiceAccountsEnabled(true);
            UserRepresentation user = ClientManager.realm(adminClient.realm("test")).clientId("service-account-cl").getServiceAccountUser();
        }
    }

    @Test
    public void clientCredentialsAuthRequest_ClientES256_RealmPS256() throws Exception {
    	conductClientCredentialsAuthRequestWithRefreshToken(Algorithm.HS256, Algorithm.ES256, Algorithm.PS256);
    }

    @Test
    public void failManagePassword() {
        UserResource serviceAccount = adminClient.realm("test").users().get(userId);
        UserRepresentation representation = serviceAccount.toRepresentation();

        CredentialRepresentation password = new CredentialRepresentation();
        password.setValue("password");
        password.setType(CredentialRepresentation.PASSWORD);
        password.setTemporary(false);

        representation.setCredentials(Arrays.asList(password));

        this.expectedException.expect(Matchers.allOf(Matchers.instanceOf(ClientErrorException.class), 
                Matchers.hasProperty("response", Matchers.hasProperty("status", Matchers.is(400)))));
        this.expectedException.reportMissingExceptionWithMessage("Should fail, should not be possible to manage credentials for service accounts");

        serviceAccount.update(representation);
    }
    
    /**
     * See KEYCLOAK-9551
     */
    @Test
    public void clientCredentialsAuthSuccessWithoutRefreshToken_revokeToken() throws Exception {
        String tokenString = clientCredentialsAuthSuccessWithoutRefreshTokenImpl();
        AccessToken accessToken = oauth.verifyToken(tokenString);

        // Revoke access token
        CloseableHttpResponse response1 = oauth.doTokenRevoke(tokenString, "access_token", "secret1");
        assertThat(response1, org.keycloak.testsuite.util.Matchers.statusCodeIsHC(Response.Status.OK));
        response1.close();

        events.expect(EventType.REVOKE_GRANT)
                .client("service-account-cl")
                .user(AssertEvents.isUUID())
                .session(Matchers.isEmptyOrNullString())
                .detail(Details.TOKEN_ID, accessToken.getId())
                .assertEvent();

        // Check that it is not possible to introspect token anymore
        Assert.assertFalse(getIntrospectionResponse("service-account-cl", "secret1", tokenString));
        // TODO: This would be better to be "INTROSPECT_TOKEN_ERROR"
        events.expect(EventType.INTROSPECT_TOKEN)
                .client("service-account-cl")
                .user(Matchers.isEmptyOrNullString())
                .session(Matchers.isEmptyOrNullString())
                .assertEvent();
    }

    @Test
    public void clientCredentialsAuthSuccessWithoutRefreshToken_pairWiseSubject() throws Exception {
        // Add pairwise protocolMapper through admin REST endpoint
        ProtocolMapperRepresentation pairwiseProtMapper = SHA256PairwiseSubMapper.createPairwiseMapper(null, null);
        ClientManager.realm(adminClient.realm("test")).clientId("service-account-cl")
                .addRedirectUris(oauth.getRedirectUri())
                .addProtocolMapper(pairwiseProtMapper);

        clientCredentialsAuthSuccessWithoutRefreshTokenImpl();

        ClientManager.realm(adminClient.realm("test")).clientId("service-account-cl").removeProtocolMapper(pairwiseProtMapper.getName());
    }

    // Returns accessToken string
    private String clientCredentialsAuthSuccessWithoutRefreshTokenImpl() throws Exception {
        oauth.clientId("service-account-cl");
        OAuthClient.AccessTokenResponse response = oauth.doClientCredentialsGrantAccessTokenRequest("secret1");

        assertEquals(200, response.getStatusCode());
        String tokenString = response.getAccessToken();

        Assert.assertNotNull("Access-Token should be present", tokenString);
        AccessToken accessToken = oauth.verifyToken(tokenString);
        Assert.assertNull(accessToken.getSessionState());
        Assert.assertNull("Refresh-Token should not be present", response.getRefreshToken());

        events.expectClientLogin()
                .client("service-account-cl")
                .user(AssertEvents.isUUID())
                .session(AssertEvents.isUUID())
                .detail(Details.TOKEN_ID, accessToken.getId())
                .detail(Details.USERNAME, ServiceAccountConstants.SERVICE_ACCOUNT_USER_PREFIX + "service-account-cl")
                .assertEvent();

        // new clients which use client-credentials grant should NOT create a refresh-token or session, see KEYCLOAK-9551.
        List<Map<String, String>> clientSessionStats = getAdminClient().realm(oauth.getRealm()).getClientSessionStats();
        assertThat(clientSessionStats, empty());

        // Check that token is possible to introspect
        Assert.assertTrue(getIntrospectionResponse("service-account-cl", "secret1", tokenString));
        events.expect(EventType.INTROSPECT_TOKEN)
                .client("service-account-cl")
                .user(AssertEvents.isUUID())
                .user(Matchers.isEmptyOrNullString())
                .session(Matchers.isEmptyOrNullString())
                .assertEvent();

        return tokenString;
    }

    private boolean getIntrospectionResponse(String clientId, String clientSecret, String tokenString) throws IOException {
        String introspectionResponse = oauth.introspectAccessTokenWithClientCredential(clientId, clientSecret, tokenString);
        ObjectMapper objectMapper = new ObjectMapper();
        JsonNode jsonNode = objectMapper.readTree(introspectionResponse);
        return jsonNode.get("active").asBoolean();
    }

    private void conductClientCredentialsAuthRequestWithRefreshToken(String expectedRefreshAlg, String expectedAccessAlg, String realmTokenAlg) throws Exception {
        try {
            /// Realm Setting is used for ID Token Signature Algorithm
            TokenSignatureUtil.changeRealmTokenSignatureProvider(adminClient, realmTokenAlg);
            TokenSignatureUtil.changeClientAccessTokenSignatureProvider(ApiUtil.findClientByClientId(adminClient.realm("test"), "service-account-cl-refresh-on"), expectedAccessAlg);
            clientCredentialsAuthSuccessWithRefreshToken(expectedRefreshAlg, expectedAccessAlg);
        } finally {
            TokenSignatureUtil.changeRealmTokenSignatureProvider(adminClient, Algorithm.RS256);
            TokenSignatureUtil.changeClientAccessTokenSignatureProvider(ApiUtil.findClientByClientId(adminClient.realm("test"), "service-account-cl-refresh-on"), Algorithm.RS256);
        }
        return;
    }

    // Testing of refresh token is for backwards compatibility. By default, there won't be refresh token for the client credentials grant
    private void clientCredentialsAuthSuccessWithRefreshToken(String expectedRefreshAlg, String expectedAccessAlg) throws Exception {
        oauth.clientId("service-account-cl-refresh-on");

        OAuthClient.AccessTokenResponse response = oauth.doClientCredentialsGrantAccessTokenRequest("secret1");

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

        events.expectClientLogin()
                .client("service-account-cl-refresh-on")
                .user(userId)
                .session(accessToken.getSessionState())
                .detail(Details.TOKEN_ID, accessToken.getId())
                .detail(Details.REFRESH_TOKEN_ID, refreshToken.getId())
                .detail(Details.USERNAME, userName)
                .assertEvent();

        assertEquals(accessToken.getSessionState(), refreshToken.getSessionState());
        System.out.println("Access token other claims: " + accessToken.getOtherClaims());
        Assert.assertEquals("service-account-cl-refresh-on", accessToken.getOtherClaims().get(ServiceAccountConstants.CLIENT_ID));
        Assert.assertTrue(accessToken.getOtherClaims().containsKey(ServiceAccountConstants.CLIENT_ADDRESS));
        Assert.assertTrue(accessToken.getOtherClaims().containsKey(ServiceAccountConstants.CLIENT_HOST));

        OAuthClient.AccessTokenResponse refreshedResponse = oauth.doRefreshTokenRequest(response.getRefreshToken(), "secret1");

        AccessToken refreshedAccessToken = oauth.verifyToken(refreshedResponse.getAccessToken());
        RefreshToken refreshedRefreshToken = oauth.parseRefreshToken(refreshedResponse.getRefreshToken());

        assertEquals(accessToken.getSessionState(), refreshedAccessToken.getSessionState());
        assertEquals(accessToken.getSessionState(), refreshedRefreshToken.getSessionState());

        events.expectRefresh(refreshToken.getId(), refreshToken.getSessionState()).user(userId).client("service-account-cl-refresh-on").assertEvent();
    }

    @Test
    public void userInfoForServiceAccountWithoutRefreshTokenImpl() throws Exception {
        oauth.clientId("service-account-cl");
        OAuthClient.AccessTokenResponse response = oauth.doClientCredentialsGrantAccessTokenRequest("secret1");
        assertEquals(200, response.getStatusCode());
        assertNull(response.getRefreshToken());

        UserInfo info = oauth.doUserInfoRequest(response.getAccessToken());
        assertEquals(200, response.getStatusCode());
        assertEquals("service-account-service-account-cl", info.getPreferredUsername());
    }

    @Test
    public void userInfoForServiceAccountWithRefreshTokenImpl() throws Exception {
        oauth.clientId("service-account-cl-refresh-on");
        OAuthClient.AccessTokenResponse response = oauth.doClientCredentialsGrantAccessTokenRequest("secret1");
        assertEquals(200, response.getStatusCode());
        assertNotNull(response.getRefreshToken());

        UserInfo info = oauth.doUserInfoRequest(response.getAccessToken());
        assertEquals(200, response.getStatusCode());
        assertEquals("service-account-service-account-cl-refresh-on", info.getPreferredUsername());

        HttpResponse logoutResponse = oauth.doLogout(response.getRefreshToken(), "secret1");
        assertEquals(204, logoutResponse.getStatusLine().getStatusCode());
    }
}
