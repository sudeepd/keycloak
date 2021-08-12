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

package org.keycloak.testsuite.client;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import javax.ws.rs.core.UriBuilder;

import org.apache.http.NameValuePair;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.message.BasicNameValuePair;
import org.junit.Before;
import org.junit.Test;
import org.keycloak.OAuth2Constants;
import org.keycloak.adapters.authentication.JWTClientCredentialsProvider;
import org.keycloak.client.registration.Auth;
import org.keycloak.common.util.KeycloakUriBuilder;
import org.keycloak.connections.infinispan.InfinispanConnectionProvider;
import org.keycloak.constants.ServiceUrlConstants;
import org.keycloak.jose.jwk.JSONWebKeySet;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.jose.jwk.JWKBuilder;
import org.keycloak.jose.jws.JWSBuilder;
import org.keycloak.keys.PublicKeyStorageUtils;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.protocol.oidc.OIDCLoginProtocolService;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.representations.idm.ClientInitialAccessCreatePresentation;
import org.keycloak.representations.idm.ClientInitialAccessPresentation;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.representations.oidc.OIDCClientRepresentation;
import org.keycloak.testsuite.Assert;
import org.keycloak.testsuite.arquillian.annotation.AuthServerContainerExclude;
import org.keycloak.testsuite.arquillian.annotation.AuthServerContainerExclude.AuthServer;
import org.keycloak.testsuite.client.resources.TestApplicationResourceUrls;
import org.keycloak.testsuite.client.resources.TestOIDCEndpointsApplicationResource;
import org.keycloak.testsuite.rest.resource.TestingOIDCEndpointsApplicationResource;
import org.keycloak.testsuite.util.OAuthClient;


/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
@AuthServerContainerExclude(AuthServer.REMOTE)
public class OIDCJwksClientRegistrationTest extends AbstractClientRegistrationTest {

    private static final String PRIVATE_KEY = "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";
    private static final String PUBLIC_KEY = "MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAiQI6Hatcex7EMNTrCkzfqgxh5L2PhII4I8ziZhmS5GWKMRNs4hn1ojmjPWb5TqswffYJdSDyP1iNnJogGdUzzF0r75x4AbHweCi3RnCInhXMXZZqz7nBUZ5DsNatTSU+kvSZ1ysKbGMd0fxHZltC7WsHvem2XIXpo15+vTvxSBbqmOOY77zHmhWhzwz/trR/lzokn0NTjWxkLeAZraCYl37/8zSOccrfbOw1a3OVzXGYBLfYY8rmNP+E1LCRLkAox9CGkQMPsT00xlrV3qalozifjxi0K1SFpmVinp4jYEvn5ByOiyd7ekncW/N1cAR6Bz3QpbXgb7Stm/dHyQqMd4L0ZPrIhQGLwY5M/FjUzuW8BSdOdEfSw2ZE5ONuCccb8njgh/RGM/db8XFn/LRhfjjvp3vSzBPDg7wLDCfhx1LmL9bVq1HDx7mRUk+Y3cAVelmItdTwE3PM9Ccu7nZv/Ayxa8kyr7ozvfGn0BYKwNQZvvXX3/vwU0vqWvaDnRTjAgMBAAE=";

    @Override
    public void addTestRealms(List<RealmRepresentation> testRealms) {
        super.addTestRealms(testRealms);
        testRealms.get(0).setPrivateKey(PRIVATE_KEY);
        testRealms.get(0).setPublicKey(PUBLIC_KEY);
    }

    @Before
    public void before() throws Exception {
        super.before();

        ClientInitialAccessPresentation token = adminClient.realm(REALM_NAME).clientInitialAccess().create(new ClientInitialAccessCreatePresentation(0, 10));
        reg.auth(Auth.token(token));
    }

    private OIDCClientRepresentation createRep() {
        OIDCClientRepresentation client = new OIDCClientRepresentation();
        client.setClientName("RegistrationAccessTokenTest");
        client.setClientUri(OAuthClient.APP_ROOT);
        client.setRedirectUris(Collections.singletonList(oauth.getRedirectUri()));
        return client;
    }


    @Test
    public void createClientWithJWKS_generatedKid() throws Exception {
        OIDCClientRepresentation clientRep = createRep();

        clientRep.setGrantTypes(Collections.singletonList(OAuth2Constants.CLIENT_CREDENTIALS));
        clientRep.setTokenEndpointAuthMethod(OIDCLoginProtocol.PRIVATE_KEY_JWT);

        // Generate keys for client
        TestOIDCEndpointsApplicationResource oidcClientEndpointsResource = testingClient.testApp().oidcClientEndpoints();
        Map<String, String> generatedKeys = oidcClientEndpointsResource.generateKeys("RS256");

        JSONWebKeySet keySet = oidcClientEndpointsResource.getJwks();
        clientRep.setJwks(keySet);

        OIDCClientRepresentation response = reg.oidc().create(clientRep);
        Assert.assertEquals(OIDCLoginProtocol.PRIVATE_KEY_JWT, response.getTokenEndpointAuthMethod());
        Assert.assertNull(response.getClientSecret());
        Assert.assertNull(response.getClientSecretExpiresAt());

        // Tries to authenticate client with privateKey JWT
        assertAuthenticateClientSuccess(generatedKeys, response, KEEP_GENERATED_KID);
    }


    // The "kid" is null in the signed JWT. This is backwards compatibility test as in versions prior to 2.3.0, the "kid" wasn't set by JWTClientCredentialsProvider
    @Test
    public void createClientWithJWKS_nullKid() throws Exception {
        OIDCClientRepresentation clientRep = createRep();

        clientRep.setGrantTypes(Collections.singletonList(OAuth2Constants.CLIENT_CREDENTIALS));
        clientRep.setTokenEndpointAuthMethod(OIDCLoginProtocol.PRIVATE_KEY_JWT);

        // Generate keys for client
        TestOIDCEndpointsApplicationResource oidcClientEndpointsResource = testingClient.testApp().oidcClientEndpoints();
        Map<String, String> generatedKeys = oidcClientEndpointsResource.generateKeys("RS256");

        JSONWebKeySet keySet = oidcClientEndpointsResource.getJwks();
        clientRep.setJwks(keySet);

        OIDCClientRepresentation response = reg.oidc().create(clientRep);

        // Tries to authenticate client with privateKey JWT
        assertAuthenticateClientSuccess(generatedKeys, response, null);
    }


    // The "kid" is set manually to some custom value
    @Test
    public void createClientWithJWKS_customKid() throws Exception {
        OIDCClientRepresentation response = createClientWithManuallySetKid("a1");

        Map<String, String> generatedKeys = testingClient.testApp().oidcClientEndpoints().getKeysAsPem();

        // Tries to authenticate client with privateKey JWT
        assertAuthenticateClientSuccess(generatedKeys, response, "a1");
    }


    private OIDCClientRepresentation createClientWithManuallySetKid(String kid) throws Exception {
        OIDCClientRepresentation clientRep = createRep();

        clientRep.setGrantTypes(Collections.singletonList(OAuth2Constants.CLIENT_CREDENTIALS));
        clientRep.setTokenEndpointAuthMethod(OIDCLoginProtocol.PRIVATE_KEY_JWT);

        // Generate keys for client
        TestOIDCEndpointsApplicationResource oidcClientEndpointsResource = testingClient.testApp().oidcClientEndpoints();
        oidcClientEndpointsResource.generateKeys("RS256");

        JSONWebKeySet keySet = oidcClientEndpointsResource.getJwks();

        // Override kid with custom value
        keySet.getKeys()[0].setKeyId(kid);
        clientRep.setJwks(keySet);

        return reg.oidc().create(clientRep);
    }


    @Test
    public void testTwoClientsWithSameKid() throws Exception {
        // Create client with manually set "kid"
        OIDCClientRepresentation response = createClientWithManuallySetKid("a1");


        // Create client2
        OIDCClientRepresentation clientRep2 = createRep();

        clientRep2.setGrantTypes(Collections.singletonList(OAuth2Constants.CLIENT_CREDENTIALS));
        clientRep2.setTokenEndpointAuthMethod(OIDCLoginProtocol.PRIVATE_KEY_JWT);

        // Generate some random keys for client2
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        PublicKey client2PublicKey = generator.generateKeyPair().getPublic();

        // Set client2 with manually set "kid" to be same like kid of client1 (but keys for both clients are different)
        JSONWebKeySet keySet = new JSONWebKeySet();
        keySet.setKeys(new JWK[]{JWKBuilder.create().kid("a1").rs256(client2PublicKey)});

        clientRep2.setJwks(keySet);
        clientRep2 = reg.oidc().create(clientRep2);


        // Authenticate client1
        Map<String, String> generatedKeys = testingClient.testApp().oidcClientEndpoints().getKeysAsPem();
        assertAuthenticateClientSuccess(generatedKeys, response, "a1");

        // Assert item in publicKey cache for client1
        String expectedCacheKey = PublicKeyStorageUtils.getClientModelCacheKey(REALM_NAME, response.getClientId());
        Assert.assertTrue(testingClient.testing().cache(InfinispanConnectionProvider.KEYS_CACHE_NAME).contains(expectedCacheKey));

        // Assert it's not possible to authenticate as client2 with the same "kid" like client1
        assertAuthenticateClientError(generatedKeys, clientRep2, "a1");
    }


    @Test
    public void testPublicKeyCacheInvalidatedWhenUpdatingClient() throws Exception {
        OIDCClientRepresentation response = createClientWithManuallySetKid("a1");

        Map<String, String> generatedKeys = testingClient.testApp().oidcClientEndpoints().getKeysAsPem();

        // Tries to authenticate client with privateKey JWT
        assertAuthenticateClientSuccess(generatedKeys, response, "a1");

        // Assert item in publicKey cache for client1
        String expectedCacheKey = PublicKeyStorageUtils.getClientModelCacheKey(REALM_NAME, response.getClientId());
        Assert.assertTrue(testingClient.testing().cache(InfinispanConnectionProvider.KEYS_CACHE_NAME).contains(expectedCacheKey));



        // Update client with some bad JWKS_URI
        response.setJwksUri("http://localhost:4321/non-existent");
        reg.auth(Auth.token(response.getRegistrationAccessToken()))
                .oidc().update(response);

        // Assert item not any longer for client1
        Assert.assertFalse(testingClient.testing().cache(InfinispanConnectionProvider.KEYS_CACHE_NAME).contains(expectedCacheKey));

        // Assert it's not possible to authenticate as client1
        assertAuthenticateClientError(generatedKeys, response, "a1");
    }


    @Test
    public void createClientWithJWKSURI() throws Exception {
        OIDCClientRepresentation clientRep = createRep();

        clientRep.setGrantTypes(Collections.singletonList(OAuth2Constants.CLIENT_CREDENTIALS));
        clientRep.setTokenEndpointAuthMethod(OIDCLoginProtocol.PRIVATE_KEY_JWT);

        // Generate keys for client
        TestOIDCEndpointsApplicationResource oidcClientEndpointsResource = testingClient.testApp().oidcClientEndpoints();
        Map<String, String> generatedKeys = oidcClientEndpointsResource.generateKeys("RS256");

        clientRep.setJwksUri(TestApplicationResourceUrls.clientJwksUri());

        OIDCClientRepresentation response = reg.oidc().create(clientRep);
        Assert.assertEquals(OIDCLoginProtocol.PRIVATE_KEY_JWT, response.getTokenEndpointAuthMethod());
        Assert.assertNull(response.getClientSecret());
        Assert.assertNull(response.getClientSecretExpiresAt());
        Assert.assertEquals(response.getJwksUri(), TestApplicationResourceUrls.clientJwksUri());

        // Tries to authenticate client with privateKey JWT
        assertAuthenticateClientSuccess(generatedKeys, response, KEEP_GENERATED_KID);
    }

    @Test
    public void createClientWithJWKSURI_rotateClientKeys() throws Exception {
        OIDCClientRepresentation clientRep = createRep();

        clientRep.setGrantTypes(Collections.singletonList(OAuth2Constants.CLIENT_CREDENTIALS));
        clientRep.setTokenEndpointAuthMethod(OIDCLoginProtocol.PRIVATE_KEY_JWT);

        // Generate keys for client
        TestOIDCEndpointsApplicationResource oidcClientEndpointsResource = testingClient.testApp().oidcClientEndpoints();
        Map<String, String> generatedKeys = oidcClientEndpointsResource.generateKeys("RS256");

        clientRep.setJwksUri(TestApplicationResourceUrls.clientJwksUri());

        OIDCClientRepresentation response = reg.oidc().create(clientRep);
        Assert.assertEquals(OIDCLoginProtocol.PRIVATE_KEY_JWT, response.getTokenEndpointAuthMethod());
        Assert.assertNull(response.getClientSecret());
        Assert.assertNull(response.getClientSecretExpiresAt());
        Assert.assertEquals(response.getJwksUri(), TestApplicationResourceUrls.clientJwksUri());

        // Tries to authenticate client with privateKey JWT
        assertAuthenticateClientSuccess(generatedKeys, response, KEEP_GENERATED_KID);

        // Add new key to the jwks
        Map<String, String> generatedKeys2 = oidcClientEndpointsResource.generateKeys("RS256");

        // Error should happen. KeyStorageProvider won't yet download new keys because of timeout
        assertAuthenticateClientError(generatedKeys2, response, KEEP_GENERATED_KID);

        setTimeOffset(20);

        // Now new keys should be successfully downloaded
        assertAuthenticateClientSuccess(generatedKeys2, response, KEEP_GENERATED_KID);
    }


    // Client auth with signedJWT - helper methods

    private void assertAuthenticateClientSuccess(Map<String, String> generatedKeys, OIDCClientRepresentation response, String kid) throws Exception {
        KeyPair keyPair = getKeyPairFromGeneratedPems(generatedKeys);
        String signedJwt = getClientSignedJWT(response.getClientId(), keyPair, kid);
        OAuthClient.AccessTokenResponse accessTokenResponse = doClientCredentialsGrantRequest(signedJwt);
        Assert.assertEquals(200, accessTokenResponse.getStatusCode());
        AccessToken accessToken = oauth.verifyToken(accessTokenResponse.getAccessToken());
        Assert.assertEquals(response.getClientId(), accessToken.getIssuedFor());
    }

    private void assertAuthenticateClientError(Map<String, String> generatedKeys, OIDCClientRepresentation response, String kid) throws Exception {
        KeyPair keyPair = getKeyPairFromGeneratedPems(generatedKeys);
        String signedJwt = getClientSignedJWT(response.getClientId(), keyPair, kid);
        OAuthClient.AccessTokenResponse accessTokenResponse = doClientCredentialsGrantRequest(signedJwt);
        Assert.assertEquals(400, accessTokenResponse.getStatusCode());
        Assert.assertNull(accessTokenResponse.getAccessToken());
        Assert.assertNotNull(accessTokenResponse.getError());
    }

    private KeyPair getKeyPairFromGeneratedPems(Map<String, String> generatedKeys) {
        String privateKeyPem = generatedKeys.get(TestingOIDCEndpointsApplicationResource.PRIVATE_KEY);
        String publicKeyPem =  generatedKeys.get(TestingOIDCEndpointsApplicationResource.PUBLIC_KEY);
        PrivateKey privateKey = KeycloakModelUtils.getPrivateKey(privateKeyPem);
        PublicKey publicKey = KeycloakModelUtils.getPublicKey(publicKeyPem);
        return new KeyPair(publicKey, privateKey);
    }

    private static final String KEEP_GENERATED_KID = "KEEP_GENERATED_KID";

    private String getClientSignedJWT(String clientId, KeyPair keyPair, final String kid) {
        String realmInfoUrl = KeycloakUriBuilder.fromUri(getAuthServerRoot()).path(ServiceUrlConstants.REALM_INFO_PATH).build(REALM_NAME).toString();

        // Use token-endpoint as audience as OIDC conformance testsuite is using it too.
        JWTClientCredentialsProvider jwtProvider = new JWTClientCredentialsProvider() {

            @Override
            public String createSignedRequestToken(String clientId, String realmInfoUrl) {
                if (KEEP_GENERATED_KID.equals(kid)) {
                    return super.createSignedRequestToken(clientId, realmInfoUrl);
                } else {
                    JsonWebToken jwt = createRequestToken(clientId, realmInfoUrl);
                    return new JWSBuilder()
                            .kid(kid)
                            .jsonContent(jwt)
                            .rsa256(keyPair.getPrivate());
                }
            }

            @Override
            protected JsonWebToken createRequestToken(String clientId, String realmInfoUrl) {
                JsonWebToken jwt = super.createRequestToken(clientId, realmInfoUrl);
                String tokenEndpointUrl = OIDCLoginProtocolService.tokenUrl(UriBuilder.fromUri(getAuthServerRoot())).build(REALM_NAME).toString();
                jwt.audience(tokenEndpointUrl);
                return jwt;
            }

        };
        jwtProvider.setupKeyPair(keyPair);
        jwtProvider.setTokenTimeout(10);
        return jwtProvider.createSignedRequestToken(clientId, realmInfoUrl);

    }


    private OAuthClient.AccessTokenResponse doClientCredentialsGrantRequest(String signedJwt) throws Exception {
        List<NameValuePair> parameters = new LinkedList<NameValuePair>();
        parameters.add(new BasicNameValuePair(OAuth2Constants.GRANT_TYPE, OAuth2Constants.CLIENT_CREDENTIALS));
        parameters.add(new BasicNameValuePair(OAuth2Constants.CLIENT_ASSERTION_TYPE, OAuth2Constants.CLIENT_ASSERTION_TYPE_JWT));
        parameters.add(new BasicNameValuePair(OAuth2Constants.CLIENT_ASSERTION, signedJwt));

        CloseableHttpResponse response = sendRequest(oauth.getServiceAccountUrl(), parameters);
        return new OAuthClient.AccessTokenResponse(response);
    }


    private CloseableHttpResponse sendRequest(String requestUrl, List<NameValuePair> parameters) throws Exception {
        CloseableHttpClient client = new DefaultHttpClient();
        try {
            HttpPost post = new HttpPost(requestUrl);
            UrlEncodedFormEntity formEntity = new UrlEncodedFormEntity(parameters, "UTF-8");
            post.setEntity(formEntity);
            return client.execute(post);
        } finally {
            oauth.closeClient(client);
        }
    }
}
