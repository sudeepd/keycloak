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
    private static final String PUBLIC_KEY = "MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAs2njo0TT4UkMcp2Cq+6wcyEVZsyLJ+3bIG5pBPwzik3jUEPG3r7SlPJyx/x6wXUNDvI/x4Q7CKEh6Xm1oLXGStyHQWiFX9VuyTe4aR5VMWC6maezK2YsWVkXY0OGCi96J85qWHRGnIloaCKXr0vfyVsGmrAwnCmRj/aUiQTwZB54lQt0t9wgrT944vvCVoyAiThmIlMNdL87LNwjj5t50kKmPccCl7bjo4IvakDMhpJbvJbz7WWldoBWa7hlU8EmGpUhB3Q2pNqnUQBVKeYu67kfA9uLto6XK/UTpwVcIugveS5v8f/5ZhWM6oGNfam8JiJhD7zP3GYfSTpcYGDKrLnqdE7+bOxzYSXVqTS0dO2J20qr0J2qnykI+y/dpCiZDlhq0AChe142QkxA9zDbSmH89Oy6oJvdBnycSTNv2EzameRakxZyDI3Jc2zrc9e/76i3HPO1RK6ZItieEqg4sa/RUGbO3eaq8rdKUwrxGLuxighO11uZ5KcdOhW9PixFAgMBAAE=";

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
