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


import org.junit.Before;
import org.junit.Test;
import org.keycloak.OAuth2Constants;
import org.keycloak.admin.client.resource.ClientResource;
import org.keycloak.admin.client.resource.ClientsResource;
import org.keycloak.authentication.authenticators.client.X509ClientAuthenticator;
import org.keycloak.client.registration.Auth;
import org.keycloak.client.registration.ClientRegistrationException;
import org.keycloak.client.registration.HttpErrorException;
import org.keycloak.common.util.CollectionUtil;
import org.keycloak.events.Errors;
import org.keycloak.jose.jwe.JWEConstants;
import org.keycloak.jose.jws.Algorithm;
import org.keycloak.models.CibaConfig;
import org.keycloak.protocol.oidc.OIDCAdvancedConfigWrapper;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.protocol.oidc.utils.OIDCResponseType;
import org.keycloak.representations.idm.ClientInitialAccessCreatePresentation;
import org.keycloak.representations.idm.ClientInitialAccessPresentation;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;
import org.keycloak.representations.oidc.OIDCClientRepresentation;
import org.keycloak.testsuite.Assert;
import org.keycloak.testsuite.admin.ApiUtil;
import org.keycloak.testsuite.util.KeycloakModelUtils;

import java.util.*;
import java.util.stream.Collectors;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.keycloak.testsuite.auth.page.AuthRealm.TEST;

/**
 * @author <a href="mailto:sthorger@redhat.com">Stian Thorgersen</a>
 */
public class OIDCClientRegistrationTest extends AbstractClientRegistrationTest {

    private static final String PRIVATE_KEY = "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";
    private static final String PUBLIC_KEY = "MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAs2njo0TT4UkMcp2Cq+6wcyEVZsyLJ+3bIG5pBPwzik3jUEPG3r7SlPJyx/x6wXUNDvI/x4Q7CKEh6Xm1oLXGStyHQWiFX9VuyTe4aR5VMWC6maezK2YsWVkXY0OGCi96J85qWHRGnIloaCKXr0vfyVsGmrAwnCmRj/aUiQTwZB54lQt0t9wgrT944vvCVoyAiThmIlMNdL87LNwjj5t50kKmPccCl7bjo4IvakDMhpJbvJbz7WWldoBWa7hlU8EmGpUhB3Q2pNqnUQBVKeYu67kfA9uLto6XK/UTpwVcIugveS5v8f/5ZhWM6oGNfam8JiJhD7zP3GYfSTpcYGDKrLnqdE7+bOxzYSXVqTS0dO2J20qr0J2qnykI+y/dpCiZDlhq0AChe142QkxA9zDbSmH89Oy6oJvdBnycSTNv2EzameRakxZyDI3Jc2zrc9e/76i3HPO1RK6ZItieEqg4sa/RUGbO3eaq8rdKUwrxGLuxighO11uZ5KcdOhW9PixFAgMBAAE=";
    private static final String ERR_MSG_CLIENT_REG_FAIL = "Failed to send request";

    @Override
    public void addTestRealms(List<RealmRepresentation> testRealms) {
        super.addTestRealms(testRealms);
        RealmRepresentation testRealm = testRealms.get(0);
        testRealm.setPrivateKey(PRIVATE_KEY);
        testRealm.setPublicKey(PUBLIC_KEY);

        ClientRepresentation samlApp = KeycloakModelUtils.createClient(testRealm, "saml-client");
        samlApp.setSecret("secret");
        samlApp.setServiceAccountsEnabled(true);
        samlApp.setDirectAccessGrantsEnabled(true);
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
        client.setClientUri("http://root");
        client.setRedirectUris(Collections.singletonList("http://redirect"));
        return client;
    }

    public OIDCClientRepresentation create() throws ClientRegistrationException {
        OIDCClientRepresentation client = createRep();

        OIDCClientRepresentation response = reg.oidc().create(client);

        return response;
    }

    private void assertCreateFail(OIDCClientRepresentation client, int expectedStatusCode) {
        assertCreateFail(client, expectedStatusCode, null);
    }

    private void assertCreateFail(OIDCClientRepresentation client, int expectedStatusCode, String expectedErrorContains) {
        try {
            reg.oidc().create(client);
            Assert.fail("Not expected to successfuly register client");
        } catch (ClientRegistrationException expected) {
            HttpErrorException httpEx = (HttpErrorException) expected.getCause();
            Assert.assertEquals(expectedStatusCode, httpEx.getStatusLine().getStatusCode());
            if (expectedErrorContains != null) {
                assertTrue("Error response doesn't contain expected text", httpEx.getErrorResponse().contains(expectedErrorContains));
            }
        }
    }

    private void assertGetFail(String clientId, int expectedStatusCode, String expectedErrorContains) {
        try {
            reg.oidc().get(clientId);
            Assert.fail("Not expected to successfully get client");
        } catch (ClientRegistrationException expected) {
            HttpErrorException httpEx = (HttpErrorException) expected.getCause();
            Assert.assertEquals(expectedStatusCode, httpEx.getStatusLine().getStatusCode());
            if (expectedErrorContains != null) {
                assertTrue("Error response doesn't contain expected text", httpEx.getErrorResponse().contains(expectedErrorContains));
            }
        }
    }

    // KEYCLOAK-3421
    @Test
    public void createClientWithUriFragment() {
        OIDCClientRepresentation client = createRep();
        client.setRedirectUris(Arrays.asList("http://localhost/auth", "http://localhost/auth#fragment", "http://localhost/auth*"));

        assertCreateFail(client, 400, "URI fragment");
    }

    @Test
    public void createClient() throws ClientRegistrationException {
        OIDCClientRepresentation response = create();

        assertNotNull(response.getRegistrationAccessToken());
        assertNotNull(response.getClientIdIssuedAt());
        assertNotNull(response.getClientId());
        assertNotNull(response.getClientSecret());
        assertEquals(0, response.getClientSecretExpiresAt().intValue());
        assertNotNull(response.getRegistrationClientUri());
        assertEquals("RegistrationAccessTokenTest", response.getClientName());
        assertEquals("http://root", response.getClientUri());
        assertEquals(1, response.getRedirectUris().size());
        assertEquals("http://redirect", response.getRedirectUris().get(0));
        assertEquals(Arrays.asList("code", "none"), response.getResponseTypes());
        assertEquals(Arrays.asList(OAuth2Constants.AUTHORIZATION_CODE, OAuth2Constants.REFRESH_TOKEN), response.getGrantTypes());
        assertEquals(OIDCLoginProtocol.CLIENT_SECRET_BASIC, response.getTokenEndpointAuthMethod());
        Assert.assertNull(response.getUserinfoSignedResponseAlg());
    }

    @Test
    public void getClient() throws ClientRegistrationException {
        OIDCClientRepresentation response = create();
        reg.auth(Auth.token(response));

        OIDCClientRepresentation rep = reg.oidc().get(response.getClientId());
        assertNotNull(rep);
        assertEquals(response.getRegistrationAccessToken(), rep.getRegistrationAccessToken());
        assertTrue(CollectionUtil.collectionEquals(Arrays.asList("code", "none"), response.getResponseTypes()));
        assertTrue(CollectionUtil.collectionEquals(Arrays.asList(OAuth2Constants.AUTHORIZATION_CODE, OAuth2Constants.REFRESH_TOKEN), response.getGrantTypes()));
        assertNotNull(response.getClientSecret());
        assertEquals(0, response.getClientSecretExpiresAt().intValue());
        assertEquals(OIDCLoginProtocol.CLIENT_SECRET_BASIC, response.getTokenEndpointAuthMethod());
    }

    @Test
    public void updateClient() throws ClientRegistrationException {
        OIDCClientRepresentation response = create();
        reg.auth(Auth.token(response));

        response.setRedirectUris(Collections.singletonList("http://newredirect"));
        response.setResponseTypes(Arrays.asList("code", "id_token token", "code id_token token"));
        response.setGrantTypes(Arrays.asList(OAuth2Constants.AUTHORIZATION_CODE, OAuth2Constants.REFRESH_TOKEN, OAuth2Constants.PASSWORD));

        OIDCClientRepresentation updated = reg.oidc().update(response);

        assertTrue(CollectionUtil.collectionEquals(Collections.singletonList("http://newredirect"), updated.getRedirectUris()));
        assertTrue(CollectionUtil.collectionEquals(Arrays.asList(OAuth2Constants.AUTHORIZATION_CODE, OAuth2Constants.IMPLICIT, OAuth2Constants.REFRESH_TOKEN, OAuth2Constants.PASSWORD), updated.getGrantTypes()));
        assertTrue(CollectionUtil.collectionEquals(Arrays.asList(OAuth2Constants.CODE, OIDCResponseType.NONE, OIDCResponseType.ID_TOKEN, "id_token token", "code id_token", "code token", "code id_token token"), updated.getResponseTypes()));
    }

    @Test
    public void updateClientError() throws ClientRegistrationException {
        try {
            OIDCClientRepresentation response = create();
            reg.auth(Auth.token(response));
            response.setResponseTypes(Arrays.asList("code", "tokenn"));
            reg.oidc().update(response);
            fail("Not expected to end with success");
        } catch (ClientRegistrationException cre) {
        }
    }

    @Test
    public void deleteClient() throws ClientRegistrationException {
        OIDCClientRepresentation response = create();
        reg.auth(Auth.token(response));

        reg.oidc().delete(response);
    }

    @Test
    public void testSignaturesRequired() throws Exception {
        OIDCClientRepresentation clientRep = null;
        OIDCClientRepresentation response = null;
        try {
            clientRep = createRep();
            clientRep.setUserinfoSignedResponseAlg(Algorithm.ES256.toString());
            clientRep.setRequestObjectSigningAlg(Algorithm.ES256.toString());

            response = reg.oidc().create(clientRep);
            Assert.assertEquals(Algorithm.ES256.toString(), response.getUserinfoSignedResponseAlg());
            Assert.assertEquals(Algorithm.ES256.toString(), response.getRequestObjectSigningAlg());
            Assert.assertNotNull(response.getClientSecret());

            // Test Keycloak representation
            ClientRepresentation kcClient = getClient(response.getClientId());
            OIDCAdvancedConfigWrapper config = OIDCAdvancedConfigWrapper.fromClientRepresentation(kcClient);
            Assert.assertEquals(config.getUserInfoSignedResponseAlg(), Algorithm.ES256);
            Assert.assertEquals(config.getRequestObjectSignatureAlg(), Algorithm.ES256);

            // update (ES256 to PS256)
            clientRep.setUserinfoSignedResponseAlg(Algorithm.PS256.toString());
            clientRep.setRequestObjectSigningAlg(Algorithm.PS256.toString());
            response = reg.oidc().create(clientRep);
            Assert.assertEquals(Algorithm.PS256.toString(), response.getUserinfoSignedResponseAlg());
            Assert.assertEquals(Algorithm.PS256.toString(), response.getRequestObjectSigningAlg());

            // keycloak representation
            kcClient = getClient(response.getClientId());
            config = OIDCAdvancedConfigWrapper.fromClientRepresentation(kcClient);
            Assert.assertEquals(config.getUserInfoSignedResponseAlg(), Algorithm.PS256);
            Assert.assertEquals(config.getRequestObjectSignatureAlg(), Algorithm.PS256);
        } finally {
            // back to RS256 for other tests
            clientRep.setUserinfoSignedResponseAlg(Algorithm.RS256.toString());
            clientRep.setRequestObjectSigningAlg(Algorithm.RS256.toString());
            response = reg.oidc().create(clientRep);
        }
    }

    @Test
    public void createClientImplicitFlow() throws ClientRegistrationException {
        OIDCClientRepresentation clientRep = createRep();

        clientRep.setResponseTypes(Arrays.asList("id_token token"));
        OIDCClientRepresentation response = reg.oidc().create(clientRep);

        String clientId = response.getClientId();
        ClientRepresentation kcClientRep = getKeycloakClient(clientId);
        Assert.assertFalse(kcClientRep.isPublicClient());
        Assert.assertNull(kcClientRep.getSecret());
    }

    @Test
    public void createPublicClient() throws ClientRegistrationException {
        OIDCClientRepresentation clientRep = createRep();

        clientRep.setTokenEndpointAuthMethod("none");
        OIDCClientRepresentation response = reg.oidc().create(clientRep);
        Assert.assertEquals("none", response.getTokenEndpointAuthMethod());

        String clientId = response.getClientId();
        ClientRepresentation kcClientRep = getKeycloakClient(clientId);
        Assert.assertTrue(kcClientRep.isPublicClient());
        Assert.assertNull(kcClientRep.getSecret());
    }

    // KEYCLOAK-6771 Certificate Bound Token
    // https://tools.ietf.org/html/draft-ietf-oauth-mtls-08#section-6.5
    @Test
    public void testMtlsHoKTokenEnabled() throws Exception {
        // create (no specification)
        OIDCClientRepresentation clientRep = createRep();

        OIDCClientRepresentation response = reg.oidc().create(clientRep);
        Assert.assertEquals(Boolean.FALSE, response.getTlsClientCertificateBoundAccessTokens());
        Assert.assertNotNull(response.getClientSecret());

        // Test Keycloak representation
        ClientRepresentation kcClient = getClient(response.getClientId());
        OIDCAdvancedConfigWrapper config = OIDCAdvancedConfigWrapper.fromClientRepresentation(kcClient);
        assertTrue(!config.isUseMtlsHokToken());

        // update (true)
        reg.auth(Auth.token(response));
        response.setTlsClientCertificateBoundAccessTokens(Boolean.TRUE);
        OIDCClientRepresentation updated = reg.oidc().update(response);
        assertTrue(updated.getTlsClientCertificateBoundAccessTokens().booleanValue());

        // Test Keycloak representation
        kcClient = getClient(updated.getClientId());
        config = OIDCAdvancedConfigWrapper.fromClientRepresentation(kcClient);
        assertTrue(config.isUseMtlsHokToken());

        // update (false)
        reg.auth(Auth.token(updated));
        updated.setTlsClientCertificateBoundAccessTokens(Boolean.FALSE);
        OIDCClientRepresentation reUpdated = reg.oidc().update(updated);
        assertTrue(!reUpdated.getTlsClientCertificateBoundAccessTokens().booleanValue());

        // Test Keycloak representation
        kcClient = getClient(reUpdated.getClientId());
        config = OIDCAdvancedConfigWrapper.fromClientRepresentation(kcClient);
        assertTrue(!config.isUseMtlsHokToken());

    }

    @Test
    public void testIdTokenEncryptedResponse() throws Exception {
        OIDCClientRepresentation response = null;
        OIDCClientRepresentation updated = null;
        try {
             // create (no specification)
             OIDCClientRepresentation clientRep = createRep();

             response = reg.oidc().create(clientRep);
             Assert.assertEquals(Boolean.FALSE, response.getTlsClientCertificateBoundAccessTokens());
             Assert.assertNotNull(response.getClientSecret());

             // Test Keycloak representation
             ClientRepresentation kcClient = getClient(response.getClientId());
             OIDCAdvancedConfigWrapper config = OIDCAdvancedConfigWrapper.fromClientRepresentation(kcClient);
             Assert.assertNull(config.getIdTokenEncryptedResponseAlg());
             Assert.assertNull(config.getIdTokenEncryptedResponseEnc());

             // update (alg RSA1_5, enc A128CBC-HS256)
             reg.auth(Auth.token(response));
             response.setIdTokenEncryptedResponseAlg(JWEConstants.RSA1_5);
             response.setIdTokenEncryptedResponseEnc(JWEConstants.A128CBC_HS256);
             updated = reg.oidc().update(response);
             Assert.assertEquals(JWEConstants.RSA1_5, updated.getIdTokenEncryptedResponseAlg());
             Assert.assertEquals(JWEConstants.A128CBC_HS256, updated.getIdTokenEncryptedResponseEnc());

             // Test Keycloak representation
             kcClient = getClient(updated.getClientId());
             config = OIDCAdvancedConfigWrapper.fromClientRepresentation(kcClient);
             Assert.assertEquals(JWEConstants.RSA1_5, config.getIdTokenEncryptedResponseAlg());
             Assert.assertEquals(JWEConstants.A128CBC_HS256, config.getIdTokenEncryptedResponseEnc());

        } finally {
            // revert
            reg.auth(Auth.token(updated));
            updated.setIdTokenEncryptedResponseAlg(null);
            updated.setIdTokenEncryptedResponseEnc(null);
            reg.oidc().update(updated);
        }
    }

    @Test
    public void testTokenEndpointSigningAlg() throws Exception {
        OIDCClientRepresentation response = null;
        OIDCClientRepresentation updated = null;
        try {
            OIDCClientRepresentation clientRep = createRep();
            clientRep.setTokenEndpointAuthSigningAlg(Algorithm.ES256.toString());

            response = reg.oidc().create(clientRep);
            Assert.assertEquals(Algorithm.ES256.toString(), response.getTokenEndpointAuthSigningAlg());

            ClientRepresentation kcClient = getClient(response.getClientId());
            OIDCAdvancedConfigWrapper config = OIDCAdvancedConfigWrapper.fromClientRepresentation(kcClient);
            Assert.assertEquals(Algorithm.ES256.toString(), config.getTokenEndpointAuthSigningAlg());

            reg.auth(Auth.token(response));
            response.setTokenEndpointAuthSigningAlg(null);
            updated = reg.oidc().update(response);
            Assert.assertEquals(null, response.getTokenEndpointAuthSigningAlg());

            kcClient = getClient(updated.getClientId());
            config = OIDCAdvancedConfigWrapper.fromClientRepresentation(kcClient);
            Assert.assertEquals(null, config.getTokenEndpointAuthSigningAlg());
        } finally {
            // revert
            reg.auth(Auth.token(updated));
            updated.setTokenEndpointAuthSigningAlg(null);
            reg.oidc().update(updated);
        }
    }

    @Test
    public void testCIBASettings() throws Exception {
        OIDCClientRepresentation clientRep = null;
        OIDCClientRepresentation response = null;
        clientRep = createRep();
        clientRep.setBackchannelTokenDeliveryMode("poll");

        response = reg.oidc().create(clientRep);
        Assert.assertEquals("poll", response.getBackchannelTokenDeliveryMode());

        // Test Keycloak representation
        ClientRepresentation kcClient = getClient(response.getClientId());
        Assert.assertEquals("poll", kcClient.getAttributes().get(CibaConfig.CIBA_BACKCHANNEL_TOKEN_DELIVERY_MODE_PER_CLIENT));

        // update
        clientRep.setBackchannelTokenDeliveryMode("ping");
        try {
            reg.oidc().create(clientRep);
            fail();
        } catch (ClientRegistrationException e) {
            assertEquals(ERR_MSG_CLIENT_REG_FAIL, e.getMessage());
        }
    }

    @Test
    public void testOIDCEndpointCreateWithSamlClient() throws Exception {
        ClientsResource clientsResource = adminClient.realm(TEST).clients();
        ClientRepresentation samlClient = clientsResource.findByClientId("saml-client").get(0);
        String samlClientServiceId = clientsResource.get(samlClient.getId()).getServiceAccountUser().getId();

        String realmManagementId = clientsResource.findByClientId("realm-management").get(0).getId();
        RoleRepresentation role = clientsResource.get(realmManagementId).roles().get("create-client").toRepresentation();

        adminClient.realm(TEST).users().get(samlClientServiceId).roles().clientLevel(realmManagementId).add(Arrays.asList(role));

        String accessToken = oauth.clientId("saml-client").doClientCredentialsGrantAccessTokenRequest("secret").getAccessToken();
        reg.auth(Auth.token(accessToken));

        // change client to saml
        samlClient.setProtocol("saml");
        clientsResource.get(samlClient.getId()).update(samlClient);

        OIDCClientRepresentation client = createRep();
        assertCreateFail(client, 400, Errors.INVALID_CLIENT);

        // revert client
        samlClient.setProtocol("openid-connect");
        clientsResource.get(samlClient.getId()).update(samlClient);
    }

    @Test
    public void testOIDCEndpointGetWithSamlClient() throws Exception {
        OIDCClientRepresentation response = create();
        reg.auth(Auth.token(response));
        assertNotNull(reg.oidc().get(response.getClientId()));
        ClientsResource clientsResource = adminClient.realm(TEST).clients();
        ClientRepresentation client = clientsResource.findByClientId(response.getClientId()).get(0);

        // change client to saml
        client.setProtocol("saml");
        clientsResource.get(client.getId()).update(client);

        assertGetFail(client.getClientId(), 400, Errors.INVALID_CLIENT);
    }

    @Test
    public void testOIDCEndpointGetWithToken() throws Exception {
        OIDCClientRepresentation response = create();
        reg.auth(Auth.token(response));
        assertNotNull(reg.oidc().get(response.getClientId()));
    }

    @Test
    public void testOIDCEndpointGetWithoutToken() throws Exception {
        assertGetFail(create().getClientId(), 401, null);
    }

    @Test
    public void testTlsClientAuthSubjectDn() throws Exception {
        OIDCClientRepresentation response = null;
        OIDCClientRepresentation updated = null;
        try {
             // create (no specification)
             OIDCClientRepresentation clientRep = createRep();
             clientRep.setTokenEndpointAuthMethod(OIDCLoginProtocol.TLS_CLIENT_AUTH);
             clientRep.setTlsClientAuthSubjectDn("Ein");

             response = reg.oidc().create(clientRep);
             Assert.assertEquals(OIDCLoginProtocol.TLS_CLIENT_AUTH, response.getTokenEndpointAuthMethod());
             Assert.assertEquals("Ein", response.getTlsClientAuthSubjectDn());

             // Test Keycloak representation
             ClientRepresentation kcClient = getClient(response.getClientId());
             OIDCAdvancedConfigWrapper config = OIDCAdvancedConfigWrapper.fromClientRepresentation(kcClient);
             Assert.assertEquals(X509ClientAuthenticator.PROVIDER_ID, kcClient.getClientAuthenticatorType());
             Assert.assertEquals("Ein", config.getTlsClientAuthSubjectDn());

             // update
             reg.auth(Auth.token(response));
             response.setTlsClientAuthSubjectDn("(.*?)(?:$)");
             updated = reg.oidc().update(response);
             Assert.assertEquals(OIDCLoginProtocol.TLS_CLIENT_AUTH, updated.getTokenEndpointAuthMethod());
             Assert.assertEquals("(.*?)(?:$)", updated.getTlsClientAuthSubjectDn());

             // Test Keycloak representation
             kcClient = getClient(updated.getClientId());
             config = OIDCAdvancedConfigWrapper.fromClientRepresentation(kcClient);
             Assert.assertEquals(X509ClientAuthenticator.PROVIDER_ID, kcClient.getClientAuthenticatorType());
             Assert.assertEquals("(.*?)(?:$)", config.getTlsClientAuthSubjectDn());
        } finally {
            // revert
            reg.auth(Auth.token(updated));
            updated.setTokenEndpointAuthMethod(null);
            updated.setTlsClientAuthSubjectDn(null);
            reg.oidc().update(updated);
        }
    }

    private ClientRepresentation getKeycloakClient(String clientId) {
        return ApiUtil.findClientByClientId(adminClient.realms().realm(REALM_NAME), clientId).toRepresentation();
    }

    @Test
    public void testClientWithScope() throws Exception {
        OIDCClientRepresentation clientRep = null;
        OIDCClientRepresentation response = null;
        String clientScope = "phone address";

        clientRep = createRep();
        clientRep.setScope(clientScope);
        response = reg.oidc().create(clientRep);

        Set<String> clientScopes = new HashSet<>(Arrays.asList(clientScope.split(" ")));
        Set<String> registeredClientScopes = new HashSet<>(Arrays.asList(response.getScope().split(" ")));
        assertTrue(clientScopes.equals(registeredClientScopes));

        ClientResource clientResource = adminClient.realm(REALM_NAME).clients().get(response.getClientId());
        assertTrue(clientResource.toRepresentation().getDefaultClientScopes().isEmpty());

    }

    @Test
    public void testClientWithNotDefinedScope() throws Exception {
        OIDCClientRepresentation clientRep = null;
        OIDCClientRepresentation response = null;

        String clientScope = "notdefinedscope address";

        clientRep = createRep();
        clientRep.setScope(clientScope);
        try {
            response = reg.oidc().create(clientRep);
            fail("Expected 403");
        } catch (ClientRegistrationException e) {
            assertEquals(403, ((HttpErrorException) e.getCause()).getStatusLine().getStatusCode());
        }
    }

    @Test
    public void testClientWithoutScope() throws ClientRegistrationException {
        Set<String> realmOptionalClientScopes = new HashSet<>(adminClient.realm(REALM_NAME).getDefaultOptionalClientScopes()
                .stream()
                .filter(scope -> Objects.equals(scope.getProtocol(), OIDCLoginProtocol.LOGIN_PROTOCOL))
                .map(i->i.getName()).collect(Collectors.toList()));

        OIDCClientRepresentation clientRep = null;
        OIDCClientRepresentation response = null;

        clientRep = createRep();
        response = reg.oidc().create(clientRep);

        Set<String> registeredClientScopes = new HashSet<>(Arrays.asList(response.getScope().split(" ")));
        assertTrue(realmOptionalClientScopes.equals(new HashSet<>(registeredClientScopes)));

        ClientResource clientResource = adminClient.realm(REALM_NAME).clients().get(response.getClientId());
        ClientRepresentation rep = clientResource.toRepresentation();

        Set<String> realmDefaultClientScopes = new HashSet<>(adminClient.realm(REALM_NAME).getDefaultDefaultClientScopes()
                .stream()
                .filter(scope -> Objects.equals(scope.getProtocol(), OIDCLoginProtocol.LOGIN_PROTOCOL))
                .map(i->i.getName()).collect(Collectors.toList()));

        Set<String> registeredDefaultClientScopes = new HashSet<>(rep.getDefaultClientScopes());
        assertTrue(realmDefaultClientScopes.equals(new HashSet<>(registeredDefaultClientScopes)));

    }

    @Test
    public void testRequestUris() throws Exception {
        OIDCClientRepresentation clientRep = null;
        OIDCClientRepresentation response = null;

        clientRep = createRep();
        clientRep.setRequestUris(Arrays.asList("http://host/foo", "https://host2/bar"));

        response = reg.oidc().create(clientRep);
        Assert.assertNames(response.getRequestUris(), "http://host/foo", "https://host2/bar");

        // Test Keycloak representation
        ClientRepresentation kcClient = getClient(response.getClientId());
        OIDCAdvancedConfigWrapper config = OIDCAdvancedConfigWrapper.fromClientRepresentation(kcClient);
        Assert.assertNames(config.getRequestUris(), "http://host/foo", "https://host2/bar");
    }

    @Test
    public void testClientWithoutRefreshToken() throws Exception {
        OIDCClientRepresentation clientRep = null;
        OIDCClientRepresentation response = null;

        clientRep = createRep();
        clientRep.setGrantTypes(Arrays.asList(OAuth2Constants.AUTHORIZATION_CODE));

        response = reg.oidc().create(clientRep);

        // Test Keycloak representation
        ClientRepresentation kcClient = getClient(response.getClientId());
        OIDCAdvancedConfigWrapper config = OIDCAdvancedConfigWrapper.fromClientRepresentation(kcClient);
        Assert.assertFalse(config.isUseRefreshToken());
    }

    @Test
    public void testClientWithRefreshToken() throws Exception {
        OIDCClientRepresentation clientRep = null;
        OIDCClientRepresentation response = null;

        clientRep = createRep();
        clientRep.setGrantTypes(Arrays.asList(OAuth2Constants.AUTHORIZATION_CODE, OAuth2Constants.REFRESH_TOKEN));

        response = reg.oidc().create(clientRep);

        // Test Keycloak representation
        ClientRepresentation kcClient = getClient(response.getClientId());
        OIDCAdvancedConfigWrapper config = OIDCAdvancedConfigWrapper.fromClientRepresentation(kcClient);
        Assert.assertTrue(config.isUseRefreshToken());
    }

    @Test
    public void testClientWithoutGrantTypes() throws Exception {
        OIDCClientRepresentation response = create();

        assertTrue(CollectionUtil.collectionEquals(
            Arrays.asList(OAuth2Constants.AUTHORIZATION_CODE, OAuth2Constants.REFRESH_TOKEN), response.getGrantTypes()));

        // Test Keycloak representation
        ClientRepresentation kcClient = getClient(response.getClientId());
        OIDCAdvancedConfigWrapper config = OIDCAdvancedConfigWrapper.fromClientRepresentation(kcClient);
        Assert.assertTrue(config.isUseRefreshToken());
    }
}
