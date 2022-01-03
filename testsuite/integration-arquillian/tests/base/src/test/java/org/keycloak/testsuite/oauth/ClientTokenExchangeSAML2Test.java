/*
 * Copyright 2020 Red Hat, Inc. and/or its affiliates
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

import org.junit.Rule;
import org.junit.Test;
import org.keycloak.OAuth2Constants;
import org.keycloak.TokenVerifier;
import org.keycloak.authorization.model.Policy;
import org.keycloak.authorization.model.ResourceServer;
import org.keycloak.common.Profile;
import org.keycloak.common.util.Base64Url;
import org.keycloak.dom.saml.v2.assertion.AssertionType;
import org.keycloak.dom.saml.v2.assertion.AudienceRestrictionType;
import org.keycloak.dom.saml.v2.assertion.NameIDType;
import org.keycloak.models.ClientModel;
import org.keycloak.models.ImpersonationConstants;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserCredentialModel;
import org.keycloak.models.UserModel;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.protocol.oidc.mappers.UserSessionNoteMapper;
import org.keycloak.protocol.saml.SamlConfigAttributes;
import org.keycloak.protocol.saml.SamlProtocol;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.representations.idm.authorization.ClientPolicyRepresentation;
import org.keycloak.representations.idm.authorization.DecisionStrategy;
import org.keycloak.saml.common.util.DocumentUtil;
import org.keycloak.saml.processing.core.parsers.saml.SAMLParser;
import org.keycloak.saml.processing.core.saml.v2.util.AssertionUtil;
import org.keycloak.saml.processing.core.util.XMLEncryptionUtil;
import org.keycloak.services.resources.admin.permissions.AdminPermissionManagement;
import org.keycloak.services.resources.admin.permissions.AdminPermissions;
import org.keycloak.testsuite.AbstractKeycloakTest;
import org.keycloak.testsuite.Assert;
import org.keycloak.testsuite.AssertEvents;
import org.keycloak.testsuite.arquillian.annotation.AuthServerContainerExclude;
import org.keycloak.testsuite.arquillian.annotation.AuthServerContainerExclude.AuthServer;
import org.keycloak.testsuite.arquillian.annotation.EnableFeature;
import org.keycloak.testsuite.arquillian.annotation.UncaughtServerErrorExpected;
import org.keycloak.testsuite.util.AdminClientUtil;
import org.keycloak.testsuite.util.OAuthClient;
import org.keycloak.util.BasicAuthHelper;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.ws.rs.client.Client;
import javax.ws.rs.client.Entity;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.Form;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.Response;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.assertNotNull;
import static org.keycloak.models.ImpersonationSessionNote.IMPERSONATOR_ID;
import static org.keycloak.models.ImpersonationSessionNote.IMPERSONATOR_USERNAME;
import static org.keycloak.protocol.saml.SamlProtocol.SAML_ASSERTION_CONSUMER_URL_POST_ATTRIBUTE;
import static org.keycloak.testsuite.auth.page.AuthRealm.TEST;

/**
 * @author <a href="mailto:h2-wada@nri.co.jp">Hiroyuki Wada</a>
 */
@AuthServerContainerExclude(AuthServer.REMOTE)
@EnableFeature(value = Profile.Feature.TOKEN_EXCHANGE, skipRestart = true)
public class ClientTokenExchangeSAML2Test extends AbstractKeycloakTest {

    private static final String SAML_SIGNED_TARGET = "http://localhost:8080/saml-signed-assertion/";
    private static final String SAML_ENCRYPTED_TARGET = "http://localhost:8080/saml-encrypted-assertion/";
    private static final String SAML_SIGNED_AND_ENCRYPTED_TARGET = "http://localhost:8080/saml-signed-and-encrypted-assertion/";
    private static final String SAML_UNSIGNED_AND_UNENCRYPTED_TARGET = "http://localhost:8080/saml-unsigned-and-unencrypted-assertion/";

    private static final String REALM_PRIVATE_KEY = "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";
    private static final String REALM_PUBLIC_KEY = "MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAs2njo0TT4UkMcp2Cq+6wcyEVZsyLJ+3bIG5pBPwzik3jUEPG3r7SlPJyx/x6wXUNDvI/x4Q7CKEh6Xm1oLXGStyHQWiFX9VuyTe4aR5VMWC6maezK2YsWVkXY0OGCi96J85qWHRGnIloaCKXr0vfyVsGmrAwnCmRj/aUiQTwZB54lQt0t9wgrT944vvCVoyAiThmIlMNdL87LNwjj5t50kKmPccCl7bjo4IvakDMhpJbvJbz7WWldoBWa7hlU8EmGpUhB3Q2pNqnUQBVKeYu67kfA9uLto6XK/UTpwVcIugveS5v8f/5ZhWM6oGNfam8JiJhD7zP3GYfSTpcYGDKrLnqdE7+bOxzYSXVqTS0dO2J20qr0J2qnykI+y/dpCiZDlhq0AChe142QkxA9zDbSmH89Oy6oJvdBnycSTNv2EzameRakxZyDI3Jc2zrc9e/76i3HPO1RK6ZItieEqg4sa/RUGbO3eaq8rdKUwrxGLuxighO11uZ5KcdOhW9PixFAgMBAAE=";
    private static final String ENCRYPTION_CERTIFICATE = "MIIE2TCCAsECBgFJGVacCDANBgkqhkiG9w0BAQsFADAwMS4wLAYDVQQDEyVodHRwOi8vbG9jYWxob3N0OjgwODAvc2FsZXMtcG9zdC1lbmMvMB4XDTE0MTAxNjE0MjA0NloXDTI0MTAxNjE0MjIyNlowMDEuMCwGA1UEAxMlaHR0cDovL2xvY2FsaG9zdDo4MDgwL3NhbGVzLXBvc3QtZW5jLzCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAJqAmahT/JdcFRF46alY8gDdljYrE+Wj7Ht/FawKFrETq4zGYT1MQRqY8A1ScD4U9AjtQGlToW+SNNvZIRHc65MveYAFd6NATDCbvUX4Av3HlQN2gWHzq/rY6nGYyhBfT6RIIpd4ShYPHBY6eTWCmzuDugbNXBsYWN657tCpqC+zkHCpkhCYq754imF4KMRRxvpjNtKG0vI8sazejXSadbXbgtLtAsvJI8S0J3rDVn4jG8jXRH/Ns5sM2IJiiJrdYyjmbhl3AXG9Fmun0H66jdJzjiqOBkXRE94MwMTKenjWtV8lp4twZ0+ZfdfLnSsaDGI496hIErmKGLXUuD9l30EQLgnavGXo/tHl1g2FgOr6WaWwSAnkTsi3tj8FLJaiFY5wovbxmOMqTYx9PmxcApdEEObROZFRn350lUwm+aJElHRcj3CL8pUqtCY1/QIuFY4v0Bna2eI5ykFQI7AN1E7FCWSTlZIe9olQ9w9P0nWu2f9Ygc9yJgilNDZklM34NgNQOVKPqHjvWH4itYBemqDFKShOI6SUh39xavQ2IJ4nvAmOJ1S+Qz/8ExqaeYlADINkNGWHKo9jP3rMCbXeeiQNdCe6EVav7glZbeZ0tauKm0qq0Ckv3EKZThsNktYAnrbH44ImFePCF9G6bkVz7zQSm57TxRuU5RgkGEaVEP/zAgMBAAEwDQYJKoZIhvcNAQELBQADggIBAHljQiIsGbRMzUKzB7h5fjTuiabcPhB0XBOzPkoolkD4vXshS2+BecZila9ifyo5r4CHyBB0g4T/jcwIzE/AImib+zXxiT9x5H6NbGUr5GTgtcaZVqF2UUKo6BdQ3RJkTdAn4lNxgvQ7W/20cL/oamSpFUERFxcSCwuseyPiworr+QAOlmAxQabWP6r5+wr6u8P0omctvuwwoRHMlzeYT/JKmHIS+isZzxJ7JoG4eBti3vKk9sWhAfrNPOY6sMeitHk3W4ISFZrf2hVTSFw+zrzIGJyCWODoEuI5p8w8Jwqh4Ezt1G32Xadb0hdda/t/dNRPkGP2Qipz147MH+mGoM54Fe559qjgW2ODvwTLB8RdQq1SnaY6u+KhUgR4JoPkohVgZH/WPq4QEnswmOz43x/fdeuaAvXwqPHptt9z3HCXqOL2vuodKx99kLYauxUGS3mDI81wEsbt1F0ymA2o2ThEmmn6x8zIPqm/MYP1TZpG3iD2KODhCwf/HQXz3QQtZNMil/4LvdXdid6BWIXmWjXbyt/27cHK/KKfn6tli/HVRmhJNicQIP3SGMBMY5oB8ufPFrbcNA8YpqZZ5hK31AiC1k/RufQEdgprqezriAgtJwpKbALVcxG/Xbb42cBU6DsaL8O1JtUz+EmTwZvywZRemcPMtp6se2AKz4EZSdD6";
    private static final String ENCRYPTION_PRIVATE_KEY = "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";

    @Rule
    public AssertEvents events = new AssertEvents(this);

    @Override
    public void addTestRealms(List<RealmRepresentation> testRealms) {
        RealmRepresentation testRealmRep = new RealmRepresentation();
        testRealmRep.setId(TEST);
        testRealmRep.setRealm(TEST);
        testRealmRep.setEnabled(true);
        testRealmRep.setPrivateKey(REALM_PRIVATE_KEY);
        testRealmRep.setPublicKey(REALM_PUBLIC_KEY);
        testRealmRep.setAccessCodeLifespan(60); // Used as default assertion lifespan
        testRealms.add(testRealmRep);
    }

    public static void setupRealm(KeycloakSession session) {
        addTargetClients(session);
        addDirectExchanger(session);

        RealmModel realm = session.realms().getRealmByName(TEST);
        RoleModel exampleRole = realm.getRole("example");

        AdminPermissionManagement management = AdminPermissions.management(session, realm);
        RoleModel impersonateRole = management.getRealmManagementClient().getRole(ImpersonationConstants.IMPERSONATION_ROLE);

        ClientModel clientExchanger = realm.addClient("client-exchanger");
        clientExchanger.setClientId("client-exchanger");
        clientExchanger.setPublicClient(false);
        clientExchanger.setDirectAccessGrantsEnabled(true);
        clientExchanger.setEnabled(true);
        clientExchanger.setSecret("secret");
        clientExchanger.setProtocol(OIDCLoginProtocol.LOGIN_PROTOCOL);
        clientExchanger.setFullScopeAllowed(false);
        clientExchanger.addScopeMapping(impersonateRole);
        clientExchanger.addProtocolMapper(UserSessionNoteMapper.createUserSessionNoteMapper(IMPERSONATOR_ID));
        clientExchanger.addProtocolMapper(UserSessionNoteMapper.createUserSessionNoteMapper(IMPERSONATOR_USERNAME));

        ClientModel illegal = realm.addClient("illegal");
        illegal.setClientId("illegal");
        illegal.setPublicClient(false);
        illegal.setDirectAccessGrantsEnabled(true);
        illegal.setEnabled(true);
        illegal.setSecret("secret");
        illegal.setProtocol(OIDCLoginProtocol.LOGIN_PROTOCOL);
        illegal.setFullScopeAllowed(false);

        ClientModel legal = realm.addClient("legal");
        legal.setClientId("legal");
        legal.setPublicClient(false);
        legal.setDirectAccessGrantsEnabled(true);
        legal.setEnabled(true);
        legal.setSecret("secret");
        legal.setProtocol(OIDCLoginProtocol.LOGIN_PROTOCOL);
        legal.setFullScopeAllowed(false);

        ClientModel directLegal = realm.addClient("direct-legal");
        directLegal.setClientId("direct-legal");
        directLegal.setPublicClient(false);
        directLegal.setDirectAccessGrantsEnabled(true);
        directLegal.setEnabled(true);
        directLegal.setSecret("secret");
        directLegal.setProtocol(OIDCLoginProtocol.LOGIN_PROTOCOL);
        directLegal.setFullScopeAllowed(false);

        ClientModel directPublic = realm.addClient("direct-public");
        directPublic.setClientId("direct-public");
        directPublic.setPublicClient(true);
        directPublic.setDirectAccessGrantsEnabled(true);
        directPublic.setEnabled(true);
        directPublic.setProtocol(OIDCLoginProtocol.LOGIN_PROTOCOL);
        directPublic.setFullScopeAllowed(false);

        ClientModel directNoSecret = realm.addClient("direct-no-secret");
        directNoSecret.setClientId("direct-no-secret");
        directNoSecret.setPublicClient(false);
        directNoSecret.setDirectAccessGrantsEnabled(true);
        directNoSecret.setEnabled(true);
        directNoSecret.setProtocol(OIDCLoginProtocol.LOGIN_PROTOCOL);
        directNoSecret.setFullScopeAllowed(false);

        // permission for client to client exchange to "target" client
        ClientPolicyRepresentation clientRep = new ClientPolicyRepresentation();
        clientRep.setName("to");
        clientRep.addClient(clientExchanger.getId());
        clientRep.addClient(legal.getId());
        clientRep.addClient(directLegal.getId());

        ClientModel samlSignedTarget = realm.getClientByClientId(SAML_SIGNED_TARGET);
        ClientModel samlEncryptedTarget = realm.getClientByClientId(SAML_ENCRYPTED_TARGET);
        ClientModel samlSignedAndEncryptedTarget = realm.getClientByClientId(SAML_SIGNED_AND_ENCRYPTED_TARGET);
        ClientModel samlUnsignedAndUnencryptedTarget = realm.getClientByClientId(SAML_UNSIGNED_AND_UNENCRYPTED_TARGET);
        assertNotNull(samlSignedTarget);
        assertNotNull(samlEncryptedTarget);
        assertNotNull(samlSignedAndEncryptedTarget);
        assertNotNull(samlUnsignedAndUnencryptedTarget);

        ResourceServer server = management.realmResourceServer();
        Policy clientPolicy = management.authz().getStoreFactory().getPolicyStore().create(clientRep, server);
        management.clients().exchangeToPermission(samlSignedTarget).addAssociatedPolicy(clientPolicy);
        management.clients().exchangeToPermission(samlEncryptedTarget).addAssociatedPolicy(clientPolicy);
        management.clients().exchangeToPermission(samlSignedAndEncryptedTarget).addAssociatedPolicy(clientPolicy);
        management.clients().exchangeToPermission(samlUnsignedAndUnencryptedTarget).addAssociatedPolicy(clientPolicy);

        // permission for user impersonation for a client

        ClientPolicyRepresentation clientImpersonateRep = new ClientPolicyRepresentation();
        clientImpersonateRep.setName("clientImpersonators");
        clientImpersonateRep.addClient(directLegal.getId());
        clientImpersonateRep.addClient(directPublic.getId());
        clientImpersonateRep.addClient(directNoSecret.getId());
        server = management.realmResourceServer();
        Policy clientImpersonatePolicy = management.authz().getStoreFactory().getPolicyStore().create(clientImpersonateRep, server);
        management.users().setPermissionsEnabled(true);
        management.users().adminImpersonatingPermission().addAssociatedPolicy(clientImpersonatePolicy);
        management.users().adminImpersonatingPermission().setDecisionStrategy(DecisionStrategy.AFFIRMATIVE);

        UserModel user = session.users().addUser(realm, "user");
        user.setEnabled(true);
        session.userCredentialManager().updateCredential(realm, user, UserCredentialModel.password("password"));
        user.grantRole(exampleRole);
        user.grantRole(impersonateRole);

        UserModel bad = session.users().addUser(realm, "bad-impersonator");
        bad.setEnabled(true);
        session.userCredentialManager().updateCredential(realm, bad, UserCredentialModel.password("password"));
    }

    @Override
    protected boolean isImportAfterEachMethod() {
        return true;
    }

    @Test
    @UncaughtServerErrorExpected
    public void testExchangeToSAML2SignedAssertion() throws Exception {
        testingClient.server().run(ClientTokenExchangeSAML2Test::setupRealm);

        oauth.realm(TEST);
        oauth.clientId("client-exchanger");
        OAuthClient.AccessTokenResponse response = oauth.doGrantAccessTokenRequest("secret", "user", "password");
        String accessToken = response.getAccessToken();
        TokenVerifier<AccessToken> accessTokenVerifier = TokenVerifier.create(accessToken, AccessToken.class);
        AccessToken token = accessTokenVerifier.parse().getToken();
        Assert.assertEquals(token.getPreferredUsername(), "user");
        Assert.assertTrue(token.getRealmAccess() == null || !token.getRealmAccess().isUserInRole("example"));

        Map<String, String> params = new HashMap<>();
        params.put(OAuth2Constants.REQUESTED_TOKEN_TYPE, OAuth2Constants.SAML2_TOKEN_TYPE);

        {
            response = oauth.doTokenExchange(TEST, accessToken, SAML_SIGNED_TARGET, "client-exchanger", "secret", params);

            String exchangedTokenString = response.getAccessToken();
            String assertionXML = new String(Base64Url.decode(exchangedTokenString), "UTF-8");

            // Verify issued_token_type
            Assert.assertEquals(OAuth2Constants.SAML2_TOKEN_TYPE, response.getIssuedTokenType());

            // Verify assertion
            Element assertionElement = DocumentUtil.getDocument(assertionXML).getDocumentElement();
            Assert.assertTrue(AssertionUtil.isSignedElement(assertionElement));
            AssertionType assertion = (AssertionType) SAMLParser.getInstance().parse(assertionElement);
            Assert.assertTrue(AssertionUtil.isSignatureValid(assertionElement, publicKeyFromString(REALM_PUBLIC_KEY)));

            // Expires
            Assert.assertEquals(60, response.getExpiresIn());

            // Audience
            AudienceRestrictionType aud = (AudienceRestrictionType) assertion.getConditions().getConditions().get(0);
            Assert.assertEquals(SAML_SIGNED_TARGET, aud.getAudience().get(0).toString());

            // NameID
            Assert.assertEquals("user", ((NameIDType) assertion.getSubject().getSubType().getBaseID()).getValue());

            // Role mapping
            List<String> roles = AssertionUtil.getRoles(assertion, null);
            Assert.assertTrue(roles.contains("example"));
        }

        {
            response = oauth.doTokenExchange(TEST, accessToken, SAML_SIGNED_TARGET, "legal", "secret", params);

            String exchangedTokenString = response.getAccessToken();
            String assertionXML = new String(Base64Url.decode(exchangedTokenString), "UTF-8");

            // Verify issued_token_type
            Assert.assertEquals(OAuth2Constants.SAML2_TOKEN_TYPE, response.getIssuedTokenType());

            // Verify assertion
            Element assertionElement = DocumentUtil.getDocument(assertionXML).getDocumentElement();
            Assert.assertTrue(AssertionUtil.isSignedElement(assertionElement));
            AssertionType assertion = (AssertionType) SAMLParser.getInstance().parse(assertionElement);
            Assert.assertTrue(AssertionUtil.isSignatureValid(assertionElement, publicKeyFromString(REALM_PUBLIC_KEY)));

            // Audience
            AudienceRestrictionType aud = (AudienceRestrictionType) assertion.getConditions().getConditions().get(0);
            Assert.assertEquals(SAML_SIGNED_TARGET, aud.getAudience().get(0).toString());

            // NameID
            Assert.assertEquals("user", ((NameIDType) assertion.getSubject().getSubType().getBaseID()).getValue());

            // Role mapping
            List<String> roles = AssertionUtil.getRoles(assertion, null);
            Assert.assertTrue(roles.contains("example"));
        }
        {
            response = oauth.doTokenExchange(TEST, accessToken, SAML_SIGNED_TARGET, "illegal", "secret", params);
            Assert.assertEquals(403, response.getStatusCode());
        }
    }

    @Test
    @UncaughtServerErrorExpected
    public void testExchangeToSAML2EncryptedAssertion() throws Exception {
        testingClient.server().run(ClientTokenExchangeSAML2Test::setupRealm);

        oauth.realm(TEST);
        oauth.clientId("client-exchanger");
        OAuthClient.AccessTokenResponse response = oauth.doGrantAccessTokenRequest("secret", "user", "password");
        String accessToken = response.getAccessToken();
        TokenVerifier<AccessToken> accessTokenVerifier = TokenVerifier.create(accessToken, AccessToken.class);
        AccessToken token = accessTokenVerifier.parse().getToken();
        Assert.assertEquals(token.getPreferredUsername(), "user");
        Assert.assertTrue(token.getRealmAccess() == null || !token.getRealmAccess().isUserInRole("example"));

        Map<String, String> params = new HashMap<>();
        params.put(OAuth2Constants.REQUESTED_TOKEN_TYPE, OAuth2Constants.SAML2_TOKEN_TYPE);

        {
            response = oauth.doTokenExchange(TEST, accessToken, SAML_ENCRYPTED_TARGET, "client-exchanger", "secret", params);

            String exchangedTokenString = response.getAccessToken();
            String assertionXML = new String(Base64Url.decode(exchangedTokenString), "UTF-8");

            // Verify issued_token_type
            Assert.assertEquals(OAuth2Constants.SAML2_TOKEN_TYPE, response.getIssuedTokenType());

            // Decrypt assertion
            Document assertionDoc = DocumentUtil.getDocument(assertionXML);
            Element assertionElement = XMLEncryptionUtil.decryptElementInDocument(assertionDoc, privateKeyFromString(ENCRYPTION_PRIVATE_KEY));
            Assert.assertFalse(AssertionUtil.isSignedElement(assertionElement));
            AssertionType assertion = (AssertionType) SAMLParser.getInstance().parse(assertionElement);

            // Expires
            Assert.assertEquals(30, response.getExpiresIn());

            // Audience
            AudienceRestrictionType aud = (AudienceRestrictionType) assertion.getConditions().getConditions().get(0);
            Assert.assertEquals(SAML_ENCRYPTED_TARGET, aud.getAudience().get(0).toString());

            // NameID
            Assert.assertEquals("user", ((NameIDType) assertion.getSubject().getSubType().getBaseID()).getValue());

            // Role mapping
            List<String> roles = AssertionUtil.getRoles(assertion, null);
            Assert.assertTrue(roles.contains("example"));
        }
    }

    @Test
    @UncaughtServerErrorExpected
    public void testExchangeToSAML2SignedAndEncryptedAssertion() throws Exception {
        testingClient.server().run(ClientTokenExchangeSAML2Test::setupRealm);

        oauth.realm(TEST);
        oauth.clientId("client-exchanger");
        OAuthClient.AccessTokenResponse response = oauth.doGrantAccessTokenRequest("secret", "user", "password");
        String accessToken = response.getAccessToken();
        TokenVerifier<AccessToken> accessTokenVerifier = TokenVerifier.create(accessToken, AccessToken.class);
        AccessToken token = accessTokenVerifier.parse().getToken();
        Assert.assertEquals(token.getPreferredUsername(), "user");
        Assert.assertTrue(token.getRealmAccess() == null || !token.getRealmAccess().isUserInRole("example"));

        Map<String, String> params = new HashMap<>();
        params.put(OAuth2Constants.REQUESTED_TOKEN_TYPE, OAuth2Constants.SAML2_TOKEN_TYPE);

        {
            response = oauth.doTokenExchange(TEST, accessToken, SAML_SIGNED_AND_ENCRYPTED_TARGET, "client-exchanger", "secret", params);

            String exchangedTokenString = response.getAccessToken();
            String assertionXML = new String(Base64Url.decode(exchangedTokenString), "UTF-8");

            // Verify issued_token_type
            Assert.assertEquals(OAuth2Constants.SAML2_TOKEN_TYPE, response.getIssuedTokenType());

            // Verify assertion
            Document assertionDoc = DocumentUtil.getDocument(assertionXML);
            Element assertionElement = XMLEncryptionUtil.decryptElementInDocument(assertionDoc, privateKeyFromString(ENCRYPTION_PRIVATE_KEY));
            Assert.assertTrue(AssertionUtil.isSignedElement(assertionElement));
            AssertionType assertion = (AssertionType) SAMLParser.getInstance().parse(assertionElement);
            Assert.assertTrue(AssertionUtil.isSignatureValid(assertionElement, publicKeyFromString(REALM_PUBLIC_KEY)));

            // Audience
            AudienceRestrictionType aud = (AudienceRestrictionType) assertion.getConditions().getConditions().get(0);
            Assert.assertEquals(SAML_SIGNED_AND_ENCRYPTED_TARGET, aud.getAudience().get(0).toString());

            // NameID
            Assert.assertEquals("user", ((NameIDType) assertion.getSubject().getSubType().getBaseID()).getValue());

            // Role mapping
            List<String> roles = AssertionUtil.getRoles(assertion, null);
            Assert.assertTrue(roles.contains("example"));
        }
    }

    @Test
    @UncaughtServerErrorExpected
    public void testExchangeToSAML2UnsignedAndUnencryptedAssertion() throws Exception {
        testingClient.server().run(ClientTokenExchangeSAML2Test::setupRealm);

        oauth.realm(TEST);
        oauth.clientId("client-exchanger");
        OAuthClient.AccessTokenResponse response = oauth.doGrantAccessTokenRequest("secret", "user", "password");
        String accessToken = response.getAccessToken();
        TokenVerifier<AccessToken> accessTokenVerifier = TokenVerifier.create(accessToken, AccessToken.class);
        AccessToken token = accessTokenVerifier.parse().getToken();
        Assert.assertEquals(token.getPreferredUsername(), "user");
        Assert.assertTrue(token.getRealmAccess() == null || !token.getRealmAccess().isUserInRole("example"));

        Map<String, String> params = new HashMap<>();
        params.put(OAuth2Constants.REQUESTED_TOKEN_TYPE, OAuth2Constants.SAML2_TOKEN_TYPE);

        {
            response = oauth.doTokenExchange(TEST, accessToken, SAML_UNSIGNED_AND_UNENCRYPTED_TARGET, "client-exchanger", "secret", params);

            String exchangedTokenString = response.getAccessToken();
            String assertionXML = new String(Base64Url.decode(exchangedTokenString), "UTF-8");

            // Verify issued_token_type
            Assert.assertEquals(OAuth2Constants.SAML2_TOKEN_TYPE, response.getIssuedTokenType());

            // Verify assertion
            Document assertionDoc = DocumentUtil.getDocument(assertionXML);
            Assert.assertFalse(AssertionUtil.isSignedElement(assertionDoc.getDocumentElement()));
            AssertionType assertion = (AssertionType) SAMLParser.getInstance().parse(assertionDoc);

            // Audience
            AudienceRestrictionType aud = (AudienceRestrictionType) assertion.getConditions().getConditions().get(0);
            Assert.assertEquals(SAML_UNSIGNED_AND_UNENCRYPTED_TARGET, aud.getAudience().get(0).toString());

            // NameID
            Assert.assertEquals("user", ((NameIDType) assertion.getSubject().getSubType().getBaseID()).getValue());

            // Role mapping
            List<String> roles = AssertionUtil.getRoles(assertion, null);
            Assert.assertTrue(roles.contains("example"));
        }
    }

    @Test
    @UncaughtServerErrorExpected
    public void testImpersonation() throws Exception {
        testingClient.server().run(ClientTokenExchangeSAML2Test::setupRealm);

        oauth.realm(TEST);
        oauth.clientId("client-exchanger");

        OAuthClient.AccessTokenResponse response = oauth.doGrantAccessTokenRequest("secret", "user", "password");
        String accessToken = response.getAccessToken();
        TokenVerifier<AccessToken> accessTokenVerifier = TokenVerifier.create(accessToken, AccessToken.class);
        AccessToken token = accessTokenVerifier.parse().getToken();
        Assert.assertEquals(token.getPreferredUsername(), "user");
        Assert.assertTrue(token.getRealmAccess() == null || !token.getRealmAccess().isUserInRole("example"));

        Map<String, String> params = new HashMap<>();
        params.put(OAuth2Constants.REQUESTED_TOKEN_TYPE, OAuth2Constants.SAML2_TOKEN_TYPE);

        // client-exchanger can impersonate from token "user" to user "impersonated-user" and to "target" client
        {
            params.put(OAuth2Constants.REQUESTED_SUBJECT, "impersonated-user");
            response = oauth.doTokenExchange(TEST, accessToken, SAML_SIGNED_TARGET, "client-exchanger", "secret", params);

            String exchangedTokenString = response.getAccessToken();
            String assertionXML = new String(Base64Url.decode(exchangedTokenString), "UTF-8");

            // Verify issued_token_type
            Assert.assertEquals(OAuth2Constants.SAML2_TOKEN_TYPE, response.getIssuedTokenType());

            // Verify assertion
            Element assertionElement = DocumentUtil.getDocument(assertionXML).getDocumentElement();
            Assert.assertTrue(AssertionUtil.isSignedElement(assertionElement));
            AssertionType assertion = (AssertionType) SAMLParser.getInstance().parse(assertionElement);
            Assert.assertTrue(AssertionUtil.isSignatureValid(assertionElement, publicKeyFromString(REALM_PUBLIC_KEY)));

            // Audience
            AudienceRestrictionType aud = (AudienceRestrictionType) assertion.getConditions().getConditions().get(0);
            Assert.assertEquals(SAML_SIGNED_TARGET, aud.getAudience().get(0).toString());

            // NameID
            Assert.assertEquals("impersonated-user", ((NameIDType) assertion.getSubject().getSubType().getBaseID()).getValue());

            // Role mapping
            List<String> roles = AssertionUtil.getRoles(assertion, null);
            Assert.assertTrue(roles.contains("example"));
        }
    }

    @Test
    @UncaughtServerErrorExpected
    public void testBadImpersonator() throws Exception {
        testingClient.server().run(ClientTokenExchangeSAML2Test::setupRealm);

        oauth.realm(TEST);
        oauth.clientId("client-exchanger");

        OAuthClient.AccessTokenResponse response = oauth.doGrantAccessTokenRequest("secret", "bad-impersonator", "password");
        String accessToken = response.getAccessToken();
        TokenVerifier<AccessToken> accessTokenVerifier = TokenVerifier.create(accessToken, AccessToken.class);
        AccessToken token = accessTokenVerifier.parse().getToken();
        Assert.assertEquals(token.getPreferredUsername(), "bad-impersonator");
        Assert.assertTrue(token.getRealmAccess() == null || !token.getRealmAccess().isUserInRole("example"));

        Map<String, String> params = new HashMap<>();
        params.put(OAuth2Constants.REQUESTED_TOKEN_TYPE, OAuth2Constants.SAML2_TOKEN_TYPE);

        // test that user does not have impersonator permission
        {
            params.put(OAuth2Constants.REQUESTED_SUBJECT, "impersonated-user");
            response = oauth.doTokenExchange(TEST, accessToken, SAML_SIGNED_TARGET, "client-exchanger", "secret", params);
            Assert.assertEquals(403, response.getStatusCode());
        }
    }

    @Test
    @UncaughtServerErrorExpected
    public void testDirectImpersonation() throws Exception {
        testingClient.server().run(ClientTokenExchangeSAML2Test::setupRealm);
        Client httpClient = AdminClientUtil.createResteasyClient();

        WebTarget exchangeUrl = httpClient.target(OAuthClient.AUTH_SERVER_ROOT)
                .path("/realms")
                .path(TEST)
                .path("protocol/openid-connect/token");
        System.out.println("Exchange url: " + exchangeUrl.getUri().toString());

        // direct-legal can impersonate from token "user" to user "impersonated-user" and to "target" client
        {
            Response response = exchangeUrl.request()
                    .header(HttpHeaders.AUTHORIZATION, BasicAuthHelper.createHeader("direct-legal", "secret"))
                    .post(Entity.form(
                            new Form()
                                    .param(OAuth2Constants.GRANT_TYPE, OAuth2Constants.TOKEN_EXCHANGE_GRANT_TYPE)
                                    .param(OAuth2Constants.REQUESTED_TOKEN_TYPE, OAuth2Constants.SAML2_TOKEN_TYPE)
                                    .param(OAuth2Constants.REQUESTED_SUBJECT, "impersonated-user")
                                    .param(OAuth2Constants.AUDIENCE, SAML_SIGNED_TARGET)
                    ));
            Assert.assertEquals(200, response.getStatus());
            AccessTokenResponse accessTokenResponse = response.readEntity(AccessTokenResponse.class);
            response.close();

            String exchangedTokenString = accessTokenResponse.getToken();
            String assertionXML = new String(Base64Url.decode(exchangedTokenString), "UTF-8");

            // Verify issued_token_type
            Assert.assertEquals(OAuth2Constants.SAML2_TOKEN_TYPE, accessTokenResponse.getOtherClaims().get(OAuth2Constants.ISSUED_TOKEN_TYPE));

            // Verify assertion
            Element assertionElement = DocumentUtil.getDocument(assertionXML).getDocumentElement();
            Assert.assertTrue(AssertionUtil.isSignedElement(assertionElement));
            AssertionType assertion = (AssertionType) SAMLParser.getInstance().parse(assertionElement);
            Assert.assertTrue(AssertionUtil.isSignatureValid(assertionElement, publicKeyFromString(REALM_PUBLIC_KEY)));

            // Audience
            AudienceRestrictionType aud = (AudienceRestrictionType) assertion.getConditions().getConditions().get(0);
            Assert.assertEquals(SAML_SIGNED_TARGET, aud.getAudience().get(0).toString());

            // NameID
            Assert.assertEquals("impersonated-user", ((NameIDType) assertion.getSubject().getSubType().getBaseID()).getValue());

            // Role mapping
            List<String> roles = AssertionUtil.getRoles(assertion, null);
            Assert.assertTrue(roles.contains("example"));
        }

        // direct-public fails impersonation
        {
            Response response = exchangeUrl.request()
                    .header(HttpHeaders.AUTHORIZATION, BasicAuthHelper.createHeader("direct-public", "secret"))
                    .post(Entity.form(
                            new Form()
                                    .param(OAuth2Constants.GRANT_TYPE, OAuth2Constants.TOKEN_EXCHANGE_GRANT_TYPE)
                                    .param(OAuth2Constants.REQUESTED_TOKEN_TYPE, OAuth2Constants.SAML2_TOKEN_TYPE)
                                    .param(OAuth2Constants.REQUESTED_SUBJECT, "impersonated-user")
                                    .param(OAuth2Constants.AUDIENCE, SAML_SIGNED_TARGET)
                    ));
            Assert.assertEquals(403, response.getStatus());
            response.close();
        }

        // direct-no-secret fails impersonation
        {
            Response response = exchangeUrl.request()
                    .header(HttpHeaders.AUTHORIZATION, BasicAuthHelper.createHeader("direct-no-secret", "secret"))
                    .post(Entity.form(
                            new Form()
                                    .param(OAuth2Constants.GRANT_TYPE, OAuth2Constants.TOKEN_EXCHANGE_GRANT_TYPE)
                                    .param(OAuth2Constants.REQUESTED_TOKEN_TYPE, OAuth2Constants.SAML2_TOKEN_TYPE)
                                    .param(OAuth2Constants.REQUESTED_SUBJECT, "impersonated-user")
                                    .param(OAuth2Constants.AUDIENCE, SAML_SIGNED_TARGET)
                    ));
            Assert.assertTrue(response.getStatus() >= 400);
            response.close();
        }
    }

    private static void addTargetClients(KeycloakSession session) {
        RealmModel realm = session.realms().getRealmByName(TEST);

        // Create SAML 2.0 target clients
        ClientModel samlSignedTarget = realm.addClient(SAML_SIGNED_TARGET);
        samlSignedTarget.setClientId(SAML_SIGNED_TARGET);
        samlSignedTarget.setEnabled(true);
        samlSignedTarget.setProtocol(SamlProtocol.LOGIN_PROTOCOL);
        samlSignedTarget.setFullScopeAllowed(true);
        samlSignedTarget.setAttribute(SamlConfigAttributes.SAML_AUTHNSTATEMENT, "true");
        samlSignedTarget.setAttribute(SAML_ASSERTION_CONSUMER_URL_POST_ATTRIBUTE,
                SAML_SIGNED_TARGET + "endpoint");
        samlSignedTarget.setAttribute(SamlConfigAttributes.SAML_NAME_ID_FORMAT_ATTRIBUTE, "username");
        samlSignedTarget.setAttribute(SamlConfigAttributes.SAML_ASSERTION_SIGNATURE, "true");
        samlSignedTarget.setAttribute(SamlConfigAttributes.SAML_SERVER_SIGNATURE, "true");
        samlSignedTarget.setAttribute(SamlConfigAttributes.SAML_ENCRYPT, "false");

        ClientModel samlEncryptedTarget = realm.addClient(SAML_ENCRYPTED_TARGET);
        samlEncryptedTarget.setClientId(SAML_ENCRYPTED_TARGET);
        samlEncryptedTarget.setEnabled(true);
        samlEncryptedTarget.setProtocol(SamlProtocol.LOGIN_PROTOCOL);
        samlEncryptedTarget.setFullScopeAllowed(true);
        samlEncryptedTarget.setAttribute(SamlConfigAttributes.SAML_AUTHNSTATEMENT, "true");
        samlEncryptedTarget.setAttribute(SAML_ASSERTION_CONSUMER_URL_POST_ATTRIBUTE,
                SAML_ENCRYPTED_TARGET + "endpoint");
        samlEncryptedTarget.setAttribute(SamlConfigAttributes.SAML_NAME_ID_FORMAT_ATTRIBUTE, "username");
        samlEncryptedTarget.setAttribute(SamlConfigAttributes.SAML_ASSERTION_SIGNATURE, "false");
        samlEncryptedTarget.setAttribute(SamlConfigAttributes.SAML_SERVER_SIGNATURE, "true");
        samlEncryptedTarget.setAttribute(SamlConfigAttributes.SAML_ENCRYPT, "true");
        samlEncryptedTarget.setAttribute(SamlConfigAttributes.SAML_ENCRYPTION_CERTIFICATE_ATTRIBUTE, ENCRYPTION_CERTIFICATE);
        samlEncryptedTarget.setAttribute(SamlConfigAttributes.SAML_ASSERTION_LIFESPAN, "30");

        ClientModel samlSignedAndEncryptedTarget = realm.addClient(SAML_SIGNED_AND_ENCRYPTED_TARGET);
        samlSignedAndEncryptedTarget.setClientId(SAML_SIGNED_AND_ENCRYPTED_TARGET);
        samlSignedAndEncryptedTarget.setEnabled(true);
        samlSignedAndEncryptedTarget.setProtocol(SamlProtocol.LOGIN_PROTOCOL);
        samlSignedAndEncryptedTarget.setFullScopeAllowed(true);
        samlSignedAndEncryptedTarget.setAttribute(SamlConfigAttributes.SAML_AUTHNSTATEMENT, "true");
        samlSignedAndEncryptedTarget.setAttribute(SAML_ASSERTION_CONSUMER_URL_POST_ATTRIBUTE,
                SAML_SIGNED_AND_ENCRYPTED_TARGET + "endpoint");
        samlSignedAndEncryptedTarget.setAttribute(SamlConfigAttributes.SAML_NAME_ID_FORMAT_ATTRIBUTE, "username");
        samlSignedAndEncryptedTarget.setAttribute(SamlConfigAttributes.SAML_ASSERTION_SIGNATURE, "true");
        samlSignedAndEncryptedTarget.setAttribute(SamlConfigAttributes.SAML_SERVER_SIGNATURE, "true");
        samlSignedAndEncryptedTarget.setAttribute(SamlConfigAttributes.SAML_ENCRYPT, "true");
        samlSignedAndEncryptedTarget.setAttribute(SamlConfigAttributes.SAML_ENCRYPTION_CERTIFICATE_ATTRIBUTE, ENCRYPTION_CERTIFICATE);

        ClientModel samlUnsignedAndUnencryptedTarget = realm.addClient(SAML_UNSIGNED_AND_UNENCRYPTED_TARGET);
        samlUnsignedAndUnencryptedTarget.setClientId(SAML_UNSIGNED_AND_UNENCRYPTED_TARGET);
        samlUnsignedAndUnencryptedTarget.setEnabled(true);
        samlUnsignedAndUnencryptedTarget.setProtocol(SamlProtocol.LOGIN_PROTOCOL);
        samlUnsignedAndUnencryptedTarget.setFullScopeAllowed(true);
        samlUnsignedAndUnencryptedTarget.setAttribute(SamlConfigAttributes.SAML_AUTHNSTATEMENT, "true");
        samlUnsignedAndUnencryptedTarget.setAttribute(SAML_ASSERTION_CONSUMER_URL_POST_ATTRIBUTE,
                SAML_UNSIGNED_AND_UNENCRYPTED_TARGET + "endpoint");
        samlUnsignedAndUnencryptedTarget.setAttribute(SamlConfigAttributes.SAML_NAME_ID_FORMAT_ATTRIBUTE, "username");
        samlUnsignedAndUnencryptedTarget.setAttribute(SamlConfigAttributes.SAML_ASSERTION_SIGNATURE, "false");
        samlUnsignedAndUnencryptedTarget.setAttribute(SamlConfigAttributes.SAML_SERVER_SIGNATURE, "true");
        samlUnsignedAndUnencryptedTarget.setAttribute(SamlConfigAttributes.SAML_ENCRYPT, "false");
    }

    private static void addDirectExchanger(KeycloakSession session) {
        RealmModel realm = session.realms().getRealmByName(TEST);
        RoleModel exampleRole = realm.addRole("example");
        AdminPermissionManagement management = AdminPermissions.management(session, realm);

        ClientModel directExchanger = realm.addClient("direct-exchanger");
        directExchanger.setName("direct-exchanger");
        directExchanger.setClientId("direct-exchanger");
        directExchanger.setPublicClient(false);
        directExchanger.setDirectAccessGrantsEnabled(true);
        directExchanger.setEnabled(true);
        directExchanger.setSecret("secret");
        directExchanger.setProtocol(OIDCLoginProtocol.LOGIN_PROTOCOL);
        directExchanger.setFullScopeAllowed(false);

        // permission for client to client exchange to "target" client
        management.clients().setPermissionsEnabled(realm.getClientByClientId(SAML_SIGNED_TARGET), true);
        management.clients().setPermissionsEnabled(realm.getClientByClientId(SAML_ENCRYPTED_TARGET), true);
        management.clients().setPermissionsEnabled(realm.getClientByClientId(SAML_SIGNED_AND_ENCRYPTED_TARGET), true);
        management.clients().setPermissionsEnabled(realm.getClientByClientId(SAML_UNSIGNED_AND_UNENCRYPTED_TARGET), true);

        ClientPolicyRepresentation clientImpersonateRep = new ClientPolicyRepresentation();
        clientImpersonateRep.setName("clientImpersonatorsDirect");
        clientImpersonateRep.addClient(directExchanger.getId());

        ResourceServer server = management.realmResourceServer();
        Policy clientImpersonatePolicy = management.authz().getStoreFactory().getPolicyStore().create(clientImpersonateRep, server);
        management.users().setPermissionsEnabled(true);
        management.users().adminImpersonatingPermission().addAssociatedPolicy(clientImpersonatePolicy);
        management.users().adminImpersonatingPermission().setDecisionStrategy(DecisionStrategy.AFFIRMATIVE);

        UserModel impersonatedUser = session.users().addUser(realm, "impersonated-user");
        impersonatedUser.setEnabled(true);
        session.userCredentialManager().updateCredential(realm, impersonatedUser, UserCredentialModel.password("password"));
        impersonatedUser.grantRole(exampleRole);
    }

    private PublicKey publicKeyFromString(String publicKey) {
        return org.keycloak.testsuite.util.KeyUtils.publicKeyFromString(publicKey);
    }

    private PrivateKey privateKeyFromString(String privateKey) {
        return org.keycloak.testsuite.util.KeyUtils.privateKeyFromString(privateKey);
    }
}
