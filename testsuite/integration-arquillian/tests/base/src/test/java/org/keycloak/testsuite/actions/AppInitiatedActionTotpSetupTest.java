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
package org.keycloak.testsuite.actions;

import java.util.Arrays;
import java.util.List;

import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.jboss.arquillian.graphene.page.Page;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.common.Profile;
import org.keycloak.events.Details;
import org.keycloak.events.EventType;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.credential.OTPCredentialModel;
import org.keycloak.models.utils.HmacOTP;
import org.keycloak.models.utils.TimeBasedOTP;
import org.keycloak.representations.idm.EventRepresentation;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.keycloak.testsuite.AssertEvents;
import org.keycloak.testsuite.admin.ApiUtil;
import org.keycloak.testsuite.arquillian.annotation.DisableFeature;
import org.keycloak.testsuite.pages.AccountTotpPage;
import org.keycloak.testsuite.pages.LoginConfigTotpPage;
import org.keycloak.testsuite.pages.LoginTotpPage;
import org.keycloak.testsuite.pages.RegisterPage;
import org.keycloak.testsuite.util.RealmBuilder;
import org.keycloak.testsuite.util.UserBuilder;
import org.openqa.selenium.By;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * @author Stan Silvert
 */
public class AppInitiatedActionTotpSetupTest extends AbstractAppInitiatedActionTest {

    public AppInitiatedActionTotpSetupTest() {
        super(UserModel.RequiredAction.CONFIGURE_TOTP.name());
    }
    
    @Override
    public void configureTestRealm(RealmRepresentation testRealm) {
        testRealm.setResetPasswordAllowed(Boolean.TRUE);
    }

    @Before
    public void setOTPAuthRequired() {
        adminClient.realm("test").flows().getExecutions("browser")
                .stream()
                .filter(execution -> execution.getDisplayName().equals("Browser - Conditional OTP"))
                .forEach(execution -> {
                        execution.setRequirement(AuthenticationExecutionModel.Requirement.REQUIRED.name());
                        adminClient.realm("test").flows().updateExecutions("browser", execution);
                });

        ApiUtil.removeUserByUsername(testRealm(), "test-user@localhost");
        UserRepresentation user = UserBuilder.create().enabled(true)
                .username("test-user@localhost")
                .email("test-user@localhost")
                .firstName("Tom")
                .lastName("Brady")
                .build();
        ApiUtil.createUserAndResetPasswordWithAdminClient(testRealm(), user, "password");
    }


    @Page
    protected LoginTotpPage loginTotpPage;

    @Page
    protected LoginConfigTotpPage totpPage;

    @Page
    protected AccountTotpPage accountTotpPage;

    @Page
    protected RegisterPage registerPage;

    protected TimeBasedOTP totp = new TimeBasedOTP();

    @Test
    public void setupTotpRegister() {
        loginPage.open();
        loginPage.clickRegister();
        registerPage.register("firstName", "lastName", "email@mail.com", "setupTotp", "password", "password");

        String userId = events.expectRegister("setupTotp", "email@mail.com").assertEvent().getUserId();

        doAIA();
        
        assertTrue(totpPage.isCurrent());

        totpPage.configure(totp.generateTOTP(totpPage.getTotpSecret()));

        events.poll(); // skip to totp event
        String authSessionId = events.expectRequiredAction(EventType.UPDATE_TOTP).user(userId).detail(Details.USERNAME, "setuptotp").assertEvent()
                .getDetails().get(Details.CODE_ID);

        assertKcActionStatus("success");
        
        events.expectLogin().user(userId).session(authSessionId).detail(Details.USERNAME, "setuptotp").assertEvent();
    }
    
    @Test
    public void cancelSetupTotp() throws Exception {
        try {
            // Emulate former (pre KEYCLOAK-11745 change) OPTIONAL requirement by:
            // * Disabling the CONFIGURE_TOTP required action on realm
            // * Marking "Browser - Conditional OTP" authenticator as CONDITIONAL
            // * Marking "Condition - user configured" authenticator as DISABLED, and
            // * Marking "OTP Form" authenticator as ALTERNATIVE
            preConfigureRealmForCancelSetupTotpTest();

            doAIA();

            loginPage.login("test-user@localhost", "password");

            assertKcActionStatus("error");
        } finally {
            // Revert the realm setup changes done within the test
            postConfigureRealmForCancelSetupTotpTest();
        }
    }

    private void preConfigureRealmForCancelSetupTotpTest() {
        // Disable CONFIGURE_TOTP required action
        configureRealmEnableRequiredActionByAlias("CONFIGURE_TOTP", false);
        // Set "Browser - Conditional OTP" execution requirement to CONDITIONAL
        configureRealmSetExecutionRequirementByDisplayName("browser", "Browser - Conditional OTP", AuthenticationExecutionModel.Requirement.CONDITIONAL);
        // Set "Condition - user configured" execution requirement to DISABLED
        configureRealmSetExecutionRequirementByDisplayName("browser", "Condition - user configured", AuthenticationExecutionModel.Requirement.DISABLED);
        // Set "OTP Form" execution requirement to ALTERNATIVE
        configureRealmSetExecutionRequirementByDisplayName("browser", "OTP Form", AuthenticationExecutionModel.Requirement.ALTERNATIVE);
    }

    private void postConfigureRealmForCancelSetupTotpTest() {
        // Revert changes done in preConfigureRealmForCancelSetupTotpTest() call
        // Enable CONFIGURE_TOTP required action back (the default)
        configureRealmEnableRequiredActionByAlias("CONFIGURE_TOTP", true);

        // Set requirement of "Browser - Conditional OTP", "Condition - user configured",
        // and "OTP Form" browser flow executions back to REQUIRED (the default)
        List<String> executionDisplayNames = Arrays.asList("Browser - Conditional OTP", "Condition - user configured", "OTP Form");
        executionDisplayNames.stream().forEach(name -> configureRealmSetExecutionRequirementByDisplayName("browser", name, AuthenticationExecutionModel.Requirement.REQUIRED));
    }

    protected void configureRealmEnableRequiredActionByAlias(final String alias, final boolean value) {
        adminClient.realm("test").flows().getRequiredActions()
                .stream()
                .filter(action -> action.getAlias().equals(alias))
                .forEach(action -> {
                        action.setEnabled(value);
                        adminClient.realm("test").flows().updateRequiredAction(alias, action);
        });
    }

    protected void configureRealmSetExecutionRequirementByDisplayName(final String flowAlias, final String executionDisplayName, final AuthenticationExecutionModel.Requirement value) {
        adminClient.realm("test").flows().getExecutions(flowAlias)
                .stream()
                .filter(execution -> execution.getDisplayName().equals(executionDisplayName))
                .forEach(execution -> {
                        execution.setRequirement(value.name());
                        adminClient.realm("test").flows().updateExecutions(flowAlias, execution);
        });
    }

    @Test
    public void setupTotpRegisterManual() {
        loginPage.open();
        loginPage.clickRegister();
        registerPage.register("firstName", "lastName", "checkQrCode@mail.com", "checkQrCode", "password", "password");
        
        doAIA();
        
        String pageSource = driver.getPageSource();

        assertTrue(pageSource.contains("Install one of the following applications on your mobile"));
        assertTrue(pageSource.contains("FreeOTP"));
        assertTrue(pageSource.contains("Google Authenticator"));

        assertTrue(pageSource.contains("Open the application and scan the barcode"));
        assertFalse(pageSource.contains("Open the application and enter the key"));

        assertTrue(pageSource.contains("Unable to scan?"));
        assertFalse(pageSource.contains("Scan barcode?"));

        totpPage.clickManual();

        pageSource = driver.getPageSource();

        assertTrue(pageSource.contains("Install one of the following applications on your mobile"));
        assertTrue(pageSource.contains("FreeOTP"));
        assertTrue(pageSource.contains("Google Authenticator"));

        assertFalse(pageSource.contains("Open the application and scan the barcode"));
        assertTrue(pageSource.contains("Open the application and enter the key"));

        assertFalse(pageSource.contains("Unable to scan?"));
        assertTrue(pageSource.contains("Scan barcode?"));

        assertTrue(driver.findElement(By.id("kc-totp-secret-key")).getText().matches("[\\w]{4}( [\\w]{4}){7}"));

        assertEquals("Type: Time-based", driver.findElement(By.id("kc-totp-type")).getText());
        if (CryptoServicesRegistrar.isInApprovedOnlyMode())
            assertEquals("Algorithm: SHA256", driver.findElement(By.id("kc-totp-algorithm")).getText());
        else
            assertEquals("Algorithm: SHA1", driver.findElement(By.id("kc-totp-algorithm")).getText());
        assertEquals("Digits: 6", driver.findElement(By.id("kc-totp-digits")).getText());
        assertEquals("Interval: 30", driver.findElement(By.id("kc-totp-period")).getText());

        totpPage.clickBarcode();

        pageSource = driver.getPageSource();

        assertTrue(pageSource.contains("Install one of the following applications on your mobile"));
        assertTrue(pageSource.contains("FreeOTP"));
        assertTrue(pageSource.contains("Google Authenticator"));

        assertTrue(pageSource.contains("Open the application and scan the barcode"));
        assertFalse(pageSource.contains("Open the application and enter the key"));

        assertTrue(pageSource.contains("Unable to scan?"));
        assertFalse(pageSource.contains("Scan barcode?"));
    }

    // KEYCLOAK-7081
    @Test
    public void setupTotpRegisterManualModeSwitchesOnBadSubmit() {
        loginPage.open();
        loginPage.clickRegister();
        registerPage.register("firstName", "lastName", "setupTotpRegisterManualModeSwitchesOnBadSubmit@mail.com", "setupTotpRegisterManualModeSwitchesOnBadSubmit", "password", "password");

        doAIA();
        
        String pageSource = driver.getPageSource();

        assertTrue(pageSource.contains("Unable to scan?"));
        assertFalse(pageSource.contains("Scan barcode?"));

        totpPage.clickManual();

        pageSource = driver.getPageSource();

        assertFalse(pageSource.contains("Unable to scan?"));
        assertTrue(pageSource.contains("Scan barcode?"));

        totpPage.submit();

        pageSource = driver.getPageSource();

        assertFalse(pageSource.contains("Unable to scan?"));
        assertTrue(pageSource.contains("Scan barcode?"));

        assertEquals("Please specify authenticator code.", totpPage.getInputCodeError());
    }

    // KEYCLOAK-7081
    @Test
    public void setupTotpRegisterBarcodeModeSwitchesOnBadSubmit() {
        loginPage.open();
        loginPage.clickRegister();
        registerPage.register("firstName", "lastName", "setupTotpRegisterBarcodeModeSwitchesOnBadSubmit@mail.com", "setupTotpRegisterBarcodeModeSwitchesOnBadSubmit", "password", "password");

        doAIA();
        
        String pageSource = driver.getPageSource();

        assertTrue(pageSource.contains("Unable to scan?"));
        assertFalse(pageSource.contains("Scan barcode?"));

        totpPage.submit();

        pageSource = driver.getPageSource();

        assertTrue(pageSource.contains("Unable to scan?"));
        assertFalse(pageSource.contains("Scan barcode?"));

        assertEquals("Please specify authenticator code.", totpPage.getInputCodeError());

        totpPage.clickManual();

        pageSource = driver.getPageSource();

        assertFalse(pageSource.contains("Unable to scan?"));
        assertTrue(pageSource.contains("Scan barcode?"));
    }

    @Test
    public void setupTotpModifiedPolicy() {
        RealmResource realm = testRealm();
        RealmRepresentation rep = realm.toRepresentation();
        rep.setOtpPolicyDigits(8);
        rep.setOtpPolicyType("hotp");
        rep.setOtpPolicyAlgorithm("HmacSHA256");
        realm.update(rep);
        try {
            loginPage.open();
            loginPage.clickRegister();
            registerPage.register("firstName", "lastName", "setupTotpModifiedPolicy@mail.com", "setupTotpModifiedPolicy", "password", "password");

            doAIA();
            
            String pageSource = driver.getPageSource();

            assertTrue(pageSource.contains("FreeOTP"));
            assertFalse(pageSource.contains("Google Authenticator"));

            totpPage.clickManual();

            assertEquals("Type: Counter-based", driver.findElement(By.id("kc-totp-type")).getText());
            assertEquals("Algorithm: SHA256", driver.findElement(By.id("kc-totp-algorithm")).getText());
            assertEquals("Digits: 8", driver.findElement(By.id("kc-totp-digits")).getText());
            assertEquals("Counter: 0", driver.findElement(By.id("kc-totp-counter")).getText());
        } finally {
            rep.setOtpPolicyDigits(6);
            rep.setOtpPolicyType("totp");
            rep.setOtpPolicyAlgorithm("HmacSHA256");
            realm.update(rep);
        }
    }

    @Test
    public void setupTotpExisting() {
        doAIA();
        
        loginPage.login("test-user@localhost", "password");
        
        totpPage.assertCurrent();

        String totpSecret = totpPage.getTotpSecret();

        totpPage.configure(totp.generateTOTP(totpSecret));

        String authSessionId = events.expectRequiredAction(EventType.UPDATE_TOTP).assertEvent()
                .getDetails().get(Details.CODE_ID);

        assertKcActionStatus("success");

        EventRepresentation loginEvent = events.expectLogin().session(authSessionId).assertEvent();

        oauth.openLogout();

        events.expectLogout(authSessionId).assertEvent();

        loginPage.open();
        loginPage.login("test-user@localhost", "password");
        
        loginTotpPage.login(totp.generateTOTP(totpSecret));

        events.expectLogin().assertEvent();
    }

    @Test
    @DisableFeature(value = Profile.Feature.ACCOUNT2, skipRestart = true) // TODO remove this (KEYCLOAK-16228)
    public void setupTotpRegisteredAfterTotpRemoval() {
        // Register new user
        loginPage.open();
        loginPage.clickRegister();
        registerPage.register("firstName2", "lastName2", "email2@mail.com", "setupTotp2", "password2", "password2");

        String userId = events.expectRegister("setupTotp2", "email2@mail.com").assertEvent().getUserId();

        doAIA();
        
        // Configure totp
        totpPage.assertCurrent();

        String totpCode = totpPage.getTotpSecret();
        totpPage.configure(totp.generateTOTP(totpCode));

        // After totp config, user should be on the app page
        assertKcActionStatus("success");

        events.poll();
        events.expectRequiredAction(EventType.UPDATE_TOTP).user(userId).detail(Details.USERNAME, "setuptotp2").assertEvent();

        EventRepresentation loginEvent = events.expectLogin().user(userId).detail(Details.USERNAME, "setuptotp2").assertEvent();

        // Logout
        oauth.openLogout();
        events.expectLogout(loginEvent.getSessionId()).user(userId).assertEvent();

        // Try to login after logout
        loginPage.open();
        loginPage.login("setupTotp2", "password2");

        // Totp is already configured, thus one-time password is needed, login page should be loaded
        String uri = driver.getCurrentUrl();
        String src = driver.getPageSource();
        assertTrue(loginPage.isCurrent());
        Assert.assertFalse(totpPage.isCurrent());

        // Login with one-time password
        loginTotpPage.login(totp.generateTOTP(totpCode));

        loginEvent = events.expectLogin().user(userId).detail(Details.USERNAME, "setupTotp2").assertEvent();

        // Open account page
        accountTotpPage.open();
        accountTotpPage.assertCurrent();

        // Remove google authentificator
        accountTotpPage.removeTotp();

        events.expectAccount(EventType.REMOVE_TOTP).user(userId).assertEvent();

        // Logout
        oauth.openLogout();
        events.expectLogout(loginEvent.getSessionId()).user(userId).assertEvent();

        // Try to login
        loginPage.open();
        loginPage.login("setupTotp2", "password2");
    }

    @Test
    public void setupOtpPolicyChangedTotp8Digits() {
        // set policy to 8 digits
        RealmRepresentation realmRep = adminClient.realm("test").toRepresentation();
        RealmBuilder.edit(realmRep)
                    .otpLookAheadWindow(1)
                    .otpDigits(8)
                    .otpPeriod(30)
                    .otpType(OTPCredentialModel.TOTP)
                    .otpAlgorithm(HmacOTP.HMAC_SHA256)
                    .otpInitialCounter(0);
        adminClient.realm("test").update(realmRep);


        doAIA();
        
        loginPage.login("test-user@localhost", "password");

        totpPage.assertCurrent();

        String totpSecret = totpPage.getTotpSecret();

        TimeBasedOTP timeBased = new TimeBasedOTP(HmacOTP.HMAC_SHA256, 8, 30, 1);
        totpPage.configure(timeBased.generateTOTP(totpSecret));

        String sessionId = events.expectRequiredAction(EventType.UPDATE_TOTP).assertEvent()
                .getDetails().get(Details.CODE_ID);

        assertKcActionStatus("success");

        EventRepresentation loginEvent = events.expectLogin().session(sessionId).assertEvent();

        oauth.openLogout();

        events.expectLogout(loginEvent.getSessionId()).assertEvent();

        loginPage.open();
        loginPage.login("test-user@localhost", "password");
        String src = driver.getPageSource();
        String token = timeBased.generateTOTP(totpSecret);
        assertEquals(8, token.length());
        loginTotpPage.login(token);

        assertKcActionStatus(null);

        events.expectLogin().assertEvent();

        // Revert
        realmRep = adminClient.realm("test").toRepresentation();
        RealmBuilder.edit(realmRep)
                .otpDigits(6);
        adminClient.realm("test").update(realmRep);
    }

    @Test
    public void setupOtpPolicyChangedHotp() {
        RealmRepresentation realmRep = adminClient.realm("test").toRepresentation();
        RealmBuilder.edit(realmRep)
                    .otpLookAheadWindow(0)
                    .otpDigits(6)
                    .otpPeriod(30)
                    .otpType(OTPCredentialModel.HOTP)
                    .otpAlgorithm(HmacOTP.HMAC_SHA256)
                    .otpInitialCounter(0);
        adminClient.realm("test").update(realmRep);

        doAIA();

        loginPage.login("test-user@localhost", "password");

        totpPage.assertCurrent();

        String totpSecret = totpPage.getTotpSecret();

        HmacOTP otpgen = new HmacOTP(6, HmacOTP.HMAC_SHA256, 1);
        totpPage.configure(otpgen.generateHOTP(totpSecret, 0));

        String sessionId = events.expectRequiredAction(EventType.UPDATE_TOTP).assertEvent()
            .getDetails().get(Details.CODE_ID);
        
        //RequestType reqType = appPage.getRequestType();
        assertKcActionStatus("success");
        EventRepresentation loginEvent = events.expectLogin().session(sessionId).assertEvent();

        oauth.openLogout();

        events.expectLogout(loginEvent.getSessionId()).assertEvent();

        loginPage.open();
        loginPage.login("test-user@localhost", "password");
        String token = otpgen.generateHOTP(totpSecret, 1);
        loginTotpPage.login(token);

        assertKcActionStatus(null);

        events.expectLogin().assertEvent();

        oauth.openLogout();
        events.expectLogout(null).session(AssertEvents.isUUID()).assertEvent();

        // test lookAheadWindow
        realmRep = adminClient.realm("test").toRepresentation();
        RealmBuilder.edit(realmRep)
                    .otpLookAheadWindow(5)
                    .otpDigits(6)
                    .otpPeriod(30)
                    .otpType(OTPCredentialModel.HOTP)
                    .otpAlgorithm(HmacOTP.HMAC_SHA256)
                    .otpInitialCounter(0);
        adminClient.realm("test").update(realmRep);


        loginPage.open();
        loginPage.login("test-user@localhost", "password");
        token = otpgen.generateHOTP(totpSecret, 4);
        loginTotpPage.assertCurrent();
        loginTotpPage.login(token);

        assertKcActionStatus(null);

        events.expectLogin().assertEvent();

        // Revert
        realmRep = adminClient.realm("test").toRepresentation();
        RealmBuilder.edit(realmRep)
                .otpLookAheadWindow(1)
                .otpDigits(6)
                .otpPeriod(30)
                .otpType(OTPCredentialModel.TOTP)
                .otpAlgorithm(HmacOTP.HMAC_SHA256)
                .otpInitialCounter(0);
        adminClient.realm("test").update(realmRep);

    }

}
