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

package org.keycloak;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.util.ASN1Dump;
import org.junit.Assert;
import org.junit.Test;
import org.keycloak.common.VerificationException;
import org.keycloak.common.util.Base64;
import org.keycloak.common.util.PemUtils;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;

/**
 * @author <a href="mailto:sthorger@redhat.com">Stian Thorgersen</a>
 */
public class KeyPairVerifierTest {
    /**
     * The original entries here are NOT PKCS#8 keys, they are missing the algo id as the second field in
     * the ASN representation. We fix it by changing the entries from openssl pem to PKCS#8
     */

    /**
     * Also , the original key cloak "privateKey1" item is a 1024 bit key and is not allowed
     * So, we use openssl command to generate another 2048 b=bit key, and push it here as
     * the privateKey1 and publicKey1
     */


//    String privateKey1 = "MIICXAIBAAKBgQCrVrCuTtArbgaZzL1hvh0xtL5mc7o0NqPVnYXkLvgcwiC3BjLGw1tGEGoJaXDuSaRllobm53JBhjx33UNv+5z/UMG4kytBWxheNVKnL6GgqlNabMaFfPLPCF8kAgKnsi79NMo+n6KnSY8YeUmec/p2vjO2NjsSAVcWEQMVhJ31LwIDAQABAoGAfmO8gVhyBxdqlxmIuglbz8bcjQbhXJLR2EoS8ngTXmN1bo2L90M0mUKSdc7qF10LgETBzqL8jYlQIbt+e6TH8fcEpKCjUlyq0Mf/vVbfZSNaVycY13nTzo27iPyWQHK5NLuJzn1xvxxrUeXI6A2WFpGEBLbHjwpx5WQG9A+2scECQQDvdn9NE75HPTVPxBqsEd2z10TKkl9CZxu10Qby3iQQmWLEJ9LNmy3acvKrE3gMiYNWb6xHPKiIqOR1as7L24aTAkEAtyvQOlCvr5kAjVqrEKXalj0Tzewjweuxc0pskvArTI2Oo070h65GpoIKLc9jf+UA69cRtquwP93aZKtW06U8dQJAF2Y44ks/mK5+eyDqik3koCI08qaC8HYq2wVl7G2QkJ6sbAaILtcvD92ToOvyGyeE0flvmDZxMYlvaZnaQ0lcSQJBAKZU6umJi3/xeEbkJqMfeLclD27XGEFoPeNrmdx0q10Azp4NfJAY+Z8KRyQCR2BEG+oNitBOZ+YXF9KCpH3cdmECQHEigJhYg+ykOvr1aiZUMFT72HU0jnmQe2FVekuG+LJUt2Tm7GtMjTFoGpf0JwrVuZN39fOYAlo+nTixgeW7X8Y=";
//    String publicKey1 = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCrVrCuTtArbgaZzL1hvh0xtL5mc7o0NqPVnYXkLvgcwiC3BjLGw1tGEGoJaXDuSaRllobm53JBhjx33UNv+5z/UMG4kytBWxheNVKnL6GgqlNabMaFfPLPCF8kAgKnsi79NMo+n6KnSY8YeUmec/p2vjO2NjsSAVcWEQMVhJ31LwIDAQAB";

//    String privateKey2048 = "-----BEGIN RSA PRIVATE KEY-----\n" + "MIIEpQIBAAKCAQEA4V3MpOnuKsdBbR1UzNjK9o5meEMQ4s5Vpykhv1DpqTilKOiE\n"
//            + "H7VQ/XtjNxw0yjnFBilCnpK6yN9mDEHbBEzaRjtdrgVhkIejiaXFBP5MBhUQ5l9u\n" + "8E3IZC3E8pwDjVF0Z9u0R4lGeUg2k6O+NKumqIvxoLCTuG0zf53bctGsRd57LuFi\n"
//            + "pgCkNyxvscOhulsbEMYrLwlb5bMGgx9v+RCnwvunNEb7RK+5pzP+iH1MRejRsX+U\n" + "7h9zHRn2gQhIl7SzG9GXebuPWr4KKwfMHWy0PEuQrsfWRXm9/dTEavbfNkv5E53z\n"
//            + "WXjWyf93ezkVhBX0YoXmf6UO7PAlvsrjno3TuwIDAQABAoIBAQC5iCAOcCtLemhp\n" + "bOlADwXgPtErFoNTROyMxjbrKrCCSIjniawj8oAvfiHq38Sx6ydBcDxREZjF/+wi\n"
//            + "ESE+hAp6ISt5NSLh+lhu3FK7TqLFqxgTn+NT36Umm+t0k231LGa5jcz3y5KCDCoq\n" + "F3ZiJCH6xeLxGA00mmn4GLvt5aF+jiO80ICGs4iUg99IoXhc5u/VU0hB5J78BinW\n"
//            + "inkCABuBNkDLgIqc9BoH4L5MOx3zDqzmHffeq9+2V4X7NiD5QyiyWtABaQpEIY5k\n" + "R48RTno6xN3hvG48/DwkO2gABSLQ/OJd3Hupv4wlmmSc1xo93CaV44hq2i2GsU1i\n"
//            + "m6d3xDW5AoGBAPCfkvPkqr88xg+8Cu3G/3GFpUsQ0VEme+8dIjXMTJHa13K7xaRh\n" + "GHCVg4a8oHJ/P/vNSwvPyR71iRX4csqkKSaprvJk8vxbU539unmHWKkfUHrywQlz\n"
//            + "q4OuXOjOdvILLOTsu3/+k6vAIE6SZJiDmf2eGxi9Qbm5rlxE3h3HRAKfAoGBAO/E\n" + "ogHV86LmnJTJbx1hP3IfRHk0qaiSj35ljlAz+3v6GN/KSUYCWTtp2GjRIKY3qQ8I\n"
//            + "7l+PVTFg3SY7cPq2C9TE+6xroiWkUd2JldPLYSxpWpFNYlo709SzmLquDho+fwJC\n" + "nAxoxKghsXJarz7TRfNyFqDXscS6oQLurU9P5lVlAoGBAJh1QvLtS5Jnu0Z06qfF\n"
//            + "kkwnVZe+TCGStKvIVciobUts0V2Mw6lnK8kJspBIK5DgN3YfmREe0lufTwBwrqre\n" + "YIRytro2ZA6o/s332ZLuwqpFgQSlktGeTGnerFeFma+6jPNvW025y27jCJVABCTu\n"
//            + "HT+oUZrXLzGyCFvF9sX/X4QZAoGBAICap4r0h0nJCBOGN+M6Vh2QR9n7NUUF15Gk\n" + "R0EdoLZO3yiqB8NVXydPDpSqFykQkc1OrQz0hG2H1xa6q07OdmoZfiRtVvt5t69s\n"
//            + "LMD9RZHcsIdfSnG7xVNBQZpf4ZCSFO3RbIH7b//+kn8TxQudptd9SkXba65prBM2\n" + "kh8IbDNBAoGAVsKvkruH7RK7CimDSWcdAKvHARqkjs/PoeKEEY8Yu6zf0Z9TQM5l\n"
//            + "uC9EwBamYcSusWRcdcz+9HYG58XFnmXq+3EUuFbJ+Ljb8YWBgePjSHDoS/6+/+zq\n" + "B1b5uQp/jYFbYQl50UPRPTF+ul1eQoy7F43Ngj3/5cDRarFZe3ZTzZo=\n"
//            + "-----END RSA PRIVATE KEY-----";

    String privateKey1 = "MIIG/QIBADANBgkqhkiG9w0BAQEFAASCBucwggbjAgEAAoIBgQDFKJH6tUMTqXBC" +
            "Gttwy3WSiIhL/yUM58w/2PNFcJwPNMxmrABmE4gLJ8PkzSVGl3BiIgBHhW+VE9QB" +
            "nJvFqrIc1o4lh5n2Uz8SmygpW9SLQDa3ctl76wbc/CEhJD1KK7lTdr42WFYaqKi/" +
            "cyjjHC4W6/tKTlNLABMV9TfW3LPxspmLdwuqop8FcaTPxEZY6JvpYS5RJt8uen64" +
            "BZlslLM5M9IFCTJYiFH3zCgIihMFOAQDEhaTepPMgerrYjHg3urT4b1j6+KKQNvQ" +
            "1dsoITTyOW6q9D5udcZrFbbYRHWsmPB5Qo0PMgDc9dPLP5BDIWwa1mCaXgbx2PnX" +
            "/U8dCIPnrlHsrVeDw+H8xZ9Dq2q9cizd3PiX1NuXNyIOXfPFDtQgScMBZW9ukE7m" +
            "1iNLlPTIQiVuovG0jWTxEC2uvJdEYnpH2dKIEzzHITncBEBspCI53ebYHkZHaRRr" +
            "JVkCTv59j/t29TE43N1lLAemEB3ewCSBekPbBhp0E7yOZQFyJbUCAwEAAQKCAYAU" +
            "bgLKbtP3ipw2TWAlzP9u4rT04whs0OwqRYnXzTZuoPL5RKN58FYtib5TzCorqW+c" +
            "y5cp0hrg4MAcNqUxk2GHeXgbTXTXwIKNpARCXOCmWU4SLlV48L6yUXIBZCbxs5wt" +
            "mOVW7kpl0spBpGY9OmNQPr24UmtxHx3bLaDOo+oFhpNAj2JnGRjPUJpaaSU8+0WE" +
            "pmxNPnDr+Qd+fB4M0U/NAqClovFTmTSdL8uKLvyPkuFfjBVIzO/ZxjCYmYE/ovmV" +
            "dsWyJ+ISInepzXkm2qPL10AR13ikszos+CW6Tz3v5sp6EQV/b6oAn7u2AwA8fU3m" +
            "O1raoKLO5R/Z4aN0BvfLyqdmcM88CVPEg9Kyq3hkyWq3deMM1BM8AP302hkFscZd" +
            "iUeeIyhQKrhMEFv4rj7GvwFmCtzfcj7+YAwks1Gyd4CwKW0nXqNVdUIuZyO6oV91" +
            "lpEdKAHQDV+/hxKR9a4Sjy1QPtzhmSASVPRS4eFn0fxFDGppvqcyIORWVqfM+iEC" +
            "gcEA/jAT4HAZg4gn+UAJxOs83D6zUN6WPEiI5t2+8bpBiVW+XjMATPITuzfeaSRl" +
            "ckf/G0XOIRk+cfEPHYBmsbHMyXUKA+9RQdyxF5u3tlDAdSPh4+XmNVebA51aCxxS" +
            "yuKYOIaSPpNPRrFcdzx0wQ/iV/UNaxpTUKQaVa/x4S5jPFNBoRqAGTx9iWmX0Gzz" +
            "+DkyCLmOBt3XZP2QgiS3si3VZOczB6hrChiumdU9TBIdnZWaUu3ypIzNy6oP19aM" +
            "HVgtAoHBAMaQaEzzsNL7IdTnUgjvOZ9rtoXxhmm/NSPtrdi0yrtN9nl5CtZ8o7mY" +
            "ZlU5gQKgac/BYvBCbfgfwXM449U2rfd99R+CD5MLH6LLdzJY7cATgR0mvTzwOcAc" +
            "vfQZoxiaFKasVx7sRTMac/iHUnIoz3OWyTALPemBOzQCYud5Oo+l2juvBmfpFDTW" +
            "EWoywYMw61SdI6Muc+8A9BmZwF/Dq760eUr9uAdpFOq9VtEIDiNoleeAT+zPvaTU" +
            "CbPq/8SwqQKBwQCY0H6ip8Iu+WROzNkSsfnczzUuoSLhCxqC8T0iRj+wOQRBzZeY" +
            "qtCB9YyY2XDDy9TqqITMEUkhZzMXIWKb4bCkTODAjNflKLCu6McBrHqH8hKT2FsW" +
            "JpzjB25iz5xWrPOmyACT7ivy7B4S8R2gE9SX3JM8mI8OJBpQ+X4JSsIOOl9yY2Qv" +
            "x9YRDpJek6H40SnrZOKl7ijYZjjChSCK1lM8XmKnb/EqGLyfbztyyFFVs+MbiEIf" +
            "+yaeEpeDw1BpM+ECgcBNUtTbCpbUQil1kDMY+Ze15iso09ok+enGuPrXBehgskaG" +
            "HUXEKrtTPe6zx3XewPsThVpy91t9oVgi94d5cxah5zH6eBp6h31lVthvCcRj5PSF" +
            "lp1gyqeikU7DbOxfWzkpgrlWeGmmMenxYTkQ7aWDfLeR9v7AHKwiX7+GJmZQpCRs" +
            "04aqFlDhFm+nrGZBIV6zD5JeLGvHKdbk1UPdxwPterg1JMJyWFBl7R+OvRVMYqDl" +
            "iskVDfzq4At7PcsmHCkCgcAnoUpOOTTk2VjH1eRdVQKPUCAy8JTgXbufEfGGdfPb" +
            "01lUxEqoqykymu2T0G0uSHYL07WOIvJq3T7IInztVABf2cXeork3gfAzw+ydnckG" +
            "HS7cx9b3O04b3HJv2qgCdpDhEDfb7ZoVRANealm7d886AJkR3gJhJyNd6RdbTk64" +
            "/HEMXbysF6poRJMS3wPyosSZErZJJIGFDfdn0LQ0XmJdiuB+U94K8LlNYpaQRxh2" +
            "lF8vIwC4f4cuZqD9xOW4ibw=" ;


    String publicKey1 = "MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAxSiR+rVDE6lwQhrbcMt1" +
            "koiIS/8lDOfMP9jzRXCcDzTMZqwAZhOICyfD5M0lRpdwYiIAR4VvlRPUAZybxaqy" +
            "HNaOJYeZ9lM/EpsoKVvUi0A2t3LZe+sG3PwhISQ9Siu5U3a+NlhWGqiov3Mo4xwu" +
            "Fuv7Sk5TSwATFfU31tyz8bKZi3cLqqKfBXGkz8RGWOib6WEuUSbfLnp+uAWZbJSz" +
            "OTPSBQkyWIhR98woCIoTBTgEAxIWk3qTzIHq62Ix4N7q0+G9Y+viikDb0NXbKCE0" +
            "8jluqvQ+bnXGaxW22ER1rJjweUKNDzIA3PXTyz+QQyFsGtZgml4G8dj51/1PHQiD" +
            "565R7K1Xg8Ph/MWfQ6tqvXIs3dz4l9TblzciDl3zxQ7UIEnDAWVvbpBO5tYjS5T0" +
            "yEIlbqLxtI1k8RAtrryXRGJ6R9nSiBM8xyE53ARAbKQiOd3m2B5GR2kUayVZAk7+" +
            "fY/7dvUxONzdZSwHphAd3sAkgXpD2wYadBO8jmUBciW1AgMBAAE=";

    String privateKey2048= "-----BEGIN PRIVATE KEY-----\n" +
            "MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDhXcyk6e4qx0Ft\n" +
            "HVTM2Mr2jmZ4QxDizlWnKSG/UOmpOKUo6IQftVD9e2M3HDTKOcUGKUKekrrI32YM\n" +
            "QdsETNpGO12uBWGQh6OJpcUE/kwGFRDmX27wTchkLcTynAONUXRn27RHiUZ5SDaT\n" +
            "o740q6aoi/GgsJO4bTN/ndty0axF3nsu4WKmAKQ3LG+xw6G6WxsQxisvCVvlswaD\n" +
            "H2/5EKfC+6c0RvtEr7mnM/6IfUxF6NGxf5TuH3MdGfaBCEiXtLMb0Zd5u49avgor\n" +
            "B8wdbLQ8S5Cux9ZFeb391MRq9t82S/kTnfNZeNbJ/3d7ORWEFfRiheZ/pQ7s8CW+\n" +
            "yuOejdO7AgMBAAECggEBALmIIA5wK0t6aGls6UAPBeA+0SsWg1NE7IzGNusqsIJI\n" +
            "iOeJrCPygC9+IerfxLHrJ0FwPFERmMX/7CIRIT6ECnohK3k1IuH6WG7cUrtOosWr\n" +
            "GBOf41PfpSab63STbfUsZrmNzPfLkoIMKioXdmIkIfrF4vEYDTSaafgYu+3loX6O\n" +
            "I7zQgIaziJSD30iheFzm79VTSEHknvwGKdaKeQIAG4E2QMuAipz0Ggfgvkw7HfMO\n" +
            "rOYd996r37ZXhfs2IPlDKLJa0AFpCkQhjmRHjxFOejrE3eG8bjz8PCQ7aAAFItD8\n" +
            "4l3ce6m/jCWaZJzXGj3cJpXjiGraLYaxTWKbp3fENbkCgYEA8J+S8+SqvzzGD7wK\n" +
            "7cb/cYWlSxDRUSZ77x0iNcxMkdrXcrvFpGEYcJWDhrygcn8/+81LC8/JHvWJFfhy\n" +
            "yqQpJqmu8mTy/FtTnf26eYdYqR9QevLBCXOrg65c6M528gss5Oy7f/6Tq8AgTpJk\n" +
            "mIOZ/Z4bGL1BubmuXETeHcdEAp8CgYEA78SiAdXzouaclMlvHWE/ch9EeTSpqJKP\n" +
            "fmWOUDP7e/oY38pJRgJZO2nYaNEgpjepDwjuX49VMWDdJjtw+rYL1MT7rGuiJaRR\n" +
            "3YmV08thLGlakU1iWjvT1LOYuq4OGj5/AkKcDGjEqCGxclqvPtNF83IWoNexxLqh\n" +
            "Au6tT0/mVWUCgYEAmHVC8u1Lkme7RnTqp8WSTCdVl75MIZK0q8hVyKhtS2zRXYzD\n" +
            "qWcryQmykEgrkOA3dh+ZER7SW59PAHCuqt5ghHK2ujZkDqj+zffZku7CqkWBBKWS\n" +
            "0Z5Mad6sV4WZr7qM829bTbnLbuMIlUAEJO4dP6hRmtcvMbIIW8X2xf9fhBkCgYEA\n" +
            "gJqnivSHSckIE4Y34zpWHZBH2fs1RQXXkaRHQR2gtk7fKKoHw1VfJ08OlKoXKRCR\n" +
            "zU6tDPSEbYfXFrqrTs52ahl+JG1W+3m3r2wswP1Fkdywh19KcbvFU0FBml/hkJIU\n" +
            "7dFsgftv//6SfxPFC52m131KRdtrrmmsEzaSHwhsM0ECgYBWwq+Su4ftErsKKYNJ\n" +
            "Zx0Aq8cBGqSOz8+h4oQRjxi7rN/Rn1NAzmW4L0TAFqZhxK6xZFx1zP70dgbnxcWe\n" +
            "Zer7cRS4Vsn4uNvxhYGB4+NIcOhL/r7/7OoHVvm5Cn+NgVthCXnRQ9E9MX66XV5C\n" +
            "jLsXjc2CPf/lwNFqsVl7dlPNmg==\n" +
            "-----END PRIVATE KEY-----";
    String publicKey2048 = "-----BEGIN PUBLIC KEY-----\n" + "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4V3MpOnuKsdBbR1UzNjK\n"
            + "9o5meEMQ4s5Vpykhv1DpqTilKOiEH7VQ/XtjNxw0yjnFBilCnpK6yN9mDEHbBEza\n" + "RjtdrgVhkIejiaXFBP5MBhUQ5l9u8E3IZC3E8pwDjVF0Z9u0R4lGeUg2k6O+NKum\n"
            + "qIvxoLCTuG0zf53bctGsRd57LuFipgCkNyxvscOhulsbEMYrLwlb5bMGgx9v+RCn\n" + "wvunNEb7RK+5pzP+iH1MRejRsX+U7h9zHRn2gQhIl7SzG9GXebuPWr4KKwfMHWy0\n"
            + "PEuQrsfWRXm9/dTEavbfNkv5E53zWXjWyf93ezkVhBX0YoXmf6UO7PAlvsrjno3T\n" + "uwIDAQAB\n" + "-----END PUBLIC KEY-----";


    @Test
    public void loadKey() throws Exception{
        byte[] key = PemUtils.pemToDer( privateKey1);
        ASN1InputStream input = new ASN1InputStream(key);

        ASN1Primitive p;
        while ((p = input.readObject()) != null) {
            System.out.println(ASN1Dump.dumpAsString(p));
        }
        PKCS8EncodedKeySpec spec =
                new PKCS8EncodedKeySpec(key);
        KeyFactory kf = KeyFactory.getInstance("RSA", "BCFIPS");
        PrivateKey pk = kf.generatePrivate(spec);
        Assert.assertNotNull(pk);
    }

    @Test
    public void verify() throws Exception {
        KeyPairVerifier.verify(privateKey1, publicKey1);
        KeyPairVerifier.verify(privateKey2048, publicKey2048);

        try {
            KeyPairVerifier.verify(privateKey1, publicKey2048);
            Assert.fail("Expected VerificationException");
        } catch (VerificationException e) {
        }

        try {
            KeyPairVerifier.verify(privateKey2048, publicKey1);
            Assert.fail("Expected VerificationException");
        } catch (VerificationException e) {
        }
    }

}
