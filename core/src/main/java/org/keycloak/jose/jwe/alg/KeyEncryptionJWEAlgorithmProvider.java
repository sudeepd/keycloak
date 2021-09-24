/*
 * Copyright 2018 Red Hat, Inc. and/or its affiliates
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

package org.keycloak.jose.jwe.alg;

import java.security.Key;
import java.security.SecureRandom;

import javax.crypto.Cipher;

import org.bouncycastle.crypto.KeyUnwrapperUsingSecureRandom;
import org.bouncycastle.crypto.KeyWrapperUsingSecureRandom;
import org.bouncycastle.crypto.asymmetric.AsymmetricRSAPrivateKey;
import org.bouncycastle.crypto.asymmetric.AsymmetricRSAPublicKey;
import org.bouncycastle.crypto.fips.FipsKeyUnwrapperUsingSecureRandom;
import org.bouncycastle.crypto.fips.FipsKeyWrapperUsingSecureRandom;
import org.bouncycastle.crypto.fips.FipsRSA;
import org.keycloak.jose.jwe.JWEKeyStorage;
import org.keycloak.jose.jwe.enc.JWEEncryptionProvider;

/**
 * Fips note , Based on https://downloads.bouncycastle.org/fips-java/BC-FJA-UserGuide-1.0.2.pdf, Section 4
 * There are no direct public/private key ciphers available in approved mode. Available ciphers are
 * restricted to use for key wrapping and key transport, see section 7 and section 8 for details.
 * Our solution is to pull out the CEK signature and encryption keys , encode them separately , and then
 */
public abstract class KeyEncryptionJWEAlgorithmProvider implements JWEAlgorithmProvider {

    @Override
    public byte[] decodeCek(byte[] encodedCek, Key privateKey) throws Exception {
        AsymmetricRSAPrivateKey rsaPrivateKey =
                new AsymmetricRSAPrivateKey(FipsRSA.ALGORITHM, privateKey.getEncoded());

        FipsRSA.KeyWrapOperatorFactory wrapFact =
                new FipsRSA.KeyWrapOperatorFactory();
        KeyUnwrapperUsingSecureRandom<FipsRSA.WrapParameters> unwrapper =
                wrapFact.createKeyUnwrapper(rsaPrivateKey, FipsRSA.WRAP_OAEP)
                        .withSecureRandom(SecureRandom.getInstance("DEFAULT"));
        return unwrapper.unwrap(encodedCek, 0, encodedCek.length);
    }


    @Override
    public byte[] encodeCek(JWEEncryptionProvider encryptionProvider, JWEKeyStorage keyStorage, Key publicKey) throws Exception {
        AsymmetricRSAPublicKey rsaPubKey =
                new AsymmetricRSAPublicKey(FipsRSA.ALGORITHM, publicKey.getEncoded());
        byte[] inputKeyBytes = keyStorage.getCekBytes();
        FipsRSA.KeyWrapOperatorFactory wrapFact =
                new FipsRSA.KeyWrapOperatorFactory();

        KeyWrapperUsingSecureRandom<FipsRSA.WrapParameters> wrapper =
                wrapFact.createKeyWrapper(rsaPubKey, FipsRSA.WRAP_OAEP).withSecureRandom( SecureRandom.getInstance("DEFAULT"));
        return wrapper.wrap(inputKeyBytes, 0, inputKeyBytes.length);
    }

    protected abstract Cipher getCipherProvider() throws Exception;

}
