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

import org.bouncycastle.crypto.Algorithm;
import org.bouncycastle.crypto.KeyUnwrapperUsingSecureRandom;
import org.bouncycastle.crypto.KeyWrapperUsingSecureRandom;
import org.bouncycastle.crypto.asymmetric.AsymmetricRSAPrivateKey;
import org.bouncycastle.crypto.asymmetric.AsymmetricRSAPublicKey;
import org.bouncycastle.crypto.fips.FipsDigestAlgorithm;
import org.bouncycastle.crypto.fips.FipsRSA;
import org.bouncycastle.crypto.fips.FipsSHS;
import org.keycloak.jose.jwe.JWEKeyStorage;
import org.keycloak.jose.jwe.enc.JWEEncryptionProvider;

import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import java.security.AlgorithmParameters;
import java.security.Key;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.MGF1ParameterSpec;

public class RsaKeyEncryption256JWEAlgorithmProvider extends KeyEncryptionJWEAlgorithmProvider {

    private final String jcaAlgorithmName;

    public RsaKeyEncryption256JWEAlgorithmProvider(String jcaAlgorithmName) {
        this.jcaAlgorithmName = jcaAlgorithmName;
    }

    @Override
    protected Cipher getCipherProvider() throws Exception {
        return Cipher.getInstance(jcaAlgorithmName);
    }

    @Override
    public byte[] decodeCek(byte[] encodedCek, Key privateKey) throws Exception {
        AsymmetricRSAPrivateKey rsaPrivateKey =
                new AsymmetricRSAPrivateKey(FipsRSA.ALGORITHM, privateKey.getEncoded());

        FipsRSA.KeyWrapOperatorFactory wrapFact =
                new FipsRSA.KeyWrapOperatorFactory();
        FipsRSA.WrapParameters oaepParams = FipsRSA.WRAP_OAEP.withDigest(FipsSHS.Algorithm.SHA256);
        KeyUnwrapperUsingSecureRandom<FipsRSA.WrapParameters> unwrapper =
                wrapFact.createKeyUnwrapper(rsaPrivateKey, oaepParams)
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

        FipsRSA.WrapParameters oaepParams = FipsRSA.WRAP_OAEP.withDigest(FipsSHS.Algorithm.SHA256);
        KeyWrapperUsingSecureRandom<FipsRSA.WrapParameters> wrapper =
                wrapFact.createKeyWrapper(rsaPubKey, oaepParams).withSecureRandom( SecureRandom.getInstance("DEFAULT"));
        return wrapper.wrap(inputKeyBytes, 0, inputKeyBytes.length);
    }


//    @Override
//    public byte[] decodeCek(byte[] encodedCek, Key privateKey) throws Exception {
//        AlgorithmParameters algp = AlgorithmParameters.getInstance("OAEP");
//        AlgorithmParameterSpec paramSpec = new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256,
//                PSource.PSpecified.DEFAULT);
//        algp.init(paramSpec);
//        Cipher cipher = getCipherProvider();
//        cipher.init(Cipher.DECRYPT_MODE, privateKey, algp);
//        return cipher.doFinal(encodedCek);
//    }
//
//    @Override
//    public byte[] encodeCek(JWEEncryptionProvider encryptionProvider, JWEKeyStorage keyStorage, Key publicKey)
//            throws Exception {
//        AlgorithmParameters algp = AlgorithmParameters.getInstance("OAEP");
//        AlgorithmParameterSpec paramSpec = new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256,
//                PSource.PSpecified.DEFAULT);
//        algp.init(paramSpec);
//        Cipher cipher = getCipherProvider();
//        cipher.init(Cipher.ENCRYPT_MODE, publicKey, algp);
//        byte[] cekBytes = keyStorage.getCekBytes();
//        return cipher.doFinal(cekBytes);
//    }
}
