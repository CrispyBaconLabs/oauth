/*
 * Copyright 2007 Netflix, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package net.oauth.signature;

import net.oauth.OAuth;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.util.Arrays;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * @author John Kristian
 */
class HMAC_SHA1 extends OAuthSignatureMethod {

    @Override
    protected String getSignature(byte[] toSign)
            throws GeneralSecurityException, UnsupportedEncodingException {
        String signature = base64Encode(computeSignature(toSign));
        return signature;
    }

    @Override
    protected boolean isValid(String signature, byte[] signed)
            throws GeneralSecurityException, UnsupportedEncodingException {
        byte[] expected = computeSignature(signed);
        byte[] actual = decodeBase64(signature);
        return Arrays.equals(expected, actual);
    }

    private byte[] computeSignature(byte[] toSign)
            throws GeneralSecurityException, UnsupportedEncodingException {
        SecretKey key = null;
        synchronized (this) {
            if (this.key == null) {
                String keyString = OAuth.percentEncode(getConsumerSecret())
                        + '&' + OAuth.percentEncode(getTokenSecret());
                byte[] keyBytes = keyString.getBytes(ENCODING);
                this.key = new SecretKeySpec(keyBytes, MAC_NAME);
            }
            key = this.key;
        }
        Mac mac = Mac.getInstance(MAC_NAME);
        mac.init(key);
        return mac.doFinal(toSign);
    }

    /** ISO-8859-1 or US-ASCII would work, too. */
    private static final String ENCODING = OAuth.ENCODING;

    private static final String MAC_NAME = "HmacSHA1";

    private SecretKey key = null;

    @Override
    public void setConsumerSecret(String consumerSecret) {
        synchronized (this) {
            key = null;
        }
        super.setConsumerSecret(consumerSecret);
    }

    @Override
    public void setTokenSecret(String tokenSecret) {
        synchronized (this) {
            key = null;
        }
        super.setTokenSecret(tokenSecret);
    }

}
