/*
 * Copyright (C) 2016 Yunify, Inc. All rights reserved.
 *
 * To demonsrate how to generate signature for API request against QingStor.
 */

import java.util.Map;
import java.util.HashMap;
import java.util.Arrays;
import java.util.Base64;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;

import java.net.URLEncoder;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class QSSignature {
    private static final String ENCODING = "UTF-8";
    private static final String ALGORITHM = "HmacSHA256";

    /**
     * Generate signature for request against QingStor.
     *
     * @param accessKey: API access key ID
     * @param secretKey: API secret access key ID
     * @param method: HTTP method
     * @param authPath:
     * @param params: HTTP request parameters
     * @param headers: HTTP request headers
     *
     * @return a string which can be used as value of HTTP request header field
     *         "Authorization" directly.
     *
     * See https://docs.qingcloud.com/qingstor/api/common/signature.html for
     * more details about how to do signature of request against QingStor.
     */
    private static String getAuth(String accessKey,
                                  String secretKey,
                                  String method,
                                  String authPath,
                                  Map<String, String> params,
                                  Map<String, String> headers) {
        final String SEPARATOR = "&";
        String signature = "";
        String strToSign = "";

        strToSign += method.toUpperCase() + "\n";

        String contentMD5 = "";
        String contentType = "";
        if (headers != null) {
            if (headers.containsKey("Content-MD5"))
                contentMD5 = headers.get("Content-MD5");
            if (headers.containsKey("Content-Type"))
                contentType = headers.get("Content-Type");
        }
        strToSign += contentMD5 + "\n";
        strToSign += contentType;

        // Append request time as string
        String dateStr = "";
        if (headers != null) {
            if (headers.containsKey("Date"))
                dateStr = headers.get("Date");
        }
        strToSign += "\n" + dateStr;

        // Generate signed headers.
        if (headers != null) {
            String[] sortedHeadersKeys = headers.keySet().toArray(new String[] {});
            Arrays.sort(sortedHeadersKeys);
            for (String key : sortedHeadersKeys) {
                if (!key.startsWith("x-qs-"))
                    continue;
                strToSign += String.format(
                    "\n%s:%s", key.toLowerCase(), headers.get(key)
                );
            }
        }

        // Generate canonicalized query string.
        String canonicalized_query = "";
        if (params != null) {
            String[] sortedParamsKeys = params.keySet().toArray(new String[] {});
            Arrays.sort(sortedParamsKeys);
            for (String key : sortedParamsKeys) {
                if (!canonicalized_query.isEmpty()) {
                    canonicalized_query += SEPARATOR;
                }
                try {
                    canonicalized_query += URLEncoder.encode(key, ENCODING);
                    String value = params.get(key);
                    if (!value.isEmpty()) {
                        canonicalized_query += "=" + URLEncoder.encode(value, ENCODING);
                    }
                } catch (UnsupportedEncodingException e) {
                    throw new RuntimeException(e);
                }
            }
        }

        // Generate canonicalized resource.
        String canonicalized_resource = authPath;
        if (!canonicalized_query.isEmpty())
            canonicalized_resource += "?" + canonicalized_query;

        strToSign += String.format("\n%s", canonicalized_resource);

        System.out.print("== String to sign ==\n" + strToSign + "\n");

        signature = genSignature(secretKey, strToSign);
        return String.format("QS-HMAC-SHA256 %s:%s", accessKey, signature);
    }

    private static String genSignature(String secretKey, String strToSign) {
        byte[] signData = null;
        try {
            Mac mac = Mac.getInstance(ALGORITHM);
            mac.init(new SecretKeySpec(secretKey.getBytes(ENCODING), ALGORITHM));
            signData = mac.doFinal(strToSign.getBytes(ENCODING));
        } catch (InvalidKeyException e) {
            throw new RuntimeException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        } catch (IllegalStateException e) {
            throw new RuntimeException(e);
        }

        Base64.Encoder encoder = Base64.getEncoder();
        return encoder.encodeToString(signData);
    }

    @SuppressWarnings("serial")
    public static void main(String[] args) {
        String accessKey = "QYACCESSKEYIDEXAMPLE";
        String secretKey = "SECRETACCESSKEY";
        String method = "PUT";

        Map<String, String> headers = new HashMap<String, String>() {{
            put("Content-MD5", "4gJE4saaMU4BqNR0kLY+lw==");
            put("Content-Type", "image/jpeg");
            put("Date", "Wed, 10 Dec 2014 17:20:31 GMT");
        }};

        String signature = getAuth(
            accessKey, secretKey, method, "/test.jpeg", null, headers
        );

        String expectedSign = String.format(
            "%s %s:%s",
            "QS-HMAC-SHA256",
            accessKey,
            "D/RdUnxNUmJw0if+JlYTp/MQbfhZyhF+/l/4Sh4iAao="
        );

        System.out.print("== Expected signature ==\n" + expectedSign + "\n");
        System.out.print("== Actual signature ==\n" + signature + "\n");

        if (!signature.equals(expectedSign))
            System.out.print("Something wrong happened\n");
        else
            System.out.print("Everything works fine\n");
    }
}

