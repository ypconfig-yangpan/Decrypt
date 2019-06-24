package com.decrypt.utils;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.digest.DigestUtils;
import com.alibaba.fastjson.JSONObject;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Map;
import java.util.TreeMap;
import java.util.Map.Entry;

public class RimSecurityDemo {
    
    public static final String UTF_8 = "UTF-8";
    
    public static final String AES_ALGORITHM = "AES/CFB/PKCS5Padding";
    public static final String RSA_ALGORITHM = "RSA/ECB/PKCS1Padding";
    
    public static void checkReceivedExample(PublicKey externalPublicKey, PrivateKey selfPrivateKey, Map<String, String> receivedMap) throws InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException, UnsupportedEncodingException, InvalidAlgorithmParameterException, DecoderException {
        
        // receivedMap为请求方通过from urlencoded方式，请求过来的参数列表

        String inputSign = receivedMap.get("sign");
        
        // 用请求方提供的公钥解密，能解密出来sign，说明来源正确
        inputSign = decryptRSA(externalPublicKey, inputSign);
        
        // 校验sign是否一致
        String sign = sha256(receivedMap);
        if (!sign.equals(inputSign)) {
            // sign校验不通过，说明双方发送出的数据和对方收到的数据不一致
            System.out.println("input sign: " + inputSign + ", calculated sign: " + sign);
            return;
        }
        
        // 解密请求方在发送请求时，加密data字段所用的对称加密密钥
        String key = receivedMap.get("key");
        String salt = receivedMap.get("salt");
        key = decryptRSA(selfPrivateKey, key);
        salt = decryptRSA(selfPrivateKey, salt);
        
        // 解密data数据
        String data = decryptAES(key, salt, receivedMap.get("data"));
        System.out.println("接收到的data内容：" + data);
        
        // 正常处理业务
    }
    
    /**
     * 调用对方接口时，数据组织示例
     * 
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     * @throws InvalidKeyException
     * @throws NoSuchPaddingException
     * @throws UnsupportedEncodingException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     * @throws InvalidAlgorithmParameterException
     */
    public static Map<String, String> sendExample(PublicKey externalPublicKey, PrivateKey selfPrivateKey) throws NoSuchAlgorithmException, InvalidKeySpecException,
            InvalidKeyException, NoSuchPaddingException, UnsupportedEncodingException, BadPaddingException,
            IllegalBlockSizeException, InvalidAlgorithmParameterException {
        
        // 随机生成对称加密的密钥和IV
        String aesKeyWithBase64 = genRandomAesSecretKey();
        String aesIVWithBase64 = genRandomIV();
        
        // 用接收方提供的公钥加密key和salt，接收方会用对应的私钥解密
        String key = encryptRSA(externalPublicKey, aesKeyWithBase64);
        String salt = encryptRSA(externalPublicKey, aesIVWithBase64);
        
        // 组织业务数据信息，并用上面生成的对称加密的密钥和IV进行加密
        JSONObject data = new JSONObject();
        data.put("key1", "value1");
        data.put("key2", "value2");
        data.put("key3", "value3");
        System.out.println("发送的data内容：" + data.toJSONString());
        String cipherData = encryptAES(aesKeyWithBase64, aesIVWithBase64, data.toJSONString());
        
        // 组织请求的key、value对
        Map<String, String> requestMap = new TreeMap<String, String>();
        requestMap.put("key", key);
        requestMap.put("salt", salt);
        requestMap.put("data", cipherData);
        requestMap.put("source", "由接收方提供"); // 添加来源标识

        // 计算sign，并用请求方的私钥加密，接收方会用请求方发放的公钥解密
        String sign = sha256(requestMap);
        requestMap.put("sign", encryptRSA(selfPrivateKey, sign));
        
        // TODO: 以form urlencoded方式调用，参数为上面组织出来的requestMap
        
        // 注意：请务必以form urlencoded方式，否则base64转码后的个别字符可能会被转成空格，对方接收后将无法正常处理
        
        return requestMap;
    }
    
    /**
     * 获取随机的对称加密的密钥
     * 
     * @return
     * @throws NoSuchAlgorithmException
     * @throws UnsupportedEncodingException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     * @throws InvalidKeyException
     * @throws NoSuchPaddingException
     */
    private static String genRandomAesSecretKey() throws NoSuchAlgorithmException, UnsupportedEncodingException,
            IllegalBlockSizeException, BadPaddingException, InvalidKeyException, NoSuchPaddingException {        
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128);
        SecretKey secretKey = keyGen.generateKey();
        String keyWithBase64 = Base64.encodeBase64String(secretKey.getEncoded());
        
        return keyWithBase64;
        
    }
    
    private static String genRandomIV() {
        SecureRandom r = new SecureRandom();
        byte[] iv = new byte[16];
        r.nextBytes(iv);
        String ivParam = Base64.encodeBase64String(iv);
        return ivParam;
    }
    
    /**
     * 对称加密数据
     * 
     * @param keyWithBase64
     * @param ivWithBase64
     * @param plainText
     * @return
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     * @throws InvalidKeyException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     * @throws UnsupportedEncodingException
     * @throws InvalidAlgorithmParameterException 
     */
    private static String encryptAES(String keyWithBase64, String ivWithBase64, String plainText)
            throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException,
            BadPaddingException, UnsupportedEncodingException, InvalidAlgorithmParameterException {
        
        SecretKeySpec key = new SecretKeySpec(Base64.decodeBase64(keyWithBase64), "AES");
        IvParameterSpec iv = new IvParameterSpec(Base64.decodeBase64(ivWithBase64));
        
        Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
       
        return Base64.encodeBase64String(cipher.doFinal(plainText.getBytes(UTF_8)));
    }
    
    /**
     * 对称解密数据
     * 
     * @param keyWithBase64
     * @param cipherText
     * @return
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     * @throws InvalidKeyException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     * @throws UnsupportedEncodingException
     * @throws InvalidAlgorithmParameterException 
     */
    private static String decryptAES(String keyWithBase64, String ivWithBase64, String cipherText)
            throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException,
            BadPaddingException, UnsupportedEncodingException, InvalidAlgorithmParameterException {
        SecretKeySpec key = new SecretKeySpec(Base64.decodeBase64(keyWithBase64), "AES");
        IvParameterSpec iv = new IvParameterSpec(Base64.decodeBase64(ivWithBase64));
        
        Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, key, iv);
        return new String(cipher.doFinal(Base64.decodeBase64(cipherText)), UTF_8);
    }
    
    /**
     * 非对称加密，根据公钥和原始内容产生加密内容
     * 
     * @param key
     * @param content
     * @return
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws UnsupportedEncodingException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     * @throws InvalidAlgorithmParameterException
     */
    private static String encryptRSA(Key key, String plainText)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, UnsupportedEncodingException,
            BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException {
        Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return Base64.encodeBase64String(cipher.doFinal(plainText.getBytes(UTF_8)));
    }
    
    /**
     * 根据私钥和加密内容产生原始内容
     * @param key
     * @param content
     * @return
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws DecoderException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     * @throws UnsupportedEncodingException
     * @throws InvalidAlgorithmParameterException
     */
    private static String decryptRSA(Key key, String content) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, DecoderException, BadPaddingException, IllegalBlockSizeException, UnsupportedEncodingException, InvalidAlgorithmParameterException {
        Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, key);
        return new String(cipher.doFinal(Base64.decodeBase64(content)), UTF_8);
    }
    
    /**
     * 计算sha256值
     * 
     * @param paramMap
     * @return
     */
    private static String sha256(Map<String, String> paramMap) {
        Map<String, String> params = new TreeMap<String, String>(paramMap);
        
        StringBuilder concatStr = new StringBuilder();
        for (Entry<String, String> entry : params.entrySet()) {
            if ("sign".equals(entry.getKey())) {
                continue;
            }
            concatStr.append(entry.getKey() + "=" + entry.getValue() + "&");
        }
        
        return DigestUtils.sha256Hex(concatStr.toString());
    }
    
    /**
     * 创建RSA的公钥和私钥示例 将生成的公钥和私钥用Base64编码后打印出来
     * 
     * @throws NoSuchAlgorithmException
     */
    public static void createKeyPairs() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048); // 必须2048
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        System.out.println(Base64.encodeBase64String(publicKey.getEncoded()));
        System.out.println(Base64.encodeBase64String(privateKey.getEncoded()));
    }
    
    public static void main(String[] args)
            throws InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException,
            UnsupportedEncodingException, InvalidKeySpecException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, DecoderException {
        
        // 预先产生的甲方公钥
        String baiduPubKey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAucxoUu+PVDTusktbaHqr0D7LtnfaI5FFAgxB7RnfkKHRJJU0O7pjNj55O+dd8ui5TTu9PoZ6+Iiu4Xmyo//GNc4ajKGGRoKJLltSONDDqJ+Dw1N3Agc19usmMQg4XHrwhgLdNhHeQ5O4QPMvfOzPY370app4/X5LQvC3Xv7/25MSWieIzkV5EKqcqCPX5+hZqIZqoeaWtLm9uVSJC4XBBs2LQz46YCG7nmRiNUGxLD1Y497jH20VKxq53UHXS/LiTy4QjlRCwHz11TkbKkrmdnw1QkBgrv0vyhhYrgkMmYrjL+cukxb6eyhS3ld3ur/z56/sUoR4/MTBPFJP+ZYGEwIDAQAB";
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(Base64.decodeBase64(baiduPubKey));
        PublicKey baiduPublicKey = keyFactory.generatePublic(x509KeySpec);
        
        // 预先产生的甲方私钥
        String baiduPriKey = "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC5zGhS749UNO6yS1toeqvQPsu2d9ojkUUCDEHtGd+QodEklTQ7umM2Pnk7513y6LlNO70+hnr4iK7hebKj/8Y1zhqMoYZGgokuW1I40MOon4PDU3cCBzX26yYxCDhcevCGAt02Ed5Dk7hA8y987M9jfvRqmnj9fktC8Lde/v/bkxJaJ4jORXkQqpyoI9fn6Fmohmqh5pa0ub25VIkLhcEGzYtDPjpgIbueZGI1QbEsPVjj3uMfbRUrGrndQddL8uJPLhCOVELAfPXVORsqSuZ2fDVCQGCu/S/KGFiuCQyZiuMv5y6TFvp7KFLeV3e6v/Pnr+xShHj8xME8Uk/5lgYTAgMBAAECggEAa7x9menToK544uYTgQfw7PYcxhfFY+5up3tYFxZzrrhGQAJMoX243dFoFzZYIeyU1pYXbFQqpkcLsS8SSUqdMsHqXzWiWOyEg17s1Ikpi3PDwdV6IrDvt9gu8yujEu0u32Z1w06lJWZY50CcfsIKl9UcAVzFX6iGF7Dhg7I1xqoJvKRbs7wLpBimgX3kNt2FxiiZ9EPo1Hwx7YauP3Wd/Dzx3J1bmg3R5PiiRWy8AdhVApMKPjuqqhGec8f1IW4gT7eYRzdpI/On90hnthjJK7Cysj/lJAaQtO5NLSBjWK5SE/fFvN5NquWeMnssaaX2g1RBs7s/+ZMSgtjcY1SpgQKBgQDr02v/O6y3l+Aza1hPZeB08Bu0slbfo2Bpf53qBm2Qn4HUsMeeFglwJlgYETK074GfwCrDo5DLlYsLfleZJNMXF2PYYD5EJb7pTBBbonI+L9lSMzoFIULhVrYNdnV50Xh9mgvGk1ywnsbgNc5aD3bXcgHUfGjIa3129BtygULa8wKBgQDJsWMqc+uh2Y02eGkIx26REZ5uxASEt3NJ5L+pvlJlZMiUfQvqo4TYzv/AWjMcNGebDFdUP7e+IJLRG66eZPhcM6CdbIkGP3iYqXAbmgEpeoIT4NzIvTjTg2IQZd9ef8ql6rlt7DfyhV0P0ebhvFpzJkrG4Jjh8L2tNvWsrt6wYQKBgFcaGdOFqP+OmwKi7VU2HbdTUAhnrmqfn2aX+i2L/j/iikOSn8gl/4pqvzL0dzQZGll00ta7vSlUrKysF5K65TSsMPakZZsqDd+BdrFByMxrQ+t2fEGUzW0JZ+iFDlLWKZjKovrPRvb9ThtWBEeDWrOsqjxfTxxnh0m+U7zxPU49AoGBAIi6pEtHQln6LWzbu/ijmiTmGM1mPNnrs1BIrlXYG+t4ozFmhAmQyKJh0acIftWEAShu+VS3zUwqsNzpMztVn7iBl0ShK1L8/DghxUow4NDJqBzpt0KuZDOfQX90UDSz1SEdOo92L4dNOYVb+nTVR0wAjXi9EWc52JvwQiPKeFSBAoGBAIgO/4X5iGPVDDk+Fl4IWEAPv+DMhemnVEVGmHmXvaR4d782kq+k8C23XTw8xurt0RR0MgOtmEqRhKdunrmmy98tyjMP0QDYbZ+PgOo+mdzj6LiFmtqnbd34C+Q84G76th2v4r0WKP1ZLYpeUxCU8AhvJoubQSm+uH393iF9eCmE";
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(Base64.decodeBase64(baiduPriKey));
        PrivateKey baiduPrivateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
        
        // 预先产生的乙方构公钥
        String partnerPubKey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnXXTyhEY4XmRNaafdPZu/YktnagLEq9IFj9HrepgkzPkbk9dvApWK0FifKn8yqOeuUZm/OcPVs7hay20PUC8ud+f+PgMpVLOGro1ySZPSeTmw12cauTjD7mJBs9te7zUde4CnGGRlm9jZf5s2tP6pTLNRzo6TXpYwsV8uaUuVLP8u2HPmZF2PIfthIkGIfDCeGlM3c0gitU2OVRvw+S/TP0I0WwnI70C6YBmdLi0iI5r/Qxm0KfKrHGtSsZHuAqnhh5Fn1LCqsDYYaJ/5qy+LDBxzMo7u78vmtgq+bPbx/Lyn+6nStyw/10RLjQhvX+KEhUc/bx0wlrx0HR5L+Bd4wIDAQAB";
        X509EncodedKeySpec x509KeySpec2 = new X509EncodedKeySpec(Base64.decodeBase64(partnerPubKey));
        PublicKey partnerPublicKey = keyFactory.generatePublic(x509KeySpec2);
        
        // 预先产生的乙方构私钥
        String partnerPriKey = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCdddPKERjheZE1pp909m79iS2dqAsSr0gWP0et6mCTM+RuT128ClYrQWJ8qfzKo565Rmb85w9WzuFrLbQ9QLy535/4+AylUs4aujXJJk9J5ObDXZxq5OMPuYkGz217vNR17gKcYZGWb2Nl/mza0/qlMs1HOjpNeljCxXy5pS5Us/y7Yc+ZkXY8h+2EiQYh8MJ4aUzdzSCK1TY5VG/D5L9M/QjRbCcjvQLpgGZ0uLSIjmv9DGbQp8qsca1Kxke4CqeGHkWfUsKqwNhhon/mrL4sMHHMyju7vy+a2Cr5s9vH8vKf7qdK3LD/XREuNCG9f4oSFRz9vHTCWvHQdHkv4F3jAgMBAAECggEAKU0MnkXZxtqCMhZgYOd6uVnP8zhunxoGyH8UqBN//VxxIFYE+huj+niOArD7s5MzQNmsjc11gomFKv2z9xUR65cyeLVna73Kfcw162r3BSTbOodFTex3elpqDLU/vGMNP1mMqcQV0eWppskTeFp9tfMbUQF+5W+f9IakbnVbL7AUFRru3i08E7LMuJaPElr49ik2Dq4ca0EgL52nFL+yt6QYXqYZ3/5H0rf26XaOGzmjmCX02NTkfLhrersqE2rrFos8kB2SXJTq9t0cDooQGmGSV2NbmqTiwepfJNhtZQm+OraF+XYyo+qUTqJ5xlWslP2rXw6ByUDCuTDN0Pl24QKBgQDifzgNCWf0u5X111sCCtEqhsnkHoC/g+3PB8RK2w9DWjNgs6Vlh5W03N5ED87hOpUzjPQkHaospZ+MJntiDIz7WBw/ljfwbjDPLU1D63Gtg8SnGgvEKwRSv/mP9F9Ctc+vZfNbLuzlviLAFPqNaOgMxML3iCpja3mXVAzUTI5CSQKBgQCx+IG+nXHRyh0ADhwuEr6QoTOGiJxskCireqCicj/LPslMk6Cu/juAbibcWVXFk7uz5hvR5H8w7kthVy9kz/Zh9s/ZfLopn23R7VrR8+6COHcKJ742yJGt5vmiY6pI/NMfax2Cfw7MYontmW/IFZNOUlIrtAfxeSeG1hBjuONeywKBgCRcWgo1vVublbpuxSxxwhx6oQSfJPoZ2t6Gl6uQuUWNwHvAu0euWYk8f+4bP5IGzpcFBNibbotWV2OvddVKwINFJNvMaNSPTASmeCX0MT6yzaop00O9yCbkrNLAX16dQ2ccDdJQmTVUrc16ULLM6ZvLJqWIVY26Xj29/4VBeQEJAoGBAJixs3f9E9vAQlN6x7jMAk6K0G98JGGM6if+RXY6+fsCuqmF/BZIMHsHhzYFO+8RyrkWFAZouqwbt/cjW5luSGFS5pAeUIdHr2yu7f43AQsfMRs4cB4Gxd7jzokCY+bNbMKHH8GIDAVWAismO177C/Dl9nRiuXH31e79GQDGb+YzAoGAREzbyqrJcjYwxCsvg98h9VgwU4NOzi/fT8SWIN+Jgv4WNQ2weZqEpLPHRhAz+tGFZ0vsPAnPPxxZCHYLItXKGrLaq8JEfU+PA2LTF96p52L8oYdDPxqrAlH5vj/n1ascoTILUq/IYIApJqDMt/iWDHeudtRGfjt6HQA/TXzYxfc=";
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec2 = new PKCS8EncodedKeySpec(Base64.decodeBase64(partnerPriKey));
        PrivateKey partnerPrivateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec2);
        
        
        // 包括加密逻辑的发送请求示例
        Map<String, String> requestMap = sendExample(baiduPublicKey, partnerPrivateKey);
        JSONObject json = new JSONObject();
        json.putAll(requestMap);
        System.out.println("加密后发送出去的数据：" + json.toJSONString());
        
        // 包括解密逻辑的数据接收示例，假设以上数据被对方成功接收
        checkReceivedExample(partnerPublicKey, baiduPrivateKey, requestMap);
    }
}
