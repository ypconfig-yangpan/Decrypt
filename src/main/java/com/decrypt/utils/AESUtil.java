package com.decrypt.utils;

import java.io.UnsupportedEncodingException;
import java.security.*;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;

/**
 * Title:AESUtil
 * Description:AES加密工具类
 * @sine 2017-6-2上午9:56:44
 * @author yowasa
 */
public class AESUtil {
	public static final String UTF_8 = "UTF-8";
	// 反馈加密
    public static final String AES_ALGORITHM = "AES/CFB/PKCS5Padding";
    // ECB密码填充模式(分段加密)
    public static final String ECB_ALGORITHM = "AES/ECB/PKCS5Padding";

    /**
	 * 获取随机的对称加密AES128位Base64编码的的密钥
	 * @author yowasa
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws UnsupportedEncodingException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws InvalidKeyException
	 * @throws NoSuchPaddingException
	 */
    public static String genRandomAesSecretKey() throws NoSuchAlgorithmException, UnsupportedEncodingException,
            IllegalBlockSizeException, BadPaddingException, InvalidKeyException, NoSuchPaddingException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128);
        SecretKey secretKey = keyGen.generateKey();
        String keyWithBase64 = Base64.encodeBase64String(secretKey.getEncoded());
        return keyWithBase64;
    }
    /**
     * 获取随机的对称加密AES的IV偏移值并以Base64编码返回
     * @author yowasa
     * @return
     */
    public static String genRandomIV() {
        SecureRandom r = new SecureRandom();
        byte[] iv = new byte[16];
        r.nextBytes(iv);
        String ivParam = Base64.encodeBase64String(iv);
        return ivParam;
    }



    /**
     * 对称解密数据  ECB模式
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
//    public static String decryptAES(String keyWithBase64,  String cipherText)
//            throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException,
//            BadPaddingException, UnsupportedEncodingException {
//
//        KeyGenerator kgen = KeyGenerator.getInstance("AES");
//        kgen.init(128);
//        Cipher cipher = Cipher.getInstance(ECB_ALGORITHM);
//        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(Base64.decodeBase64(keyWithBase64), "AES"));
//
//        byte[] textBytes = cipherText.getBytes(UTF_8);
//        byte[] bytes = cipher.doFinal(textBytes);
//        return Base64.encodeBase64String(bytes);
//
//    }


    /**
     * 对称解密数据 CFB
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
    public static String decryptAES(String keyWithBase64, String ivWithBase64, String cipherText)
            throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException,
            BadPaddingException, UnsupportedEncodingException, InvalidAlgorithmParameterException {
        SecretKeySpec key = new SecretKeySpec(Base64.decodeBase64(keyWithBase64), "AES");
        IvParameterSpec iv = new IvParameterSpec(Base64.decodeBase64(ivWithBase64));

        Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, key, iv);
        return new String(cipher.doFinal(Base64.decodeBase64(cipherText)), UTF_8);
    }
    /**
     * 对称加密数据  CFB
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
    public static String encryptAES(String keyWithBase64, String ivWithBase64, String plainText)
            throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException,
            BadPaddingException, UnsupportedEncodingException, InvalidAlgorithmParameterException {

        SecretKeySpec key = new SecretKeySpec(Base64.decodeBase64(keyWithBase64), "AES");
        IvParameterSpec iv = new IvParameterSpec(Base64.decodeBase64(ivWithBase64));

        Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);

        return Base64.encodeBase64String(cipher.doFinal(plainText.getBytes(UTF_8)));
    }

    /**
     * 对称加密数据 ECB
     *
     * @param keyWithBase64
     * @param plainText
     */
//    public static String encryptAES(String keyWithBase64, String plainText)
//            throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException,
//            BadPaddingException, UnsupportedEncodingException {
//
//        KeyGenerator kgen = KeyGenerator.getInstance("AES");
//        kgen.init(128);
//        SecretKeySpec key = new SecretKeySpec(Base64.decodeBase64(keyWithBase64), "AES");
//        Cipher cipher = Cipher.getInstance(ECB_ALGORITHM);
//        cipher.init(Cipher.ENCRYPT_MODE, key);
//
//        return Base64.encodeBase64String(cipher.doFinal(plainText.getBytes(UTF_8)));
//    }
}
