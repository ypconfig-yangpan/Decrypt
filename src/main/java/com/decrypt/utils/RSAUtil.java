package com.decrypt.utils;

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
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.TypeReference;

/**
 * Title:RSAUtil
 * Description:RSA工具
 * @sine 2017-5-25下午5:33:39
 * @author yowasa
 */
public class RSAUtil {
	public static final String UTF_8 = "UTF-8";
	// 预先产生的公钥
	public static final String pubKey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArIGhXYMqK9dbb7CYXjOdYnYiONCX4KGkHo8pMpAK59l1L1Ve6y2IdW/6W5ZHth8mE/BK1YIVvS8HCifQsT02ewU2Oq6/fcnlgH1vlFRHJNHjPpVlPyUjIPJjLQcnNFeMNHupBdUY6UK6dneBSzB+Yv7dF9/DKOClOOE2k5BUgYwLS74GN7XewrnRODvK2Lka1y4VRUKwHuKRtWT2XrOBIka6R0q4pwV96MW+52+9ASc8stKU5ymSiILKEHUo/wY6AYSZYIfMphpuSMIKEn0cJ3SdE1sFUeARJrPBu77bOl9YV9BGMIMb7CJm+TPW+KCBdjeo1pZP45CVSybFoFTw6wIDAQAB";
	public static final String priKey = "MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQCsgaFdgyor11tvsJheM51idiI40JfgoaQejykykArn2XUvVV7rLYh1b/pblke2HyYT8ErVghW9LwcKJ9CxPTZ7BTY6rr99yeWAfW+UVEck0eM+lWU/JSMg8mMtByc0V4w0e6kF1RjpQrp2d4FLMH5i/t0X38Mo4KU44TaTkFSBjAtLvgY3td7CudE4O8rYuRrXLhVFQrAe4pG1ZPZes4EiRrpHSrinBX3oxb7nb70BJzyy0pTnKZKIgsoQdSj/BjoBhJlgh8ymGm5IwgoSfRwndJ0TWwVR4BEms8G7vts6X1hX0EYwgxvsImb5M9b4oIF2N6jWlk/jkJVLJsWgVPDrAgMBAAECggEAcPtZ33Anr50V4tnrgU8W1kT+9u0Pe+0CG42x8s7Khb0z9fNY/njM9fWIKHINt6dA/jAUIzBW4pgpaSpYkazAwOPR96859b3E1VnSOXjVO7VHu1aHgErnbg2yjOwxbiOkzT7snchKz4OHsk1k3gT90gKQdbF1FZHERLOkVhNidZFWwz6/dbqIMEXqQue35KV2bH0qL9m1sLogPAiIePA7JqD2WTz4oWkPFR5CYNE8qS7yPHmtfX8ITv4TKPN6EFIN7Q8vJqMv775lnBpWepq00Kv+N9r2yn53/d7rzOxeZFndz3VwmneoolcXgWmukSueAxP553N1PXeLo7XGthey4QKBgQD6xmzcOeqDcq6urnAQtlfW/C4xGRY28Gta7yLczWBi4a4Uw5Z0URxwb3LHQjpUQMV5F8UtPYh80Qr/8Og5HK4z2TNSwWyUqxP+r4vXkwgsCQKZF21DimigncTv2qQplwvhWrKznpd+pfLmWigYdg4DPJaBbCk2NkpSlvnA319wkQKBgQCwGb0BALX80UrY0PXb8u7P76ly1drcx8+/DgO2LxWsvjydFHbtHojv5wt73VJi39C+KfFCnj2S54fnYJkRbYdobCW2WvUtAD3mjQPqdQAgkc+5qNdAEtuqH3UD/b5CY9kMnahSlLvgZRl3OwysucyhdRABDTjR+2Z/CrIQkc3HuwKBgQDL9VJYkyovGrkEDY/Lp+ItUhFnkVXF/SfzX4dlOgxon9Brxt+5XrbYo2wgr7atC7kQUcrmjqNRkNt3akIVIUR1mvPpHLPo/nNWswPzovwEhJd+V9VgF1QdPfQMeDEIOndJI/EvsY7ZTLMPssfljS68ZyypuoSSOPmdznj26zW+YQKBgQCcjLUGMDCY6SJFrzXx63w75E3aJZ1kikj4CqhoDGGTaKcP6YJz96I6y0XdPnqgJWI3u6eb1nrcnvGlUq2g3aLzxLid7Sxqbf2ZeKETjCGp0pY88Ykxj9Ix4bcv7iJ2eLcazQk3KLwAlz/VS+xPnPj6S8wHc06g9YI/zC1SJ5wtQwKBgQC21fZP0+HiM26FgSuS8KWIj0rx0j2hylgCy0aPW/OhyGmgPWOnhfjtxndWsQVVo/Q5MgTHC34ffwSsF6lxVdmZXZA12JOsp6RCxovVzseYVKL/xapFYbeU53VAawJ0lSVTMa3yj2vI2+XcGpA9FAI02AfbDoqzXcExyuzoofRgsw==";
	/**
	 * 获得RSA密匙对对象 
	 *@author yowasa
	 * @return map中publicKey公钥 privateKey私钥 类分别为RSAPublicKey，RSAPrivateKey
	 * @throws NoSuchAlgorithmException
	 */
	public static Map<String,Key> getRSAKeys() throws NoSuchAlgorithmException{
		Map<String,Key> map=new TreeMap<String, Key>();
		// RSA的公钥和私钥
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		keyPairGenerator.initialize(2048);
		KeyPair keyPair = keyPairGenerator.generateKeyPair();
		RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
		RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
		map.put("publicKey", publicKey);
		map.put("privateKey", privateKey);
		return map;
	}

	/**
	 * 生成RSA密匙对使用base64编码打印出来
	 *@author yowasa
	 * @throws NoSuchAlgorithmException
	 */
	public static void createAndPrintKeyPairs() throws NoSuchAlgorithmException {
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		keyPairGenerator.initialize(2048);
		KeyPair keyPair = keyPairGenerator.generateKeyPair();
		RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
		RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
		System.out.println(Base64.encodeBase64String(publicKey.getEncoded()));
		System.out.println(Base64.encodeBase64String(privateKey.getEncoded()));
	}

	/**
	 * 根据base64编码的公钥字符串获取公钥对象
	 *@author yowasa
	 * @param pubKey
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 */
	public static PublicKey getRSAPublicKeyByBase64String(String pubKey) throws NoSuchAlgorithmException, InvalidKeySpecException{
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(Base64.decodeBase64(pubKey));
		PublicKey publicKey = keyFactory.generatePublic(x509KeySpec);
		return publicKey;
	}

	/**
	 * 根据base64编码的私钥字符串获取私钥对象
	 *@author yowasa
	 * @param priKey
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 */
	public static PrivateKey getRSAPrivateKeyByBase64String(String priKey) throws NoSuchAlgorithmException, InvalidKeySpecException {
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(Base64.decodeBase64(priKey));
		PrivateKey privateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
		return privateKey;
	}

	/**
	 * RSA签名并使用Base64编码.
	 *@author yowasa
	 * @param key
	 * @param content
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 * @throws DecoderException
	 * @throws SignatureException
	 * @throws UnsupportedEncodingException
	 */
	public static String signRSAByBase64(PrivateKey key, String content) throws NoSuchAlgorithmException, InvalidKeyException, DecoderException, SignatureException, UnsupportedEncodingException {
		Signature signature = Signature.getInstance("SHA256withRSA");
		signature.initSign(key);
		signature.update(content.getBytes("UTF-8"));
		return Base64.encodeBase64String(signature.sign());
	}

	/**
	 * 验证使用Base64编码的RSA签名
	 *@author yowasa
	 * @param key
	 * @param content
	 * @param sign
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 * @throws DecoderException
	 * @throws SignatureException
	 * @throws UnsupportedEncodingException
	 */
	public static boolean verifyRSAByBase64(PublicKey key, String content, String sign) throws NoSuchAlgorithmException, InvalidKeyException, DecoderException, SignatureException, UnsupportedEncodingException {
		Signature signature = Signature.getInstance("SHA256withRSA");
		signature.initVerify(key);
		signature.update(content.getBytes("UTF-8"));
		return signature.verify(Base64.decodeBase64(sign));
	}

	/**
	 * RSA签名并使用HEX编码
	 *@author yowasa
	 * @param key
	 * @param content
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 * @throws DecoderException
	 * @throws SignatureException
	 * @throws UnsupportedEncodingException
	 */
	public static String signRSAByHex(PrivateKey key, String content) throws NoSuchAlgorithmException, InvalidKeyException, DecoderException, SignatureException, UnsupportedEncodingException {
		Signature signature = Signature.getInstance("SHA256withRSA");
		signature.initSign(key);
		signature.update(content.getBytes("UTF-8"));
		return Hex.encodeHexString(signature.sign());
	}

	/**
	 * 验证使用HEX编码的RSA签名
	 *@author yowasa
	 * @param key
	 * @param content
	 * @param sign
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 * @throws DecoderException
	 * @throws SignatureException
	 * @throws UnsupportedEncodingException
	 */
	public static boolean verifyRSAByHex(PublicKey key, String content, String sign) throws NoSuchAlgorithmException, InvalidKeyException, DecoderException, SignatureException, UnsupportedEncodingException {
		Signature signature = Signature.getInstance("SHA256withRSA");
		signature.initVerify(key);
		signature.update(content.getBytes("UTF-8"));
		return signature.verify(Hex.decodeHex(sign.toCharArray()));
	}

	/**
	 * map转String key=value&形式 注意必须是TreeMap, TreeMap保证key降序.
	 *@author yowasa
	 * @param map
	 * @return
	 */
	public  static String map2str(TreeMap<String, String> map) {
		List<String> values = new ArrayList<String>();
		for (String key : map.keySet()) {
			String value = key + "=" + map.get(key);
			values.add(value);
		}
		return list2String(values,"&");
	}

	/**
	 * 遍历list数据用plus拼接起来
	 *@author yowasa
	 * @param values
	 * @return
	 */
	public static String list2String(List<String> values,String plus){
		StringBuilder bui = new StringBuilder();
		if(values!=null&&values.size()>0){
			for(String str :values){
				bui.append(str);
				bui.append(plus);
			}
		}
		bui.deleteCharAt(bui.length()-1);
		return bui.toString();
	}
	/**
	 * RSA非对称加密，根据公钥和原始内容产生加密内容
	 * @author yowasa
	 * @param key
	 * @param plainText
	 * @return
	 * @throws NoSuchPaddingException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 * @throws UnsupportedEncodingException
	 * @throws BadPaddingException
	 * @throws IllegalBlockSizeException
	 * @throws InvalidAlgorithmParameterException
	 */
	public static String encryptRSA(Key key, String plainText,String rsamod)
			throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, UnsupportedEncodingException,
			BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException {
		Cipher cipher = Cipher.getInstance(rsamod);
		cipher.init(Cipher.ENCRYPT_MODE, key);
		return Base64.encodeBase64String(cipher.doFinal(plainText.getBytes(UTF_8)));
	}
	/**
	 * RSA非对称解密，根据私钥和加密内容产生原始内容
	 * @author yowasa
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
	public static String decryptRSA(Key key, String content,String rsamod) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, DecoderException, BadPaddingException, IllegalBlockSizeException, UnsupportedEncodingException, InvalidAlgorithmParameterException {
		Cipher cipher = Cipher.getInstance(rsamod);
		cipher.init(Cipher.DECRYPT_MODE, key);
		return new String(cipher.doFinal(Base64.decodeBase64(content)), UTF_8);
	}

	/**
	 * 工具测试
	 *@author yowasa
	 * @param args
	 * @throws NoSuchAlgorithmException
	 * @throws UnsupportedEncodingException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws SignatureException
	 * @throws DecoderException
	 * @throws InvalidKeySpecException
	 */
	public static void main(String[] args) throws NoSuchAlgorithmException, UnsupportedEncodingException, NoSuchPaddingException, InvalidKeyException, SignatureException, DecoderException, InvalidKeySpecException {

		// 预先产生的公钥
		String pubKey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArIGhXYMqK9dbb7CYXjOdYnYiONCX4KGkHo8pMpAK59l1L1Ve6y2IdW/6W5ZHth8mE/BK1YIVvS8HCifQsT02ewU2Oq6/fcnlgH1vlFRHJNHjPpVlPyUjIPJjLQcnNFeMNHupBdUY6UK6dneBSzB+Yv7dF9/DKOClOOE2k5BUgYwLS74GN7XewrnRODvK2Lka1y4VRUKwHuKRtWT2XrOBIka6R0q4pwV96MW+52+9ASc8stKU5ymSiILKEHUo/wY6AYSZYIfMphpuSMIKEn0cJ3SdE1sFUeARJrPBu77bOl9YV9BGMIMb7CJm+TPW+KCBdjeo1pZP45CVSybFoFTw6wIDAQAB";
		PublicKey rsaPublicKeyByBase64String = getRSAPublicKeyByBase64String(pubKey);
		System.out.println(rsaPublicKeyByBase64String);
		PublicKey publicKey = RSAUtil.getRSAPublicKeyByBase64String(pubKey);

		// 预先产生的私钥
		String priKey = "MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQCsgaFdgyor11tvsJheM51idiI40JfgoaQejykykArn2XUvVV7rLYh1b/pblke2HyYT8ErVghW9LwcKJ9CxPTZ7BTY6rr99yeWAfW+UVEck0eM+lWU/JSMg8mMtByc0V4w0e6kF1RjpQrp2d4FLMH5i/t0X38Mo4KU44TaTkFSBjAtLvgY3td7CudE4O8rYuRrXLhVFQrAe4pG1ZPZes4EiRrpHSrinBX3oxb7nb70BJzyy0pTnKZKIgsoQdSj/BjoBhJlgh8ymGm5IwgoSfRwndJ0TWwVR4BEms8G7vts6X1hX0EYwgxvsImb5M9b4oIF2N6jWlk/jkJVLJsWgVPDrAgMBAAECggEAcPtZ33Anr50V4tnrgU8W1kT+9u0Pe+0CG42x8s7Khb0z9fNY/njM9fWIKHINt6dA/jAUIzBW4pgpaSpYkazAwOPR96859b3E1VnSOXjVO7VHu1aHgErnbg2yjOwxbiOkzT7snchKz4OHsk1k3gT90gKQdbF1FZHERLOkVhNidZFWwz6/dbqIMEXqQue35KV2bH0qL9m1sLogPAiIePA7JqD2WTz4oWkPFR5CYNE8qS7yPHmtfX8ITv4TKPN6EFIN7Q8vJqMv775lnBpWepq00Kv+N9r2yn53/d7rzOxeZFndz3VwmneoolcXgWmukSueAxP553N1PXeLo7XGthey4QKBgQD6xmzcOeqDcq6urnAQtlfW/C4xGRY28Gta7yLczWBi4a4Uw5Z0URxwb3LHQjpUQMV5F8UtPYh80Qr/8Og5HK4z2TNSwWyUqxP+r4vXkwgsCQKZF21DimigncTv2qQplwvhWrKznpd+pfLmWigYdg4DPJaBbCk2NkpSlvnA319wkQKBgQCwGb0BALX80UrY0PXb8u7P76ly1drcx8+/DgO2LxWsvjydFHbtHojv5wt73VJi39C+KfFCnj2S54fnYJkRbYdobCW2WvUtAD3mjQPqdQAgkc+5qNdAEtuqH3UD/b5CY9kMnahSlLvgZRl3OwysucyhdRABDTjR+2Z/CrIQkc3HuwKBgQDL9VJYkyovGrkEDY/Lp+ItUhFnkVXF/SfzX4dlOgxon9Brxt+5XrbYo2wgr7atC7kQUcrmjqNRkNt3akIVIUR1mvPpHLPo/nNWswPzovwEhJd+V9VgF1QdPfQMeDEIOndJI/EvsY7ZTLMPssfljS68ZyypuoSSOPmdznj26zW+YQKBgQCcjLUGMDCY6SJFrzXx63w75E3aJZ1kikj4CqhoDGGTaKcP6YJz96I6y0XdPnqgJWI3u6eb1nrcnvGlUq2g3aLzxLid7Sxqbf2ZeKETjCGp0pY88Ykxj9Ix4bcv7iJ2eLcazQk3KLwAlz/VS+xPnPj6S8wHc06g9YI/zC1SJ5wtQwKBgQC21fZP0+HiM26FgSuS8KWIj0rx0j2hylgCy0aPW/OhyGmgPWOnhfjtxndWsQVVo/Q5MgTHC34ffwSsF6lxVdmZXZA12JOsp6RCxovVzseYVKL/xapFYbeU53VAawJ0lSVTMa3yj2vI2+XcGpA9FAI02AfbDoqzXcExyuzoofRgsw==";
		PrivateKey privateKey = RSAUtil.getRSAPrivateKeyByBase64String(priKey);

		// 1. 准备发送的数据
		TreeMap<String, String> map = new TreeMap<String, String>();
		map.put("order_id", "1324679");
		map.put("partner_no", "A001");
		map.put("version", "V1.0");
		map.put("comment", "");

		// 1. 计算验签字段, sign字段不参与签名
		String line = map2str(map);
		String sign = RSAUtil.signRSAByBase64(privateKey, line);
		map.put("sign", sign);

		// 1. 构造发送的数据, 发送, 发送格式为JSON(需要阿里巴巴的fastjson)
		String request = JSON.toJSONString(map);
		System.out.println(request);

		// 2. 接收到request, 将JSON转换为map
		TreeMap<String, String> map2 = JSON.parseObject(request, new TypeReference<TreeMap<String, String>>() {});
		String sign2 = map2.get("sign");

		// 2. 剔除sign字段
		map2.remove("sign");
		String line2 = map2str(map2);
		boolean isPassed = RSAUtil.verifyRSAByBase64(publicKey, line2, sign2);
		System.out.println("验签结果 : " + isPassed);


		String sing3 = "fY0ncKH86+EhHphBUNX03BnliH0lG1hHIX+41VY2QCU7x6DQJan6K3Xgy99iuP+FPLQQac/+En+L3WNI1V6SzUnpzGhMjqOjI+8FQCylVLf+P80Fl7gcYip6GpizCVBnjmFFIgg4wMmO+KIxuHUdFW4vaiAkn3QgT0gHekXTmvv5GKH266lrXw1JaOnr1P6fH8boAc7SE/TYgP5BUlEfhzxfnSVnMRv+pK6zrVauCQtqUP74LekpczHGPHJgGEC6uJ+q9Vo2iVMmuRWyhmWzVN3n0sbDnxBRZLHXgRT+9lHKbgIV5677TeYS7Lk+CrjpqCbCBae6g2w1giyPvr2EFQ==";
		String json = "{\"code\":2001,\"data\":{\"password1\":\"123456\",\"userId\":\"1\",\"username\":\"杨十七\"},\"msg\":\"成功111\"}";

		boolean result = RSAUtil.verifyRSAByBase64(publicKey, json, sing3);
		System.out.println("验签结果 : " + isPassed);

	}
}
