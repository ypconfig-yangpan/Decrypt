package com.decrypt.filter;

import com.alibaba.fastjson.JSON;
import com.decrypt.entity.RequestDecry;
import com.decrypt.utils.AESUtil;
import com.decrypt.utils.RSAUtil;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.io.IOUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpInputMessage;

import java.io.IOException;
import java.io.InputStream;

/**
 * @author yangpan
 * @Title: sell
 * @Package com.citymine.sell.filter
 * @Description:
 * @date 2018/6/814:21
 */
@Slf4j
public class DecryptHttpInputMessage implements HttpInputMessage {

    public static final String RSA_ALGORITHM = "RSA/ECB/PKCS1Padding";

    private HttpHeaders headers;
    private InputStream body;
    @Override
    public InputStream getBody() throws IOException {
        return body;
    }

    @Override
    public HttpHeaders getHeaders() {
        return headers;
    }
    /**
     *  统一  解密操作
     * @param inputMessage
     * @param charset
     * @throws Exception
     */
    public DecryptHttpInputMessage(HttpInputMessage inputMessage, String charset) throws Exception {

        this.headers = inputMessage.getHeaders();
        String content = IOUtils.toString(inputMessage.getBody(), charset);
        long startTime = System.currentTimeMillis();
        RequestDecry decryBody =null;
        try {
            decryBody= JSON.parseObject(content, RequestDecry.class);
        } catch (Exception e) {
            e.printStackTrace();
        }

        // 解密   私钥, 加密内容, 加密类型
        String search = RSAUtil.decryptRSA(RSAUtil.getRSAPrivateKeyByBase64String(RSAUtil.priKey), decryBody.getSearch(),RSA_ALGORITHM );
        // 解密随机码
        String salt = RSAUtil.decryptRSA(RSAUtil.getRSAPrivateKeyByBase64String(RSAUtil.priKey), decryBody.getSalt(),RSA_ALGORITHM );


        // 用接收方提供的公钥加密key和salt，接收方会用对应的私钥解密
        //String key = encryptRSA(externalPublicKey, aesKeyWithBase64);
       // String salt = encryptRSA(externalPublicKey, aesIVWithBase64);
        // AES解密
        String cipherText = decryBody.getSignature();
        String data = AESUtil.decryptAES(search, salt,cipherText);
        long endTime = System.currentTimeMillis();
        log.debug("Decrypt Time:" + (endTime - startTime));
        this.body = IOUtils.toInputStream(data, charset);
    }

}
