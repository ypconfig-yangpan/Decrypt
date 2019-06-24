package com.decrypt.filter;

import com.alibaba.fastjson.JSON;
import com.decrypt.annotation.Encrypt;
import com.decrypt.spring.DecryptAndEncryptProperties;
import com.decrypt.utils.RSAUtil;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.MethodParameter;
import org.springframework.http.MediaType;
import org.springframework.http.server.ServerHttpRequest;
import org.springframework.http.server.ServerHttpResponse;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.servlet.mvc.method.annotation.ResponseBodyAdvice;

import java.util.HashMap;
import java.util.Map;


/**
 * @author yangpan
 * @Title: sell
 * @Package com.citymine.sell.filter
 * @Description:
 * @date 2018/6/813:57
 */
@Slf4j
@ControllerAdvice
public class EncryptResponseBodyAdvice implements ResponseBodyAdvice {

    private static ThreadLocal<Boolean>  isEncrypt = new ThreadLocal<Boolean>();


    public static void setEncryptStatus(boolean status) {
        isEncrypt.set(status);
    }
    @Override
    public boolean supports(MethodParameter methodParameter, Class aClass) {
        return true;
    }

    @Autowired
    private DecryptAndEncryptProperties properties;
    private ObjectMapper objectMapper = new ObjectMapper();
    @Override
    public Object beforeBodyWrite(Object body, MethodParameter methodParameter, MediaType mediaType,
                                  Class aClass, ServerHttpRequest serverHttpRequest, ServerHttpResponse serverHttpResponse) {
        // 可以通过调用EncryptResponseBodyAdvice.setEncryptStatus(false);来动态设置不加密操作
        Boolean status = isEncrypt.get();
        if (status!=null&&status==false){
            isEncrypt.remove();
            return body;
        }
        // 起始时间
        long startTime = System.currentTimeMillis();
        boolean encrypt = false;
        if (methodParameter.getMethod().isAnnotationPresent(Encrypt.class)&&!properties.isDebug()){
            encrypt = true;
        }
        if (encrypt){
            try {
                //String content = objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(body); jsckson 转化json (优雅的格式)
                log.info("body====>{}",body);
                Map map = new HashMap<>(2);

                String resultDate = JSON.toJSONString(body);

                // 签名 data
                String sign = RSAUtil.signRSAByBase64(RSAUtil.getRSAPrivateKeyByBase64String(RSAUtil.priKey), resultDate);
                // 结束时间
                long endTime = System.currentTimeMillis();
                log.info("签名所用时间===>{}", endTime-startTime);
                map.put("sign",sign);
                map.put("data",body);
                log.info("responseBody====>{}",map);
                return JSON.toJSONString(map);
            } catch (Exception e) {
                e.printStackTrace();
                log.error("返回数据失败,response写出IO异常==>",e);
            }

        }

        return body;
    }
}
