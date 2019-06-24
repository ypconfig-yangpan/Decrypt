package com.decrypt.filter;

import com.decrypt.annotation.Decrypt;
import com.decrypt.spring.DecryptAndEncryptProperties;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.MethodParameter;
import org.springframework.http.HttpInputMessage;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.servlet.mvc.method.annotation.RequestBodyAdvice;

import java.io.IOException;
import java.lang.reflect.Type;

/**
 * @author yangpan
 * @Title: sell
 * @Package com.citymine.sell.filter
 * @Description:
 * @date 2018/6/813:40
 */
@ControllerAdvice
@Slf4j
public class DecryRequestBodyAdvice implements RequestBodyAdvice {


    public static final String UTF_8 = "UTF-8";

    @Autowired
    private DecryptAndEncryptProperties properties;
    /**
     * 是否启用 此拦截器
     * @param methodParameter
     * @param type
     * @param aClass
     * @return
     */
    @Override
    public boolean supports(MethodParameter methodParameter, Type type, Class<? extends HttpMessageConverter<?>> aClass) {
        return true;
    }

    /**
     *
     * @param httpInputMessage  获取 请求头, 和body 的类
     * @param methodParameter
     * @param type
     * @param aClass
     * @return
     * @throws IOException
     */
    @Override
    public HttpInputMessage beforeBodyRead(HttpInputMessage httpInputMessage, MethodParameter methodParameter,
                                           Type type, Class<? extends HttpMessageConverter<?>> aClass){
        System.out.println("经过before");
        if (methodParameter.getMethod().isAnnotationPresent(Decrypt.class)&&!properties.isDebug()){
            try {
                return  new DecryptHttpInputMessage(httpInputMessage,UTF_8);
            } catch (Exception e) {
                e.printStackTrace();
                log.error("数据解密失败", e);
            }
        }
        return httpInputMessage;
    }

    /**
     * 后处理
     * @param body
     * @param httpInputMessage
     * @param methodParameter
     * @param type
     * @param aClass
     * @return
     */
    @Override
    public Object afterBodyRead(Object body, HttpInputMessage httpInputMessage, MethodParameter methodParameter, Type type, Class<? extends HttpMessageConverter<?>> aClass) {
        return body;
    }
    /**
     * @Description: 处理空body
     * @throws
     * @author yangpan
     */
    @Override
    public Object handleEmptyBody(Object body, HttpInputMessage httpInputMessage, MethodParameter methodParameter, Type type, Class<? extends HttpMessageConverter<?>> aClass) {
        return body;
    }
}
