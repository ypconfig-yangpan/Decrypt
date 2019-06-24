package com.decrypt.spring;

import com.decrypt.filter.DecryRequestBodyAdvice;
import com.decrypt.filter.EncryptResponseBodyAdvice;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * @author yangpan
 * @Title: sell
 * @Package
 * @Description:
 * @date 2018/6/1413:44
 */
@Configuration
@EnableConfigurationProperties(DecryptAndEncryptProperties.class)
public class AutoEncryAndDecryConfiguration {

    /**
     * 配置请求解密
     * @return
     */
    @Bean
    @ConditionalOnMissingBean
    public DecryRequestBodyAdvice encryptResponseBodyAdvice() {
        return new DecryRequestBodyAdvice();
    }

    /**
     * 配置返回加密
     * @return
     */
    @Bean
    @ConditionalOnMissingBean
    public EncryptResponseBodyAdvice encryptRequestBodyAdvice() {
        return new EncryptResponseBodyAdvice();
    }

}
