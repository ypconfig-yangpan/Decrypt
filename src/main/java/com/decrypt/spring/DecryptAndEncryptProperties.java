package com.decrypt.spring;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * @author yangpan
 * @Title: sell
 * @Package com.citymine.sell.spring
 * @Description:
 * @date 2018/6/1413:52
 */
@ConfigurationProperties( prefix = "spring.encrypt")
public class DecryptAndEncryptProperties {


    /**
     * 开启调试模式，调试模式下不进行加解密操作，用于像Swagger这种在线API测试场景
     */
    private boolean debug = false;

    public boolean isDebug() {
        return debug;
    }

    public void setDebug(boolean debug) {
        this.debug = debug;
    }
}
