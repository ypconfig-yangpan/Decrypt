package com.decrypt.annotation;

import java.lang.annotation.*;

/**
 * @author yangpan
 * @Title: Decrypt
 * @Package com.decrypt.annotation
 * @Description:  解密
 * @date 2018/6/119:05
 */
@Target(ElementType.METHOD)
@Documented
@Retention(RetentionPolicy.RUNTIME)
public @interface Decrypt {
    String value() default "";
}
