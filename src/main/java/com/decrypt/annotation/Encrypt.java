package com.decrypt.annotation;

import java.lang.annotation.*;

/**
 * @author yangpan
 * @Title: Decrypt
 * @Package com.decrypt.annotation
 * @Description:  加密
 * @date 2018/6/816:01
 */
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface Encrypt {
     String value() default "";
}
