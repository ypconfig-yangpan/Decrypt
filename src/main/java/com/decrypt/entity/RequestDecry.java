package com.decrypt.entity;

import lombok.Data;

import java.io.Serializable;

/**
 * @author yangpan
 * @Title: decrypt
 * @Package com.decrypt.entity.RequestDecry
 * @Description:
 * @date 2018/6/1317:12
 */
@Data
public class RequestDecry implements Serializable{

    private String  search;
    private String  signature;
    private String  salt;
}
