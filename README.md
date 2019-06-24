# Decrypt

```java
@Slf4j
@ControllerAdvice
public class EncryptResponseBodyAdvice implements ResponseBodyAdvice
```

```java
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
    
 ```

通过ResponseBodyAdvice 和@ControllerAdvice 注解实现的一个简单的REST加解密
