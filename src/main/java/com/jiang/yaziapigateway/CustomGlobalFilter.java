package com.jiang.yaziapigateway;

import com.jiang.apicommon.model.entity.InterfaceInfo;
import com.jiang.apicommon.model.entity.User;
import com.jiang.apicommon.service.InnerInterfaceInfoService;
import com.jiang.apicommon.service.InnerUserInterfaceInfoService;
import com.jiang.apicommon.service.InnerUserService;
import com.jiang.yaziapiclientsdk.utils.SignUtils;
import lombok.extern.slf4j.Slf4j;
import org.apache.dubbo.config.annotation.DubboReference;
import org.reactivestreams.Publisher;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DataBufferFactory;
import org.springframework.core.io.buffer.DataBufferUtils;
import org.springframework.core.io.buffer.DefaultDataBufferFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.http.server.reactive.ServerHttpResponseDecorator;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;


/***
 * 全局过滤器：spring cloud gateway
 */
@Slf4j
@Component // 注入到spring boot 中
public class CustomGlobalFilter implements GlobalFilter, Ordered {


    /**
     * dubbo服务进行调用
     */
    @DubboReference
    private InnerUserInterfaceInfoService innerUserInterfaceInfoService;

    @DubboReference
    private InnerInterfaceInfoService innerInterfaceInfoService;

    @DubboReference
    private InnerUserService innerUserService;

    /***
     * 设置白名单：
     */
    public static final List<String> IP_WHITE_LIST = Arrays.asList("127.0.0.1");

    /**
     * filter 调用是一个异步调用：
     * @param exchange
     * @param chain
     * @return
     */
    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        log.info("这是全局的过滤器================>");
        //1. 用户发送请求到API网关，默认是直接发请求
        // 2. 请求日志
        ServerHttpRequest request = exchange.getRequest();
        String url = request.getPath().value();
        String method = request.getMethod().toString();
        log.info("============================>");
        log.info("请求的id: " +request.getId());
        log.info("请求的方法: " +request.getMethod());
        log.info("请求的地址: " +request.getLocalAddress());
        log.info("请求的ip: " +request.getLocalAddress().getHostName());
        log.info("请求的参数: " +request.getQueryParams());
        log.info("请求头: " +request.getHeaders());
        log.info("请求体: " +request.getBody());
        log.info("============================>");

        String hostName = request.getLocalAddress().getHostName();
        ServerHttpResponse response = exchange.getResponse();
        // 3. 访问控制==> （黑白名单） 这里实现白名单
        if (!IP_WHITE_LIST.contains(hostName)) {
            //异常处理类
            return handleAuth(response);
        }
        // 4. 用户鉴权（判断ak，sk是否合法）
        HttpHeaders headers = request.getHeaders();
        String accessKey = headers.getFirst("accessKey");
        String body = headers.getFirst("body");
        //从请求头中拿到sign
        String sign = headers.getFirst("sign");
        String nonce = headers.getFirst("nonce");
        String timestamp = headers.getFirst("timestamp");
        System.out.println("body:"+body);

        //校验随机数字段
        if (Long.parseLong(nonce) > 10000L){
            //异常处理类
            return handleAuth(response);
        }
        //校验时间字段 ,防止重放攻击，限制五分钟以内
        long currentTimes = System.currentTimeMillis() /1000 ;
        final long FIVE_MINUES= 60 * 5L;
        if ( (currentTimes - Long.parseLong(timestamp)) >= FIVE_MINUES){
            //异常处理类
            return handleAuth(response);
        }
        //调用服务通过accessKey得到InvokeUser,校验accessKey, secreteKey
        User invokeUser =null;
        try {
            invokeUser=innerUserService.getInvokeUser(accessKey);
        }catch (Exception e){
            log.error("getInvokeUser error",e);
        }
        if (invokeUser==null) {
            //异常处理类
            return handleAuth(response);
        }
        //实际是从数据库中查出secreteKey，通过用户拿到secreteKey
        String secretKey = invokeUser.getSecretKey();
        //生成服务端签名：
        String serverSign = SignUtils.getSign(body, secretKey);
        if (!serverSign.equals(sign) || sign == null){
            //异常处理类
            return handleAuth(response);
        }
        // 5. 请求的模拟接口是否存在
        InterfaceInfo interfaceInfo=null;
        try {
            interfaceInfo = innerInterfaceInfoService.getInterfaceInfo(url, method);
        }catch (Exception e){
            log.error("getInterfaceInfo error",e);
        }
        if (interfaceInfo == null){
            //异常处理类
            return handleAuth(response);
        }
        // 6. 请求转发，调用模拟接口
        /**
         * 传入userId, interfaceInfoId
         */
        return handleResponse(exchange,chain,interfaceInfo.getId(),invokeUser.getId()); //调用自定义响应处理类
//        // 7. 响应日志
//        HttpStatus statusCode = response.getStatusCode();
//        log.info("响应日志：" + statusCode);

//        // 9. 调用失败，返回一个规范的错误码
//        if (statusCode == HttpStatus.OK){
//            // 请求成功处理的
//        }else {
//            //请求失败，直接调用错误处理类：
//            return handleError(response);
//        }
//        //返回filter :
//        return filter;
    }

    @Override
    public int getOrder() {
        return -1;
    }

    /**
     * 增强响应 response, 将业务的处理都放到增强返回类中
     * @param exchange
     * @param chain
     * @return
     */
    public Mono<Void> handleResponse(ServerWebExchange exchange, GatewayFilterChain chain, long interfaceInfoId,long userId) {
        try {
            ServerHttpResponse originalResponse = exchange.getResponse();
            //缓存数据的工厂
            DataBufferFactory bufferFactory = originalResponse.bufferFactory();
            //拿到响应码
            HttpStatus statusCode = originalResponse.getStatusCode();
            if (statusCode == HttpStatus.OK) {
                //装饰，增强能力
                ServerHttpResponseDecorator decoratedResponse = new ServerHttpResponseDecorator(originalResponse) {
                    //等调用完转发的接口后才会执行
                    @Override
                    public Mono<Void> writeWith(Publisher<? extends DataBuffer> body) {
                        log.info("body instanceof Flux: {}", (body instanceof Flux));
                        if (body instanceof Flux) {
                            Flux<? extends DataBuffer> fluxBody = Flux.from(body);
                            //往返回值里写数据
                            //破解字符串
                            return super.writeWith(
                                    fluxBody.map(dataBuffer -> {
                                        //7.TODO 调用成功后，次数+ 1,其实就是修改数据库
                                        innerUserInterfaceInfoService.invokeCount(interfaceInfoId,userId);
                                        byte[] content = new byte[dataBuffer.readableByteCount()];
                                        dataBuffer.read(content);
                                        DataBufferUtils.release(dataBuffer);//释放掉内存
                                        // 构建日志
                                        StringBuilder sb2 = new StringBuilder(200);
                                        sb2.append("<--- {} {} \n");
                                        List<Object> rspArgs = new ArrayList<>();
                                        rspArgs.add(originalResponse.getStatusCode());
                                        //rspArgs.add(requestUrl);
                                        String data = new String(content, StandardCharsets.UTF_8);//data
                                        sb2.append(data);
                                        //打印日志
                                        log.info("响应结果" + data);
                                        return bufferFactory.wrap(content);
                                    }));
                        } else {
                            //8.TODO 调用失败后，返回规范的错误码
                            log.error("<--- {} 响应code异常", getStatusCode());
                        }
                        return super.writeWith(body);
                    }
                };
                //设置response对象为装饰过的
                return chain.filter(exchange.mutate().response(decoratedResponse).build());
            }
            return chain.filter(exchange);//降级处理返回数据
        } catch (Exception e) {
            log.error("网关处理响应错误" + e);
            return chain.filter(exchange);
        }
    }
    /**
     * 权限处理类
     * @param response
     * @return
     */
    public Mono<Void> handleAuth(ServerHttpResponse response){
        //设置响应状态码403没有权限：
        response.setStatusCode(HttpStatus.FORBIDDEN);
        //完成响应
        return response.setComplete();
    }

    /**
     * 错误处理类
     * @param response
     * @return
     */
    public Mono<Void> handleError(ServerHttpResponse response){
        //设置响应状态码500 内部错误：
        response.setStatusCode(HttpStatus.INTERNAL_SERVER_ERROR);
        //完成响应
        return response.setComplete();
    }
}