package com.jiang.yaziapigateway;

import com.jiang.yaziapiclientsdk.utils.SignUtils;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.Arrays;
import java.util.List;


/***
 * 全局过滤器：spring cloud gateway
 */
@Slf4j
@Component // 注入到spring boot 中
public class CustomGlobalFilter implements GlobalFilter, Ordered {
    /***
     * 设置白名单：
     */
    public static final List<String> IP_WHITE_LIST = Arrays.asList("127.0.0.1");

    private String accessServeKey="jiangyanming";
    private String secretKey="123456";

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
        log.info("============================>");
        log.info("请求的id" +request.getId());
        log.info("请求的方法" +request.getMethod());
        log.info("请求的地址" +request.getLocalAddress());
        log.info("请求的ip" +request.getLocalAddress().getHostName());
        log.info("请求的参数" +request.getQueryParams());
        log.info("请求头" +request.getHeaders());
        log.info("请求体" +request.getBody());
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
        //校验accessKey
        if (!accessServeKey.equals(accessKey)){
            //异常处理类
            return handleAuth(response);
        }
        //实际是从数据库中查出
        String genSign = SignUtils.getSign(body, secretKey);
        if (!genSign.equals(sign)){
            //异常处理类
            return handleAuth(response);
        }
        // 5. 请求的模拟接口是否存在
        //todo 去查数据库或者RPC 远程调用

        // 6. 请求转发，调用模拟接口
        Mono<Void> filter = chain.filter(exchange);

        // 7. 响应日志
        HttpStatus statusCode = response.getStatusCode();
        log.info("响应日志：" + statusCode);

        // 8. todo 调用成功，接口调用次数 + 1==>  invokeCount + 1

        // 9. 调用失败，返回一个规范的错误码
        if (statusCode == HttpStatus.OK){
            // 请求成功处理的
        }else {
            //请求失败，直接调用错误处理类：
            return handleError(response);
        }
        //返回filter :
        return filter;
    }

    @Override
    public int getOrder() {
        return -1;
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