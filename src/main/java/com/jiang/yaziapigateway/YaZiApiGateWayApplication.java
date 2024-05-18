package com.jiang.yaziapigateway;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;

@SpringBootApplication
public class YaZiApiGateWayApplication {

    public static void main(String[] args) {
        SpringApplication.run(YaZiApiGateWayApplication.class, args);
    }

    
//
//    @Bean
//    public RouteLocator customRouteLocator(RouteLocatorBuilder builder) {
//        return builder.routes()
//                .route("tobaidu", r -> r.path("/baidu")
//                        .uri("http://www.baidu.com"))
//                .route("to_yupicu", r -> r.path("/yupicu")
//                        .uri("http://yupi.icu"))
//                .build();
//    }

}
