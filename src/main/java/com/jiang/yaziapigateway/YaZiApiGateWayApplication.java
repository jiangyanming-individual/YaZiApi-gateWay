package com.jiang.yaziapigateway;

import org.apache.dubbo.config.spring.context.annotation.EnableDubbo;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
@EnableDubbo //开启dubbo
public class YaZiApiGateWayApplication {

    public static void main(String[] args) {
        SpringApplication.run(YaZiApiGateWayApplication.class, args);
    }



}
