package com.jiang.yaziapigateway;

import com.jiang.springbootinit.provider.DemoService;
import org.apache.dubbo.config.annotation.DubboReference;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

import java.util.Date;

/**
 * 服务调用
 */
@Component //注入spring boot
public class Task implements CommandLineRunner {

    /**
     *引用dubbo 的服务:
     */
    @DubboReference
    private DemoService demoService;

    @Override
    public void run(String... args) throws Exception {
        String result = demoService.sayHello("world");
        System.out.println("Receive result ======> " + result);

        String result2 = demoService.sayHello2("yupi");
        System.out.println("Receive result ======> " + result2);

        new Thread(()-> {
//            while (true) {
                try {
                    Thread.sleep(1000);
                    System.out.println(new Date() + " Receive result ======> " + demoService.sayHello("world"));
                } catch (InterruptedException e) {
                    e.printStackTrace();
                    Thread.currentThread().interrupt();
                }
//            }
        }).start();
    }
}