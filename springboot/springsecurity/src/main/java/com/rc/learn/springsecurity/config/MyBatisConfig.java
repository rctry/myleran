package com.rc.learn.springsecurity.config;

import org.mybatis.spring.annotation.MapperScan;
import org.springframework.context.annotation.Configuration;

/**
 * MyBatis配置类
 * Created by macro on 2019/4/8.
 */
@Configuration
@MapperScan({"com.rc.learn.springsecurity.mbg.mapper","com.rc.learn.springsecurity.dao"})
public class MyBatisConfig {
}
