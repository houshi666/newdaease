package io.dataease.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

/**
 * @author lad
 * @description 客户端认证
 * @time 2023/3/1
 */
@Component
@ConfigurationProperties(prefix = "sso")
@Data
public class SSOAuthConfig {
    /**
     * 客户端id
     */
    protected String clientId;
    /**
     * 客户端密钥
     */
    protected String clientSecret;
    /**
     * 重定向地址
     */
    protected String redirectUri;
    /**
     * 认证服务地址
     */
    protected String oauthServerUri;
    /**
     * authorize地址
     */
    protected String authorizeUri;
    /**
     * 授权码认证接口
     */
    protected String codeToToken;
    /**
     * 用户信息接口
     */
    protected String userinfo;
}
