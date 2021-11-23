package com.imooc.cloudmallspringcloudgatewaypractice.filter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.imooc.cloudmallspringcloudgatewaypractice.model.User;
import java.util.Objects;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * 描述：     网管鉴权过滤器
 */
@Component
public class AuthorizationFilter extends AbstractGatewayFilterFactory {

    private User currentUser = new User();
    public static final String JWT_KEY = "imooc-mall";
    public static final String USER_ID = "user_id";
    public static final String USER_NAME = "user_name";
    public static final String USER_ROLE = "user_role";
    public static final Integer ADMIN_ROLE = 2;


    @Override
    public GatewayFilter apply(Object config) {
        return (exchange, chain) -> {
            //1 对于不想对外公开的接口，拦截住
            ServerHttpRequest request = exchange.getRequest();
            String uri = request.getURI().toString();
            if (uri.contains("/getUser")
                    || uri.contains("/checkAdminRole")
                    || uri.contains("/product/updateStock")
                    || uri.contains("/product/detailForFeign")) {
                ServerHttpResponse response = exchange.getResponse();
                response.setStatusCode(HttpStatus.FORBIDDEN);
                return response.setComplete();
            }
            //2 不应该拦截的接口，要放行
            if (uri.contains("image")
                    || uri.contains("pay")
                    || uri.contains("qrcode")
                    || uri.contains("login")
                    || uri.contains("adminLogin")) {
                return chain.filter(exchange);
            }
            //3 需要鉴权的接口，要鉴权
            if (uri.contains("admin")
                    || uri.contains("cart")
                    || uri.contains("order")
                    || uri.contains("user/update")) {
                request = exchange.getRequest();
                ServerHttpResponse response = exchange.getResponse();

                uri = request.getURI().getPath();
                String method = request.getMethodValue();

                // 2.1.从AuthenticationFilter中获取token
                String key = "jwt_token";
                if (!request.getHeaders().containsKey(key)) {
                    //如果header里没有jwt_token，就直接拦住
                    response.setStatusCode(HttpStatus.FORBIDDEN);
                    return response.setComplete();
                }

                String token = Objects.requireNonNull(request.getHeaders().get(key)).get(0);
                Algorithm algorithm = Algorithm.HMAC256(JWT_KEY);
                JWTVerifier verifier = JWT.require(algorithm).build();
                try {
                    DecodedJWT jwt = verifier.verify(token);
                    currentUser.setId(jwt.getClaim(USER_ID).asInt());
                    Integer role = jwt.getClaim(USER_ROLE).asInt();
                    if (uri.contains("admin") && role != ADMIN_ROLE) {
                        return needAdmin(exchange);
                    }
                    currentUser.setRole(role);
                    currentUser.setUsername(jwt.getClaim(USER_NAME).asString());
                } catch (Exception e) {
                    //未通过校验
                    return needLogin(exchange);
                }
                //把用户信息传递个后端服务
                ServerHttpRequest host = exchange.getRequest().mutate().header(USER_ID, new String[]{String.valueOf(currentUser.getId())})
                        .header(USER_ROLE, new String[]{String.valueOf(currentUser.getRole())}).header(USER_NAME, new String[]{String.valueOf(currentUser.getUsername())}).build();
                ServerWebExchange build = exchange.mutate().request(host).build();
                return chain.filter(build);
            }
            return chain.filter(exchange);
        };
    }


    private Mono<Void> needLogin(ServerWebExchange exchange) {
        ServerHttpResponse response;
        response = exchange.getResponse();
        response.setStatusCode(HttpStatus.OK);
        response.getHeaders().add("Content-Type","application/json;charset=UTF-8");
        String msg = "{\n"
                + "    \"status\": 10007,\n"
                + "    \"msg\": \"need right jwt_token in header\",\n"
                + "    \"data\": null\n"
                + "}";
        DataBuffer bodyDataBuffer = response.bufferFactory().wrap(msg.getBytes());
        return response.writeWith(Mono.just(bodyDataBuffer));
    }

    private Mono<Void> needAdmin(ServerWebExchange exchange) {
        ServerHttpResponse response;
        response = exchange.getResponse();
        response.setStatusCode(HttpStatus.OK);
        response.getHeaders().add("Content-Type","application/json;charset=UTF-8");
        String msg = "{\n"
                + "    \"status\": 10007,\n"
                + "    \"msg\": \"need admin jwt_token in header\",\n"
                + "    \"data\": null\n"
                + "}";
        DataBuffer bodyDataBuffer = response.bufferFactory().wrap(msg.getBytes());
        return response.writeWith(Mono.just(bodyDataBuffer));
    }
}
