package com.example.ningjingspa.config;

import com.example.ningjingspa.dao.UserDao;
import com.example.ningjingspa.entity.User;
import com.example.ningjingspa.security.JwtAuthenticationFilter;
import com.example.ningjingspa.service.CustomOAuth2UserService;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Date;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true)   // 必须加这一行！
public class SecurityConfig {

    @Autowired
    private CustomOAuth2UserService customOAuth2UserService;

    @Autowired
    private UserDao userDao;

    @Autowired
    private JwtAuthenticationFilter jwtAuthFilter;

    @Value("${jwt.secret:IX0JmPMpG62JnXeRf26fUc6fCURc2eU2}")
    private String jwtSecret;
    
    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .cors(cors -> cors.configurationSource(corsConfigurationSource()))
            .csrf(csrf -> csrf.disable())
            .authorizeHttpRequests(auth -> auth
            	    // 1. 放行 OAuth2 认证流程路径
            	    .requestMatchers(
            	        "/oauth2/authorization/google",
            	        "/login/oauth2/code/google",
            	        "/login/oauth2/**",
            	        "/oauth2/**"
            	    ).permitAll()
            	    // 2. 放行所有公开 API（登录、注册、查看文章/产品等）
            	    .requestMatchers(
            	        "/api/auth/**",                // 登录、注册、登出
            	        "/api/articles",               // GET 文章列表
            	        "/api/articles/*",             // GET 单篇文章
            	        "/api/articles/latest",        // 最新文章
            	        "/api/articles/categories",    // 文章分类
            	        "/api/comments/article/*",     // 查看文章评论
            	        "/api/products",               // GET 产品列表
            	        "/api/products/*",             // GET 单个产品
            	        "/api/oil-shop/oils",          // 精油列表
            	        "/api/oil-shop/oils/*",        // 单个精油
            	        "/api/appointments/holidays",               // 公休日列表
            	        "/api/appointments/availability", // 预约名额查询
            	        "/api/auth/change-password",//修改密碼
            	        "/error",                       // 错误页面
            	        "/webhook"
            	    ).permitAll()
            	    // 3. 管理員 API（需要 ADMIN 权限）
            	    .requestMatchers(
            	        "/api/admin/**",
            	        "/api/appointments/admin/**",
            	        "/api/holidays/admin/**",
            	        "/api/products",               // POST 新增产品
            	        "/api/products/*",             // PUT/DELETE 操作（会被方法层 @PreAuthorize 二次保护）
            	        "/api/products/*/toggle-visibility",
            	        "/api/articles",               // POST 新增文章
            	        "/api/articles/*"             // PUT/DELETE 操作

            	    ).hasAuthority("ADMIN")
            	    // 4. 其他请求（如用户自己的预约、下单等）需要认证
            	    .anyRequest().permitAll()
            	)
            .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class)
            .exceptionHandling(ex -> ex
                .authenticationEntryPoint((request, response, authException) -> {
                    response.setContentType("application/json");
                    response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                    response.getWriter().write("{\"code\":401,\"message\":\"未登入或權限不足\"}");
                })
            )
            .oauth2Login(oauth2 -> oauth2
                .userInfoEndpoint(userInfo -> userInfo.userService(customOAuth2UserService))
                .successHandler((request, response, authentication) -> {
                    // ========== 补全的成功处理器 ==========
                    System.out.println(">>> OAuth2 successHandler 被呼叫！");

                    // 1. 正确提取 email
                    String email = null;
                    Object principal = authentication.getPrincipal();
                    if (principal instanceof OAuth2User) {
                        OAuth2User oauth2User = (OAuth2User) principal;
                        email = (String) oauth2User.getAttributes().get("email");
                    }
                    if (email == null) {
                        email = authentication.getName();
                    }
                    System.out.println("取得的 email: " + email);

                    // 2. 查找使用者
                    User user = userDao.getByEmail(email);
                    if (user == null) {
                        System.out.println("错误：使用者不存在于资料库！");
                        response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "使用者不存在");
                        return;
                    }

                    Integer userId = user.getUserId();
                    Boolean isAdmin = user.getIsAdmin() != null ? user.getIsAdmin() : false;
                    String userName = user.getName();

                    // 3. 生成 JWT Token
                    SecretKey key = Keys.hmacShaKeyFor(jwtSecret.getBytes(StandardCharsets.UTF_8));
                    String jwtToken = Jwts.builder()
                            .setSubject(email)
                            .claim("userId", userId)
                            .claim("isAdmin", isAdmin)
                            .claim("userName", userName)
                            .setIssuedAt(new Date())
                            .setExpiration(new Date(System.currentTimeMillis() + 86400000))
                            .signWith(key)
                            .compact();

                    // 4. 重定向到前端（自動判斷來源：localhost 或 ngrok）
                    String origin = request.getHeader("Origin");
                    String referer = request.getHeader("Referer");
                    String baseUrl = "http://localhost:4200";

                    String frontendUrl = baseUrl + "/login-success?token=" + jwtToken;
                    System.out.println("即将重定向到: " + frontendUrl);
                    response.sendRedirect(frontendUrl);
                })
            );

        return http.build();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        // ✅ 把 5500 和 127.0.0.1 都加进去
        configuration.setAllowedOrigins(Arrays.asList(
            "http://localhost:4200",
            "http://localhost:5500",
            "http://127.0.0.1:5500" 
        ));
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        configuration.setAllowedHeaders(Arrays.asList("*"));
        configuration.setAllowCredentials(true);
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
}