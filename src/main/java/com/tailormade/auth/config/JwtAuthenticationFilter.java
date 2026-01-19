package com.tailormade.auth.config;

import java.io.IOException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.tailormade.auth.util.JwtUtil;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private static final Logger logger = LoggerFactory.getLogger(JwtAuthenticationFilter.class);

    @Autowired
    private UserDetailsService userDetailsService;

    @Autowired
    private JwtUtil jwtUtil;

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request,
                                  @NonNull HttpServletResponse response,
                                  @NonNull FilterChain filterChain) throws ServletException, IOException {
        
        logger.debug("Processing JWT authentication filter for URI: {}", request.getRequestURI());
        
        final String requestTokenHeader = request.getHeader("Authorization");
        logger.debug("Authorization header: {}", requestTokenHeader);

        String username = null;
        String jwtToken = null;

        if (requestTokenHeader != null && requestTokenHeader.startsWith("Bearer ")) {
            jwtToken = requestTokenHeader.substring(7);
            logger.debug("Extracted JWT token: {}", jwtToken.length() > 20 ? jwtToken.substring(0, 20) + "..." : jwtToken);
            
            try {
                username = jwtUtil.extractUsername(jwtToken);
                logger.debug("JWT Token contains username: {}", username);
            } catch (Exception e) {
                logger.error("Unable to extract username from JWT token", e);
            }
        } else {
            logger.debug("Request does not contain Bearer token or header is missing");
        }

        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            logger.debug("Attempting to load user details for username: {}", username);
            UserDetails userDetails = this.userDetailsService.loadUserByUsername(username);
            logger.debug("Loaded user details: {}", userDetails != null);

            if (jwtToken != null && jwtUtil.validateToken(jwtToken, userDetails)) {
                logger.info("JWT token is valid for user: {}", username);
                UsernamePasswordAuthenticationToken authToken = 
                    new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                
                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                
                SecurityContextHolder.getContext().setAuthentication(authToken);
                logger.info("Successfully authenticated user: {}", username);
            } else {
                logger.warn("JWT Token is invalid or expired for user: {}", username);
            }
        } else {
            logger.debug("User already authenticated or username is null");
        }

        filterChain.doFilter(request, response);
    }
}