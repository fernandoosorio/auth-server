package com.authserver.seguranca;

import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.time.Duration;
import java.util.Arrays;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.ClientSettings;
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings;
import org.springframework.security.oauth2.server.authorization.config.TokenSettings;
import org.springframework.security.web.SecurityFilterChain;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

import lombok.var;

@EnableWebSecurity
@Configuration
public class AuthSegurancaConfig {
	
	@Bean
	@Order(Ordered.HIGHEST_PRECEDENCE)
	public SecurityFilterChain defaultFilterChain(HttpSecurity http) throws Exception {
		OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
		
		return http
				.formLogin(Customizer.withDefaults())
				.build();
		
		
	}
	
	@Bean
	public SecurityFilterChain authFilterChain(HttpSecurity http) throws Exception {
		
		http
			.authorizeRequests()
				.anyRequest()
				.authenticated();
		return http
				.formLogin(Customizer.withDefaults())
				.build();
		
		
	}
	
	@Bean
	public RegisteredClientRepository registeredClientRepository(PasswordEncoder passwordEncoder) {
		
		RegisteredClient awuserClient = RegisteredClient
				.withId("1")
				.clientId("awuser")
				.clientSecret(passwordEncoder.encode("123456"))
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
				.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
				.scope("users:read")
				.scope("users:write")
				.tokenSettings( TokenSettings.builder()
						.accessTokenTimeToLive(Duration.ofMinutes(15))
						.build())
				.clientSettings(ClientSettings.builder()
						.requireAuthorizationConsent(false)
						.build())
				.build()
				;
		
		return new InMemoryRegisteredClientRepository(
					Arrays.asList(awuserClient)
				);
	}
	
	@Bean
	public ProviderSettings providerSettings(AuthPropriedades  authPropriedades) {
		return ProviderSettings.builder()
				.issuer(authPropriedades.getUriProdedor())
				.build();
				
				
	}
	
	@Bean
	public JWKSet jWKSet(AuthPropriedades  authPropriedades) throws IOException, KeyStoreException, NoSuchAlgorithmException, CertificateException, JOSEException {
		
		final var  jksPropriedades = authPropriedades.getJks();
		String jksPath = jksPropriedades.getPath();
		final InputStream inputStream = new ClassPathResource(jksPath).getInputStream();
		
		final KeyStore keyStore  = KeyStore.getInstance("JKS");
		String storePass = jksPropriedades.getStorepass();
		
		keyStore.load(inputStream, storePass.toCharArray());
		
		RSAKey rsakey = RSAKey.load
						(keyStore,
						jksPropriedades.getAlias(), 
						storePass.toCharArray());
		
		
		return new JWKSet(rsakey);
	}
	
	
	@Bean
	public JWKSource<SecurityContext> jwkSource (JWKSet jWKSet){
		return ((jwkSelector, securityContext) -> jwkSelector.select(jWKSet) );
		
	}
	
	@Bean
	public JwtEncoder  jwtEncoder (JWKSource<SecurityContext> jwkSource ) {
		return new NimbusJwtEncoder(jwkSource);
	}
	
	
	
	
	

}
