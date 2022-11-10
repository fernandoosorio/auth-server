package com.authserver.seguranca;




import javax.validation.constraints.NotBlank;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;
import org.springframework.validation.annotation.Validated;

import lombok.Data;

@Component
@Validated
@ConfigurationProperties("aw.auth")
@Data
public class AuthPropriedades {
	
	@NotBlank
	private String uriProdedor;
	
	private JksPropriedades jks;
	
	@Data
	static class JksPropriedades{
		@NotBlank
		private String keypass;
		@NotBlank
		private String storepass;
		@NotBlank
		private String alias;
		@NotBlank
		private String path;
	}
	

}
