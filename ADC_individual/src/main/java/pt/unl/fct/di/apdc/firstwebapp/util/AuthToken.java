package pt.unl.fct.di.apdc.firstwebapp.util;

import java.util.Date;
import java.util.UUID;
import io.jsonwebtoken.*;
import io.jsonwebtoken.impl.DefaultClaims;

public class AuthToken {
	private static final String SECRET = "38782F413F4428472B4B6250655368566D5970337336763979244226452948404D635166546A576E5A7234743777217A25432A462D4A614E645267556B587032";
	public static final long EXPIRATION_TIME = 1000 * 60 * 60 * 2; // 2h
	public String username;
	public String role;
	public String tokenID;
	public long creationData;
	public long expirationData;

	public AuthToken() {
	}

	public AuthToken(String username, String role) {
		this.username = username;
		this.role = role;
		this.tokenID = UUID.randomUUID().toString();
		this.creationData = System.currentTimeMillis();
		this.expirationData = this.creationData + AuthToken.EXPIRATION_TIME;
	}
	
	public AuthToken(String username, String role, String tokenID, long creationData, long expirationData) {
		this.username = username;
		this.role = role;
		this.tokenID = tokenID;
		this.creationData = creationData;
		this.expirationData = expirationData;
	}
}