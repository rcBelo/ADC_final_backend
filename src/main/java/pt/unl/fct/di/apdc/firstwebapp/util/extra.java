package pt.unl.fct.di.apdc.firstwebapp.util;

import java.util.Date;

import com.google.cloud.datastore.*;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.impl.DefaultClaims;

public class extra {
	private static final String SECRET = "38782F413F4428472B4B6250655368566D5970337336763979244226452948404D635166546A576E5A7234743777217A25432A462D4A614E645267556B587032";

	//private final static Datastore datastore = DatastoreOptions.newBuilder().setHost("http://localhost:8081")
		//	.setProjectId("iconic-valve-379315").build().getService();

	private final static Datastore datastore = DatastoreOptions.getDefaultInstance().getService();
	
	public extra() {

	}

	public static int roleToInt(String role) {
		switch (role) {
		case "USER":
			return 1;
		case "GBO":
			return 2;
		case "GS":
			return 3;
		case "SU":
			return 4;
		}
		return 0;
	}

	@SuppressWarnings("deprecation")
	public static String AuthTokenCreate(AuthToken token) {
		Claims claims = new DefaultClaims();
		claims.put("username", token.username);
		claims.put("role", token.role);
		claims.put("tokenID", token.tokenID);
		claims.setExpiration(new Date(token.expirationData));
		claims.setIssuedAt(new Date(token.creationData));
		String jwtToken = Jwts.builder().setClaims(claims).setSubject("AuthenticationADC")
				.signWith(SignatureAlgorithm.HS512, SECRET).compact();
		return jwtToken;

	}

	@SuppressWarnings("deprecation")
	public static AuthToken AuthTokenDecode(String token) {

		Claims claims = Jwts.parser().setSigningKey(SECRET).parseClaimsJws(token).getBody();
		String tokenUsername = (String) claims.get("username");
		String tokenRole = (String) claims.get("role");
		String tokenID = (String) claims.get("tokenID");
		long creationDate = claims.getIssuedAt().getTime();
		long expirationDate = claims.getExpiration().getTime();

		AuthToken at = new AuthToken(tokenUsername, tokenRole, tokenID, creationDate, expirationDate);

		return at;

	}

	public static boolean checkToken(String token, String User) {

		Key tokenKey = datastore.newKeyFactory().addAncestor(PathElement.of("User", User)).setKind("UserToken")
				.newKey("token");
		try {
			Entity saveToken = datastore.get(tokenKey);
			if (saveToken == null) {
				return false;
			}

			String value = saveToken.getString("value");

			Claims claims = Jwts.parser().setSigningKey(SECRET).parseClaimsJws(token).getBody();

			long expirationDate = claims.getExpiration().getTime();

			return value.equals(token) && expirationDate >= System.currentTimeMillis();
		} catch (Exception e) {
			datastore.delete(tokenKey);
			return false;
		}

	}

	public static userOptionalData extractData(Entity user, userOptionalData data) {
		if (data.profile.equals("none")) {
			data.profile = user.getString("user_profile");
		}
		if (data.adress.equals("none")) {
			data.adress = user.getString("user_adress");
		}
		if (data.cell.equals("none")) {
			data.cell = user.getString("user_cell");
		}
		if (data.cellHome.equals("none")) {
			data.cellHome = user.getString("user_cellHome");
		}
		if (data.occupation.equals("none")) {
			data.occupation = user.getString("user_occupation");
		}
		if (data.workplace.equals("none")) {
			data.workplace = user.getString("user_workplace");
		}
		if (data.nif.equals("none")) {
			data.nif = user.getString("user_nif");
		}

		return data;
	}

	public static userOptionalAdminData extractData(Entity userToChange, userOptionalAdminData data) {
		if (data.profile.equals("none")) {
			data.profile = userToChange.getString("user_profile");
		}
		if (data.adress.equals("none")) {
			data.adress = userToChange.getString("user_adress");
		}
		if (data.cell.equals("none")) {
			data.cell = userToChange.getString("user_cell");
		}
		if (data.cellHome.equals("none")) {
			data.cellHome = userToChange.getString("user_cellHome");
		}
		if (data.occupation.equals("none")) {
			data.occupation = userToChange.getString("user_occupation");
		}
		if (data.workplace.equals("none")) {
			data.workplace = userToChange.getString("user_workplace");
		}
		if (data.nif.equals("none")) {
			data.nif = userToChange.getString("user_nif");
		}
		if (data.name.equals("none")) {
			data.name = userToChange.getString("user_name");
		}
		if (data.email.equals("none")) {
			data.email = userToChange.getString("user_email");
		}

		return data;
	}

	public static userListOut2 convert(Entity user) {

		return new userListOut2(user.getKey().getName(), user.getString("user_email"), user.getString("user_name"),
				user.getString("user_role"), user.getLong("user_state"), user.getString("user_cell"),
				user.getString("user_cellHome"), user.getString("user_occupation"), user.getString("user_workplace"),
				user.getString("user_adress"), user.getString("user_nif"), user.getString("user_profile"));
	}

}
