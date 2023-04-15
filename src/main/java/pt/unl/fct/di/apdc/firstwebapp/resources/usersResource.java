package pt.unl.fct.di.apdc.firstwebapp.resources;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.logging.Logger;

import javax.ws.rs.Consumes;
import javax.ws.rs.DELETE;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;
import javax.servlet.http.HttpServletRequest;

import com.fasterxml.jackson.annotation.JsonRawValue;
import com.google.appengine.repackaged.org.apache.commons.codec.digest.DigestUtils;
import com.google.cloud.Timestamp;
import com.google.cloud.datastore.*;
import com.google.cloud.datastore.StructuredQuery.*;
import com.google.gson.Gson;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import pt.unl.fct.di.apdc.firstwebapp.util.AuthToken;
import pt.unl.fct.di.apdc.firstwebapp.util.LoginData;
import pt.unl.fct.di.apdc.firstwebapp.util.SignInData;
import pt.unl.fct.di.apdc.firstwebapp.util.changePwdData;
import pt.unl.fct.di.apdc.firstwebapp.util.extra;
import pt.unl.fct.di.apdc.firstwebapp.util.userListOut1;
import pt.unl.fct.di.apdc.firstwebapp.util.userListOut2;
import pt.unl.fct.di.apdc.firstwebapp.util.userOptionalAdminData;
import pt.unl.fct.di.apdc.firstwebapp.util.userOptionalData;

import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;

import com.google.cloud.datastore.*;
import com.google.gson.Gson;

import com.google.cloud.storage.Acl;
import com.google.cloud.storage.Blob;
import com.google.cloud.storage.BlobId;
import com.google.cloud.storage.BlobInfo;
import com.google.cloud.storage.Storage;
import com.google.cloud.storage.StorageOptions;

@Path("/users")
@Produces(MediaType.APPLICATION_JSON + ";charset=utf-8")
public class usersResource {

	private static final Logger LOG = Logger.getLogger(usersResource.class.getName());

	private final Gson g = new Gson();

	//private final Datastore datastore = DatastoreOptions.getDefaultInstance().getService();
	private final Datastore datastore = DatastoreOptions.newBuilder().setHost("http://localhost:8081")
			.setProjectId("iconic-valve-379315").build().getService();

	public usersResource() {
	}

	@POST
	@Path("/SU")
	@Consumes(MediaType.APPLICATION_JSON)
	public Response SU(@QueryParam("password") String password) {
		LOG.fine("Creating SuperUSER Ruben Belo");

		Transaction txn = datastore.newTransaction();

		try {
			Key userKey = datastore.newKeyFactory().setKind("User").newKey("rbnBeloSU");
			Key tokenKey = datastore.newKeyFactory().addAncestor(PathElement.of("User", "rbnBeloSU"))
					.setKind("UserToken").newKey("token");
			Entity user = txn.get(userKey);
			if (user != null) {
				txn.rollback();
				return Response.status(Status.BAD_REQUEST).entity("User already exists.").build();
			} else {
				String n = "none";
				user = Entity.newBuilder(userKey).set("user_name", "Ruben Belo")
						.set("user_pwd", DigestUtils.sha512Hex(password)).set("user_email", "su@email")
						.set("user_role", "SU").set("user_state", 1l).set("user_profile", "publico").set("user_cell", n).set("user_cellHome", n)
						.set("user_occupation", n).set("user_workplace", n).set("user_adress", n).set("user_nif", n).set("user_photo", n)
						.set("user_creation_time", Timestamp.now()).build();

				AuthToken at = new AuthToken("rbnBeloSU", user.getString("user_role"));
				String tokenString = extra.AuthTokenCreate(at);
				Entity token = Entity.newBuilder(tokenKey).set("value", tokenString).build();
				Response r = Response.ok(g.toJson(at)).header("token", extra.AuthTokenCreate(at)).build();

				txn.add(user, token);

				LOG.info("SuperUSER registered " + password);
				txn.commit();
				return r;
			}
		} catch (Exception e) {
			txn.rollback();
			LOG.severe(e.getMessage());
			return Response.status(Status.INTERNAL_SERVER_ERROR).build();
		} finally {
			if (txn.isActive()) {
				txn.rollback();
				return Response.status(Status.INTERNAL_SERVER_ERROR).build();
			}
		}

	}

	@POST
	@Path("/signIn")
	@Consumes(MediaType.APPLICATION_JSON)
	public Response doSignin(SignInData data) {
		LOG.fine("Attempt to register user: " + data.username);

		if (!data.validRegistation()) {
			return Response.status(Status.BAD_REQUEST).entity("Missing or wrong parameter.").build();
		}

		Transaction txn = datastore.newTransaction();

		try {
			Key userKey = datastore.newKeyFactory().setKind("User").newKey(data.username);
			Key tokenKey = datastore.newKeyFactory().addAncestor(PathElement.of("User", data.username))
					.setKind("UserToken").newKey("token");
			Entity user = txn.get(userKey);
			if (user != null) {
				txn.rollback();
				return Response.status(Status.BAD_REQUEST).entity("User already exists.").build();
			} else {
				String n = "none";
				user = Entity.newBuilder(userKey).set("user_name", data.name)
						.set("user_pwd", DigestUtils.sha512Hex(data.password)).set("user_email", data.email)
						.set("user_role", "USER").set("user_state", 0l).set("user_profile", "publico").set("user_cell", n).set("user_cellHome", n)
						.set("user_occupation", n).set("user_workplace", n).set("user_adress", n).set("user_nif", n).set("user_photo", n)
						.set("user_creation_time", Timestamp.now()).build();

				AuthToken at = new AuthToken(data.username, user.getString("user_role"));
				String tokenString = extra.AuthTokenCreate(at);
				Entity token = Entity.newBuilder(tokenKey).set("value", tokenString).build();
				Response r = Response.ok(g.toJson(at)).header("token", extra.AuthTokenCreate(at)).build();

				txn.add(user, token);

				LOG.info("User registered " + data.username);
				txn.commit();
				return r;
			}
		} catch (Exception e) {
			txn.rollback();
			LOG.severe(e.getMessage());
			return Response.status(Status.INTERNAL_SERVER_ERROR).build();
		} finally {
			if (txn.isActive()) {
				txn.rollback();
				return Response.status(Status.INTERNAL_SERVER_ERROR).build();
			}
		}
	}

	@POST
	@Path("/login")
	@Consumes(MediaType.APPLICATION_JSON)
	public Response doLogin(LoginData data, @Context HttpServletRequest request, @Context HttpHeaders headers) {

		LOG.fine("Attempt to Login user: " + data.username);

		Key userKey = datastore.newKeyFactory().setKind("User").newKey(data.username);
		Key counterKey = datastore.newKeyFactory().addAncestor(PathElement.of("User", data.username))
				.setKind("UserStats").newKey("counters");

		Key logKey = datastore.allocateId(datastore.newKeyFactory().addAncestor(PathElement.of("User", data.username))
				.setKind("UserLog").newKey());

		Key tokenKey = datastore.newKeyFactory().addAncestor(PathElement.of("User", data.username)).setKind("UserToken")
				.newKey("token");

		Transaction txn = datastore.newTransaction();
		try {
			Entity user = txn.get(userKey);
			if (user == null) {
				LOG.warning("User " + data.username + " does not exist");
				return Response.status(Status.FORBIDDEN).build();
			}
			Entity stats = txn.get(counterKey);

			if (stats == null) {
				stats = Entity.newBuilder(counterKey).set("user_stats_logins", 0L).set("user_stats_failed", 0L)
						.set("user_first_login", Timestamp.now()).set("user_last_login", Timestamp.now()).build();
			}

			String HashedPWD = (String) user.getString("user_pwd");

			if (HashedPWD.equals(DigestUtils.sha512Hex(data.password))) {

				Entity log = Entity.newBuilder(logKey).set("user_login_ip", request.getRemoteAddr())
						.set("user_login_host", request.getRemoteHost()).set("user_login_time", Timestamp.now())
						.build();
				stats = Entity.newBuilder(stats).set("user_stats_logins", 1L + stats.getLong("user_stats_logins"))
						.set("user_stats_failed", 0L).set("user_first_login", stats.getTimestamp("user_first_login"))
						.set("user_last_login", Timestamp.now()).build();

				AuthToken at = new AuthToken(data.username, user.getString("user_role"));
				String tokenString = extra.AuthTokenCreate(at);
				Entity token = Entity.newBuilder(tokenKey).set("value", tokenString).build();
				userListOut2 outUser = extra.convert(user);
				Response r = Response.ok(g.toJson(outUser)).header("token", tokenString).build();
				txn.put(log, stats, token);
				txn.commit();
				LOG.info("User " + data.username + " logged in sucessfully");

				return r;

			} else {
				stats = Entity.newBuilder(counterKey).set("user_stats_logins", stats.getLong("user_stats_logins"))
						.set("user_stats_failed", 1L + stats.getLong("user_stats_logins"))
						.set("user_first_login", stats.getTimestamp("user_first_login"))
						.set("user_last_login", Timestamp.now()).set("user_last_attempt", Timestamp.now()).build();
				LOG.warning("Failed login attempt for " + data.username);
				txn.put(stats);
				txn.commit();
				return Response.status(Status.FORBIDDEN).build();

			}
		} finally {
			if (txn.isActive()) {
				txn.rollback();
				return Response.status(Status.BAD_REQUEST).build();
			}
		}
	}

	@PUT
	@Path("/role/{targetUsername}")
	@Consumes(MediaType.APPLICATION_JSON)
	public Response changeRole(
			@PathParam("targetUsername") String targetUsername, @QueryParam("newRole") String newRole,
			@Context HttpHeaders headers) {

		String username;
		AuthToken at;
		try {
			String token = headers.getHeaderString("token");

			at = extra.AuthTokenDecode(token);
			
			username = at.username;
		} catch (Exception e) {
			return Response.status(Status.NETWORK_AUTHENTICATION_REQUIRED).build();
		}
		
		if(!extra.checkToken(headers.getHeaderString("token"), username)) {
			LOG.warning("token not valid for user " + username);
			return Response.status(Status.NETWORK_AUTHENTICATION_REQUIRED).build();
			}
		
		LOG.warning(username + " attempt to change user role " + targetUsername);


		Transaction txn = datastore.newTransaction();

		try {
			Key targetUserKey = datastore.newKeyFactory().setKind("User").newKey(targetUsername);

			Entity targetUser = txn.get(targetUserKey);
			if (targetUser == null) {
				txn.rollback();
				return Response.status(Status.BAD_REQUEST).entity("User does not exists.").build();
			}

			int userRole = extra.roleToInt(at.role);

			int userToChangeRole = extra.roleToInt(targetUser.getString("user_role"));

			int newRoleCode = extra.roleToInt(newRole);

			if (userRole == 0) {
				LOG.warning("user without role " + username);
				txn.rollback();
				return Response.status(Status.INTERNAL_SERVER_ERROR).build();
			}

			if (newRoleCode == 0) {
				LOG.warning("wrong new role " + newRole);
				txn.rollback();
				return Response.status(Status.BAD_REQUEST).build();
			}

			if (userToChangeRole == 0) {
				LOG.warning("user without role " + targetUsername);
				txn.rollback();
				return Response.status(Status.INTERNAL_SERVER_ERROR).build();
			}

			if (userToChangeRole >= userRole || userRole == 2) {
				LOG.warning(username + " wrong change role request for user " + targetUsername);
				txn.rollback();
				return Response.status(Status.BAD_REQUEST).build();
			}

			if (userRole == 3 && (userToChangeRole == 2 || userToChangeRole == 1)
					&& (newRoleCode == 3 || newRoleCode == 1)) {
				LOG.warning(username + " wrong change role request for user " + targetUsername);
				txn.rollback();
				return Response.status(Status.BAD_REQUEST).build();
			}

			targetUser = Entity.newBuilder(targetUser).set("user_role", newRole).build();
			txn.update(targetUser);
			txn.commit();
			return Response.ok().build();

		} finally {
			if (txn.isActive()) {
				txn.rollback();
				return Response.status(Status.INTERNAL_SERVER_ERROR).build();
			}
		}

	}

	//test only
	@PUT
	@Path("/{username}/state/{targetUsername}")
	@Consumes(MediaType.APPLICATION_JSON)
	public Response changeState(@PathParam("username") String username,
			@PathParam("targetUsername") String targetUsername, @Context HttpHeaders headers) {

		LOG.fine(targetUsername + " attempt to change user state " + username);

		String token = headers.getHeaderString("token");

		AuthToken at = extra.AuthTokenDecode(token);

		Transaction txn = datastore.newTransaction();

		try {
			Key targetUser = datastore.newKeyFactory().setKind("User").newKey(targetUsername);

			Entity userToChangeState = txn.get(targetUser);
			if (userToChangeState == null) {
				txn.rollback();
				return Response.status(Status.BAD_REQUEST).entity("User does not exists.").build();
			}

			int userRole = extra.roleToInt(at.role);

			int userToChangeRole = extra.roleToInt(userToChangeState.getString("user_role"));

			if (userRole == 0) {
				LOG.warning("user without role " + username);
				txn.rollback();
				return Response.status(Status.INTERNAL_SERVER_ERROR).build();
			}

			if (userToChangeRole == 0) {
				LOG.warning("user without role " + targetUsername);
				txn.rollback();
				return Response.status(Status.INTERNAL_SERVER_ERROR).build();
			}

			if (userToChangeRole >= userRole) {
				LOG.warning(username + " wrong change state request for user " + targetUsername);
				txn.rollback();
				return Response.status(Status.BAD_REQUEST).build();
			}
			long state = userToChangeState.getLong("user_state");
			state = 1 - state;
			userToChangeState = Entity.newBuilder(userToChangeState).set("user_state", state).build();

			txn.update(userToChangeState);
			txn.commit();
			return Response.ok().build();

		} finally {
			if (txn.isActive()) {
				txn.rollback();
				return Response.status(Status.INTERNAL_SERVER_ERROR).build();
			}
		}

	}

	@PUT
	@Path("/{username}/state")
	@Consumes(MediaType.APPLICATION_JSON)
	public Response changeState(@PathParam("username") String username, @Context HttpHeaders headers) {
		LOG.fine("Attempt to change state user: " + username);

		Transaction txn = datastore.newTransaction();

		try {
			Key userKey = datastore.newKeyFactory().setKind("User").newKey(username);
			Entity user = txn.get(userKey);
			if (user == null) {
				txn.rollback();
				LOG.warning("user does not exist " + username);
				return Response.status(Status.BAD_REQUEST).build();
			}
			long state = user.getLong("user_state");
			state = 1 - state;

			user = Entity.newBuilder(user).set("user_state", state).build();

			txn.update(user);
			txn.commit();
			return Response.ok().build();

		} finally {
			if (txn.isActive()) {
				txn.rollback();
				return Response.status(Status.INTERNAL_SERVER_ERROR).build();
			}
		}
	}

	@DELETE
	@Path("/delete")
	@Consumes(MediaType.APPLICATION_JSON)
	public Response deleteUser(@Context HttpHeaders headers) {
		
		
		String username;
		AuthToken at;
		try {
			String token = headers.getHeaderString("token");

			at = extra.AuthTokenDecode(token);
			
			username = at.username;
		} catch (Exception e) {
			return Response.status(Status.NETWORK_AUTHENTICATION_REQUIRED).build();
		}
		
		if(!extra.checkToken(headers.getHeaderString("token"), username)) {
			LOG.warning("token not valid for user " + username);
			return Response.status(Status.NETWORK_AUTHENTICATION_REQUIRED).build();
			}
		LOG.fine("Attempt to delete user: " + username);

		Transaction txn = datastore.newTransaction();

		try {
			Key userKey = datastore.newKeyFactory().setKind("User").newKey(username);
			Key tokenKey = datastore.newKeyFactory().addAncestor(PathElement.of("User", username)).setKind("UserToken")
					.newKey("token");
			txn.delete(userKey, tokenKey);
			LOG.info("User deleted " + username);
			txn.commit();
			return Response.ok().build();

		} finally {
			if (txn.isActive()) {
				txn.rollback();
				return Response.status(Status.INTERNAL_SERVER_ERROR).build();
			}
		}
	}

	@DELETE
	@Path("/delete/{userToDelete}")
	@Consumes(MediaType.APPLICATION_JSON)
	public Response deleteUser(
			@PathParam("userToDelete") String usernameToDelete, @Context HttpHeaders headers) {
		
		String username;
		AuthToken at;
		try {
			String token = headers.getHeaderString("token");

			at = extra.AuthTokenDecode(token);
			
			username = at.username;
		} catch (Exception e) {
			return Response.status(Status.NETWORK_AUTHENTICATION_REQUIRED).build();
		}
		if(!extra.checkToken(headers.getHeaderString("token"), username)) {
			LOG.warning("token not valid for user " + username);
			return Response.status(Status.NETWORK_AUTHENTICATION_REQUIRED).build();
			}

		LOG.fine("Attempt to delete user: " + username);

		Transaction txn = datastore.newTransaction();

		try {
			Key userToDeleteKey = datastore.newKeyFactory().setKind("User").newKey(usernameToDelete);
			Key tokenKey = datastore.newKeyFactory().addAncestor(PathElement.of("User", usernameToDelete))
					.setKind("UserToken").newKey("token");

			Entity userToDelete = txn.get(userToDeleteKey);
			if (userToDelete == null) {
				txn.rollback();
				return Response.status(Status.BAD_REQUEST).entity("User does not exists.").build();
			}

			int userRole = extra.roleToInt(at.role);

			int userToDeleteRole = extra.roleToInt(userToDelete.getString("user_role"));

			if (userRole == 0) {
				LOG.warning("user without role " + username);
				txn.rollback();
				return Response.status(Status.INTERNAL_SERVER_ERROR).build();
			}

			if (userToDeleteRole == 0) {
				LOG.warning("user without role " + usernameToDelete);
				txn.rollback();
				return Response.status(Status.INTERNAL_SERVER_ERROR).build();
			}

			if (userToDeleteRole >= userRole) {
				LOG.warning("Wrong delete request for user " + username + " attemps to delete " + usernameToDelete);
				txn.rollback();
				return Response.status(Status.BAD_REQUEST).build();
			}

			txn.delete(userToDeleteKey, tokenKey);
			LOG.info("User deleted " + usernameToDelete + " by " + username);
			txn.commit();
			return Response.ok().build();

		} finally {
			if (txn.isActive()) {
				txn.rollback();
				return Response.status(Status.INTERNAL_SERVER_ERROR).build();
			}
		}
	}

	@PUT
	@Path("/updateInfo/{targetUsername}")
	@Consumes(MediaType.APPLICATION_JSON)
	public Response updateUserInfo(
			@PathParam("targetUsername") String targetUsername, userOptionalAdminData data,
			@Context HttpHeaders headers) {
		
		String username;
		AuthToken at;
		try {
			String token = headers.getHeaderString("token");

			at = extra.AuthTokenDecode(token);
			
			username = at.username;
		} catch (Exception e) {
			return Response.status(Status.NETWORK_AUTHENTICATION_REQUIRED).build();
		}

		if(!extra.checkToken(headers.getHeaderString("token"), username)) {
			LOG.warning("token not valid for user " + username);
			return Response.status(Status.NETWORK_AUTHENTICATION_REQUIRED).build();
			}
		
		LOG.fine(targetUsername + " attempt to change user state " + username);

		Transaction txn = datastore.newTransaction();

		try {
			Key targetUser = datastore.newKeyFactory().setKind("User").newKey(targetUsername);

			Entity userToChange = txn.get(targetUser);
			if (userToChange == null) {
				txn.rollback();
				return Response.status(Status.BAD_REQUEST).entity("User does not exists.").build();
			}

			int userRole = extra.roleToInt(at.role);

			int userToChangeRole = extra.roleToInt(userToChange.getString("user_role"));

			if (userRole == 0) {
				LOG.warning("user without role " + username);
				txn.rollback();
				return Response.status(Status.INTERNAL_SERVER_ERROR).build();
			}

			if (userToChangeRole == 0) {
				LOG.warning("user without role " + targetUsername);
				txn.rollback();
				return Response.status(Status.INTERNAL_SERVER_ERROR).build();
			}

			if (userToChangeRole >= userRole) {
				LOG.warning(username + " wrong change state request for user " + targetUsername);
				txn.rollback();
				return Response.status(Status.BAD_REQUEST).build();
			}

			data = extra.extractData(userToChange, data);

			userToChange = Entity.newBuilder(userToChange).set("user.profile", data.profile).set("user_name", data.name).set("user_email", data.email)
					.set("user_cell", data.cell).set("user_cellHome", data.cellHome)
					.set("user_occupation", data.occupation).set("user_workplace", data.workplace)
					.set("user_adress", data.adress).set("user_nif", data.nif).build();
			txn.update(userToChange);

			LOG.info(targetUsername + " User updatated " + username);

			txn.update(userToChange);
			txn.commit();
			return Response.ok().build();

		} finally {
			if (txn.isActive()) {
				txn.rollback();
				return Response.status(Status.INTERNAL_SERVER_ERROR).build();
			}
		}

	}

	@PUT
	@Path("/updateUserInfo")
	@Consumes(MediaType.APPLICATION_JSON)
	public Response updateUserInfo( userOptionalData data,
			@Context HttpHeaders headers) {
		String username;
		AuthToken at;
		try {
			String token = headers.getHeaderString("token");

			at = extra.AuthTokenDecode(token);
			
			username = at.username;
		} catch (Exception e) {
			return Response.status(Status.NETWORK_AUTHENTICATION_REQUIRED).build();
		}
		if(!extra.checkToken(headers.getHeaderString("token"), username)) {
			LOG.warning("token not valid for user " + username);
			return Response.status(Status.NETWORK_AUTHENTICATION_REQUIRED).build();
			}

		LOG.warning("Attempt to update info user: " + data.cell);
		
		Transaction txn = datastore.newTransaction();

		try {
			Key userKey = datastore.newKeyFactory().setKind("User").newKey(username);
			Entity user = txn.get(userKey);
			if (user == null) {
				txn.rollback();
				return Response.status(Status.BAD_REQUEST).entity("User does not exists.").build();
			} else {

				data = extra.extractData(user, data);
				LOG.warning("Attempt to update info user: " + data.cell);
				user = Entity.newBuilder(user).set("user_profile", data.profile).set("user_cell", data.cell)
						.set("user_cellHome", data.cellHome).set("user_occupation", data.occupation)
						.set("user_workplace", data.workplace).set("user_adress", data.adress).set("user_nif", data.nif)
						.build();
				txn.update(user);
				LOG.info("User updatated " + user.getString("user_cell"));
				txn.commit();
				return Response.ok().build();
			}
		} finally {
			if (txn.isActive()) {
				txn.rollback();
				return Response.status(Status.INTERNAL_SERVER_ERROR).build();
			}
		}
	}

	@PUT
	@Path("/changePwd")
	@Consumes(MediaType.APPLICATION_JSON)
	public Response changepwd(changePwdData data,
			@Context HttpHeaders headers) {
		
		String username;
		AuthToken at;
		try {
			String token = headers.getHeaderString("token");

			at = extra.AuthTokenDecode(token);
			
			username = at.username;
		} catch (Exception e) {
			return Response.status(Status.NETWORK_AUTHENTICATION_REQUIRED).build();
		}
		
		if(!extra.checkToken(headers.getHeaderString("token"), username)) {
			LOG.warning("token not valid for user " + username);
			return Response.status(Status.NETWORK_AUTHENTICATION_REQUIRED).build();
			}
		
		LOG.fine("Attempt to alter user pwd: " + username);

		Transaction txn = datastore.newTransaction();

		try {

			Key userKey = datastore.newKeyFactory().setKind("User").newKey(username);
			Entity user = txn.get(userKey);

			if (user == null) {

				txn.rollback();
				LOG.warning("user does not exist " + username);
				return Response.status(Status.BAD_REQUEST).entity("User does not exists.").build();

			} else {

				if (user.getString("user_pwd").equals(DigestUtils.sha512Hex(data.oldPassword))
						&& data.passwordConfirm.equals(data.newPassword)) {

					user = Entity.newBuilder(user).set("user_pwd", DigestUtils.sha512Hex(data.newPassword)).build();
					txn.update(user);
					LOG.info("pwd altered " + username);
					txn.commit();
					return Response.ok().build();

				} else {

					txn.rollback();
					LOG.warning("user " + username + " passwords did not match");
					return Response.status(Status.BAD_REQUEST).build();
				}
			}
		} finally {
			if (txn.isActive()) {
				txn.rollback();
				return Response.status(Status.INTERNAL_SERVER_ERROR).build();
			}
		}
	}

	@GET
	@Path("/token")
	@Consumes(MediaType.APPLICATION_JSON)
	public Response Showtoken(@Context HttpHeaders headers) {

		String token = headers.getHeaderString("token");

		AuthToken at = extra.AuthTokenDecode(token);

		return Response.ok(g.toJson(at)).header("token", token).build();

	}

	//test only
	@GET
	@Path("/user/{username}")
	@Consumes(MediaType.APPLICATION_JSON)
	public Response getUser(@PathParam("username") String username, @Context HttpHeaders headers) {

		if (!extra.checkToken(headers.getHeaderString("token"), username)) {
			LOG.warning("token not valid for user " + username);
			return Response.status(Status.BAD_REQUEST).build();
		}

		Transaction txn = datastore.newTransaction();

		try {
			Key userKey = datastore.newKeyFactory().setKind("User").newKey(username);
			Entity user = txn.get(userKey);
			if (user == null) {
				txn.rollback();
				LOG.warning("user does not exist " + username);
				return Response.status(Status.BAD_REQUEST).build();
			}
			LOG.info("User geted " + username);
			txn.commit();
			return Response.ok(g.toJson(user)).build();

		} finally {
			if (txn.isActive()) {
				txn.rollback();
				return Response.status(Status.INTERNAL_SERVER_ERROR).build();
			}
		}

	}
	
	@GET
	@Path("/user/me")
	@Consumes(MediaType.APPLICATION_JSON)
	public Response getMyUser(@Context HttpHeaders headers) {
		
		String username;
		AuthToken at;
		try {
			String token = headers.getHeaderString("token");

			at = extra.AuthTokenDecode(token);
			
			username = at.username;
		} catch (Exception e) {
			return Response.status(Status.NETWORK_AUTHENTICATION_REQUIRED).build();
		}
		
		if(!extra.checkToken(headers.getHeaderString("token"), username)) {
		LOG.warning("token not valid for user " + username);
		return Response.status(Status.NETWORK_AUTHENTICATION_REQUIRED).build();
		}
		

		Transaction txn = datastore.newTransaction();

		try {
			Key userKey = datastore.newKeyFactory().setKind("User").newKey(username);
			Entity user = txn.get(userKey);
			if (user == null) {
				txn.rollback();
				LOG.warning("user does not exist " + username);
				return Response.status(Status.BAD_REQUEST).build();
			}
			LOG.info("User geted " + username);
			txn.commit();
			return Response.ok(g.toJson(extra.convert(user))).build();

		} finally {
			if (txn.isActive()) {
				txn.rollback();
				return Response.status(Status.INTERNAL_SERVER_ERROR).build();
			}
		}

	}

	@DELETE
	@Path("/Logout")
	@Consumes(MediaType.APPLICATION_JSON)
	public Response Logout(@Context HttpHeaders headers) {

		String username;
		AuthToken at;
		try {
			String token = headers.getHeaderString("token");
			LOG.warning("token not valid " + token);
			at = extra.AuthTokenDecode(token);
			
			username = at.username;
		} catch (Exception e) {
			return Response.status(Status.NETWORK_AUTHENTICATION_REQUIRED).build();
		}
		
		if(!extra.checkToken(headers.getHeaderString("token"), username)) {
		LOG.warning("token not valid for user " + username);
		return Response.status(Status.NETWORK_AUTHENTICATION_REQUIRED).build();
		}

		Transaction txn = datastore.newTransaction();

		try {
			Key tokenKey = datastore.newKeyFactory().addAncestor(PathElement.of("User", username)).setKind("UserToken")
					.newKey("token");
			txn.delete(tokenKey);
			LOG.info("User logout " + username);
			txn.commit();
			return Response.ok().build();

		} finally {
			if (txn.isActive()) {
				txn.rollback();
				return Response.status(Status.INTERNAL_SERVER_ERROR).build();
			}
		}

	}

	@PUT
	@Path("/token/new")
	@Consumes(MediaType.APPLICATION_JSON)
	public Response getToken( @Context HttpHeaders headers) {

		String username;
		AuthToken at;
		try {
			String token = headers.getHeaderString("token");

			at = extra.AuthTokenDecode(token);
			
			username = at.username;
		} catch (Exception e) {
			return Response.status(Status.NETWORK_AUTHENTICATION_REQUIRED).build();
		}
		
		Transaction txn = datastore.newTransaction();

		try {
			Key tokenKey = datastore.newKeyFactory().addAncestor(PathElement.of("User", username)).setKind("UserToken")
					.newKey("token");
			
			at = new AuthToken(username, at.role);
			String tokenString = extra.AuthTokenCreate(at);
			Entity token = Entity.newBuilder(tokenKey).set("value", tokenString).build();

			Response r = Response.ok(g.toJson(at)).header("token", tokenString).build();
			txn.put(token);
			txn.commit();
			return r;

		} finally {
			if (txn.isActive()) {
				txn.rollback();
				return Response.status(Status.INTERNAL_SERVER_ERROR).build();
			}
		}
	}

	@GET
	@Path("/list")
	@Consumes(MediaType.APPLICATION_JSON)
	public Response getUsers(@Context HttpHeaders headers) {

		/*
		 * if (!extra.checkToken(headers.getHeaderString("token"), username)) {
		 * LOG.warning("token not valid for user " + username); return
		 * Response.status(Status.BAD_REQUEST).build(); }
		 */

		String token = headers.getHeaderString("token");

		AuthToken at = extra.AuthTokenDecode(token);

		String role = at.role;
		
		LOG.warning(role + "attemp to list");

		QueryResults<Entity> users;

		if(role.equals("USER")) {
			LOG.warning("list user");
			
			Query<Entity> query_USER = Query.newEntityQueryBuilder().setKind("User").setFilter(
					CompositeFilter.and(PropertyFilter.eq("user_role", "USER"), PropertyFilter.eq("user_state", 1l), PropertyFilter.eq("user_profile", 1l)))
					.build();
			LOG.warning("list user");
			users = datastore.run(query_USER);
			List<userListOut1> result_USER = new ArrayList();
			users.forEachRemaining(user -> {
				LOG.warning(user.getString("user_name"));
				result_USER.add(new userListOut1(user.getKey().getName(), user.getString("user_email"),
						user.getString("user_name")));
			});
			return Response.ok(g.toJson(result_USER)).build();
		}
		
		if(role.equals("GBO")) {
			LOG.warning("list GBO");
			Query<Entity> query_GBO = Query.newEntityQueryBuilder().setKind("User")
					.setFilter(CompositeFilter.and(PropertyFilter.eq("user_role", "USER"))).build();
			
			users = datastore.run(query_GBO);
			
			List<userListOut2> result_GBO = new ArrayList();
			
			users.forEachRemaining(user -> {
				LOG.warning(user.getString("user_name"));
				userListOut2 outUser = extra.convert(user);
				result_GBO.add(outUser);
			});
			
			return Response.ok(g.toJson(result_GBO)).build();
		}
		if(role.equals("GS")) {
			LOG.warning("list GS");
			Query<Entity> query_GS = Query.newEntityQueryBuilder().setKind("User")
					.setFilter(CompositeFilter.and(PropertyFilter.eq("user_role", "USER"))).build();
			
			users = datastore.run(query_GS);
			
			List<userListOut2> result_GS = new ArrayList();
			
			users.forEachRemaining(user -> {
				LOG.warning(user.getString("user_name"));
				userListOut2 outUser = extra.convert(user);
				result_GS.add(outUser);
			});
			query_GS = Query.newEntityQueryBuilder().setKind("User")
					.setFilter(CompositeFilter.and(PropertyFilter.eq("user_role", "GBO"))).build();
			
			users = datastore.run(query_GS);
			
			users.forEachRemaining(user -> {
				LOG.warning(user.getString("user_name"));
				userListOut2 outUser = extra.convert(user);
				result_GS.add(outUser);
			});
			
			return Response.ok(g.toJson(result_GS)).build();}
			
		if(role.equals("SU")) {
			LOG.warning("list SU");
			Query<Entity> query_SU = Query.newEntityQueryBuilder().setKind("User")
					.setFilter(CompositeFilter.and(PropertyFilter.eq("user_role", "USER"))).build();
			
			users = datastore.run(query_SU);
			
			List<userListOut2> result_SU = new ArrayList();
			
			users.forEachRemaining(user -> {
				LOG.warning(user.getString("user_name"));
				userListOut2 outUser = extra.convert(user);
				result_SU.add(outUser);
			});
			
			query_SU = Query.newEntityQueryBuilder().setKind("User")
					.setFilter(CompositeFilter.and(PropertyFilter.eq("user_role", "GBO"))).build();
			
			users = datastore.run(query_SU);
			
			users.forEachRemaining(user -> {
				LOG.warning(user.getString("user_name"));
				userListOut2 outUser = extra.convert(user);
				result_SU.add(outUser);
			});
			
			query_SU = Query.newEntityQueryBuilder().setKind("User")
					.setFilter(CompositeFilter.and(PropertyFilter.eq("user_role", "GS"))).build();
			
			users = datastore.run(query_SU);
			
			users.forEachRemaining(user -> {
				LOG.warning(user.getString("user_name"));
				userListOut2 outUser = extra.convert(user);
				result_SU.add(outUser);
			});
			
			return Response.ok(g.toJson(result_SU)).build();
		}
		
		return Response.status(Status.BAD_REQUEST).build();
		

	}
	
	//error
	@PUT
	@Path("/uploadPhoto/{filename}")
	@Consumes(MediaType.APPLICATION_OCTET_STREAM)
	public Response uploadPhoto(@PathParam("filename") String filename,@Context HttpServletRequest req, @Context HttpHeaders headers) throws IOException {

		LOG.warning("uploadddddddddddddddddddddddddd" + req.getContentType());
		
		String token = headers.getHeaderString("token");

		AuthToken at = extra.AuthTokenDecode(token);
		
		String username = at.username;
		
		Storage storage = StorageOptions.getDefaultInstance().getService();
		BlobId blobId = BlobId.of("iconic-valve-379315.appspot.com", filename);
        BlobInfo blobInfo = BlobInfo.newBuilder(blobId)
        							.setAcl(Collections.singletonList(Acl.newBuilder(Acl.User.ofAllUsers(),Acl.Role.READER).build()))
        							.setContentType(req.getContentType())
        							.build();
        
        Transaction txn = datastore.newTransaction();

		try {
			Key userKey = datastore.newKeyFactory().setKind("User").newKey(username);
			Entity user = txn.get(userKey);
			if (user == null) {
				txn.rollback();
				LOG.warning("user does not exist " + username);
				return Response.status(Status.BAD_REQUEST).build();
			}

			user = Entity.newBuilder(user).set("user_photo", filename).build();

			txn.update(user);
			storage.create(blobInfo, req.getInputStream());
			txn.commit();
			return Response.ok().build();

		} finally {
			if (txn.isActive()) {
				txn.rollback();
				return Response.status(Status.INTERNAL_SERVER_ERROR).build();
			}
		}

	}
}
