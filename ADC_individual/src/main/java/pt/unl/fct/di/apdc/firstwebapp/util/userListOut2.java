package pt.unl.fct.di.apdc.firstwebapp.util;

public class userListOut2 {

	public String username;
	public String email;
	public String name;
	public String role;
	public long state;
	public String profile;
	public String cell;
	public String cellHome;
	public String occupation;
	public String workplace;
	public String adress;
	public String nif;

	public userListOut2(String username, String email, String name, String role, long state, String cell,
			String cellHome, String occupation, String workplace, String adress, String nif, String profile) {
		this.email = email;
		this.name = name;
		this.username = username;
		this.role = role;
		this.state = state;
		this.cell = cell;
		this.cellHome = cellHome;
		this.occupation = occupation;
		this.workplace = workplace;
		this.adress = adress;
		this.nif = nif;
		this.profile = profile;
		
	}

}
