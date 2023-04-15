package pt.unl.fct.di.apdc.firstwebapp.util;



public class SignInData {
	
	public String username;
	public String password;
	public String passwordConfirm;
	public String email;
	public String name;
	
	public SignInData() {
		
	}
	
	public boolean validRegistation() {
		return true;
	}

}
