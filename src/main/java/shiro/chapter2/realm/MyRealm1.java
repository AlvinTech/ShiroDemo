package shiro.chapter2.realm;

import org.apache.shiro.authc.*;
import org.apache.shiro.realm.Realm;

/**
 * Created by pengli on 5/6/2015.
 */
public class MyRealm1 implements Realm{

    public String getName() {
        return "myRealm1";
    }

    public boolean supports(AuthenticationToken authenticationToken) {
        return authenticationToken instanceof UsernamePasswordToken;
    }

    public AuthenticationInfo getAuthenticationInfo(AuthenticationToken authenticationToken) throws AuthenticationException {
        // get the username for the toke user the function getPrincipal;
        String username = (String)authenticationToken.getPrincipal();
        // use the getCredentias() api to get the password.
        String password = new String((char[])authenticationToken.getCredentials());
        if(!"zhang".equals(username)){
            throw new UnknownAccountException(); // username is invalidity
        }
        if(!"123".equals(password)){
            throw  new IncorrectCredentialsException();// password is not correct;
        }
        // is through the authentication  ,should return a AuthenticationInfo .
        return new SimpleAuthenticationInfo(username,password,getName());
    }
}


