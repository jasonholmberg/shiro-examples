/**
 * 
 */
package str.shiro.tutorial;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.IncorrectCredentialsException;
import org.apache.shiro.authc.LockedAccountException;
import org.apache.shiro.authc.UnknownAccountException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.config.IniSecurityManagerFactory;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.session.Session;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.Factory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author Jason Holmberg
 *
 */
public class Tutorial {

  private static final transient Logger log = LoggerFactory.getLogger(Tutorial.class);

  /**
   * @param args
   */
  public static void main(String[] args) {
    log.info("My First Apache Shiro Application");
    
    log.info(">>>Creating SecurityManager...");
    
    Factory<SecurityManager> factory = new IniSecurityManagerFactory("classpath:shiro.ini");
    SecurityManager securityManager = factory.getInstance();
    SecurityUtils.setSecurityManager(securityManager);

    log.info(">>>Get anonymous subject...");
    Subject currentUser = SecurityUtils.getSubject();
    log.info(">>>Pre auth: {}",currentUser.getPrincipal());
    
    log.info(">>>Place something in session [id: {}]",currentUser.getSession().getId());
    Session session = currentUser.getSession();
    session.setAttribute("someKey", "aValue");
    String value = (String) session.getAttribute("someKey");
    if (value.equals("aValue")) {
      log.info("Retrieved value from session: [ " + value + " ]");
    }

    if (!currentUser.isAuthenticated()) {
      final String user = "root", password = "secret";
      log.info("Not authenticated. Logging user: [{}] in.", user);
      // collect user principals and credentials in a gui specific manner
      // such as username/password html form, X509 certificate, OpenID, etc.
      // We'll use the username/password example here since it is the most
      // common.
      log.info(">>>Create token...");
      UsernamePasswordToken token = new UsernamePasswordToken(user, password);

      // this is all you have to do to support 'remember me' (no config - built
      // in!):
      log.info(">>>Remember me...");
      token.setRememberMe(true);

      try {
        log.info(">>>Login...");
        currentUser.login(token);
        // if no exception, that's it, we're done!
      } catch (UnknownAccountException uae) {
        uae.printStackTrace();
      } catch (IncorrectCredentialsException ice) {
        ice.printStackTrace();
      } catch (LockedAccountException lae) {
        // account for that username is locked - can't login. Show them a
        // message?
        lae.printStackTrace();
      } catch (AuthenticationException ae) {
        // unexpected condition - error?
        ae.printStackTrace();
      }
    }

    // print their identifying principal (in this case, a username):
    log.info("User [" + currentUser.getPrincipal() + "] logged in successfully.");

    if (currentUser.hasRole("schwartz")) {
      log.info("May the Schwartz be with you!");
    } else {
      log.info("Hello, mere mortal.");
    }
    
    if (currentUser.hasRole("admin")) {
      log.info("You are da admin.");
    } else {
      log.info("You're not that important..non-admin");
    }
    

    if (currentUser.isPermitted("lightsaber:weild")) {
      log.info("You may use a lightsaber ring.  Use it wisely.");
    } else {
      log.info("Sorry, lightsaber rings are for schwartz masters only.");
    }

    if (currentUser.isPermitted("winnebago:drive:eagle5")) {
      log.info("You are permitted to 'drive' the 'winnebago' with license plate (id) 'eagle5'.  " + "Here are the keys - have fun!");
    } else {
      log.info("Sorry, you aren't allowed to drive the 'eagle5' winnebago!");
    }
    

    currentUser.logout();
    
    System.exit(0);
  }

}
