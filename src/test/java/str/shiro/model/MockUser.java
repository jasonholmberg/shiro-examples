/**
 * 
 */
package str.shiro.model;

import str.shiro.data.Users;
import str.shiro.enums.Status;
import str.shiro.governed.Governed;
import str.shiro.governed.GovernedObject;
import str.shiro.governed.Governors;

public class MockUser extends GovernedObject implements User {

  final int id;
  final String dob;
  final String firstname;
  final String lastname;
  final String username;
  final byte[] password;
  final Status status;
  
  public MockUser(Users user) {
    this.id = user.id;
    this.dob = user.dob;
    this.firstname = user.name();
    this.lastname = user.lastname;
    this.username = user.name();
    this.password = user.password.getBytes();
    this.status = user.status;
  }
  
  @Override
  public int getId() {
    return id;
  }
  
  @Override
  @Governed(Governors.mask)
  public String getDob() {
    // TODO Auto-generated method stub
    return (String) govern(dob);
  }
  
  @Override
  public String getFirstname() {
    return firstname;
  }

  @Override
  public String getLastname() {
    return lastname;
  }

  @Override
  public String getUsername() {
    return username;
  }

  @Override
  public byte[] getPassword() {
    return password;
  }

  @Override
  public Status getStatus() {
    return status;
  }
  
  @Override
  public String toString() {
    return username;
  }
}