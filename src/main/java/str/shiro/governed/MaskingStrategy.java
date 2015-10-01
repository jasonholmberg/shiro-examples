/**
 * 
 */
package str.shiro.governed;

/**
 * @author Jason Holmberg
 *
 */
public class MaskingStrategy implements GoverningStrategy {

  @Override
  public String govern(Object input) {
    return "XXXXXXXXXXXXXXXXXX";
  }

}
