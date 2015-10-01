/**
 * 
 */
package str.shiro.governed;

/**
 * @author Jason Holmberg
 *
 */
public enum Governors {
  mask(new MaskingStrategy());
  GoverningStrategy strategy;
  Governors(GoverningStrategy strategy) {
    this.strategy = strategy;
  }
}
