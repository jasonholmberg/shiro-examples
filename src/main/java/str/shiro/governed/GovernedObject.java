/**
 * 
 */
package str.shiro.governed;

import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * @author Jason Holmberg
 *
 */
public abstract class GovernedObject {
  protected List<String> governed;
  public List<String> getGovernedMethods() {
    governed = new ArrayList<>();
    if (governed.isEmpty()) {
    System.out.println(this.getClass().getName());
    for(Method m : this.getClass().getMethods()) {
      if (m.isAnnotationPresent(Governed.class)) {
        System.out.println("Annotation on " + m.getName() + ": " + Arrays.toString(m.getAnnotations()));
        governed.add(m.getName());
      }
    }
    }
    return governed;
  }
  
  protected Object govern(Object o) {
    String currentMethod = Thread.currentThread().getStackTrace()[2].getMethodName();
    if (getGovernedMethods().contains(currentMethod)) {
      Method m = null;
      try {
        m = this.getClass().getMethod(currentMethod, new Class[] {});
      } catch (NoSuchMethodException | SecurityException e) {
        e.printStackTrace();
      }
      GoverningStrategy strategy = m.getAnnotation(Governed.class).value().strategy;
      return strategy.govern(o);
    }
    return o;
  }
}
