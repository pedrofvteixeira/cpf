/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

package pt.webdetails.cpf;

import org.pentaho.platform.engine.core.system.PentahoSessionHolder;
import org.pentaho.platform.engine.security.SecurityHelper;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.GrantedAuthorityImpl;
import pt.webdetails.cpf.session.PentahoSession;


public final class SecurityAssertions {

  public static void assertIsAdmin(){
    if(! new PentahoSession().isAdministrator() ){
      throw new RuntimeException("Administrator privileges required.");
    }
  }
  
  public static void assertHasRole(String role){
    if(! SecurityHelper.getInstance().isGranted( new GrantedAuthorityImpl(role) ) ){
      throw new RuntimeException(role + " privileges required.");
    }
  }
  
}
