/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

package pt.webdetails.cpf.session;

import org.pentaho.platform.api.engine.IAuthorizationPolicy;
import org.pentaho.platform.api.engine.IPentahoSession;
import org.pentaho.platform.engine.core.system.PentahoSessionHolder;
import org.pentaho.platform.engine.core.system.PentahoSystem;
import org.pentaho.platform.engine.security.SecurityHelper;
import org.pentaho.platform.web.http.api.resources.utils.SystemUtils;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

public class PentahoSession implements IUserSession {
  private IPentahoSession pentahoSession;
  private boolean isCurrentSession;
  private IAuthorizationPolicy policy;

  public PentahoSession(){
    this( null, null );
  }

  public PentahoSession( IPentahoSession pentahoSession ){
    this( pentahoSession, null );
  }

  public PentahoSession( IAuthorizationPolicy policy ){
    this( null, policy );
  }

  public PentahoSession( IPentahoSession pentahoSession, IAuthorizationPolicy policy ){

    isCurrentSession =  pentahoSession == null || ( PentahoSessionHolder.getSession() == pentahoSession );
    this.pentahoSession = isCurrentSession ? PentahoSessionHolder.getSession() : pentahoSession;
    this.policy = ( policy == null ? PentahoSystem.get( IAuthorizationPolicy.class ) : policy );
  }

  @Override
  public String getUserName() {
    return ( getPentahoSession() != null ? getPentahoSession().getName() : null );
  }

  @Override
  public boolean isAdministrator() {
    return SystemUtils.canAdminister( ( isCurrentSession ? null : getPentahoSession() ) , getPolicy() );
  }

  @Override
  public boolean isAuthenticated() {
    return getPentahoSession() != null && getPentahoSession().isAuthenticated();
  }

  public IPentahoSession getPentahoSession(){
    return pentahoSession;
  }

  @Override
  public String[] getAuthorities() {
    Authentication auth = SecurityHelper.getInstance().getAuthentication( getPentahoSession(), true );
    GrantedAuthority[] authorities = auth.getAuthorities().toArray( new GrantedAuthority[] {} );
    String[] result = new String[authorities.length];
    int i=0;

    for (GrantedAuthority authority : authorities) {
      result[i++] = authority.getAuthority();
    }
    return result;
  }

  @Override
  public Object getParameter(String name) {
    if (name != null && getPentahoSession() != null ) {
      return getPentahoSession().getAttribute( name.toString() );
    }
    return null;
  }

  @Override
  public String getStringParameter(String name) {
    Object r = getParameter( name );
    if (r != null) {
      return r.toString();
    }
    return null;
  }

  @Override
  public void setParameter(String key, Object value) {
    getPentahoSession().setAttribute(key.toString(), value);
  }

  public IAuthorizationPolicy getPolicy() {
    return policy;
  }
}
