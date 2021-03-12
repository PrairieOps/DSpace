/**
 * The contents of this file are subject to the license and copyright
 * detailed in the LICENSE and NOTICE files at the root of the source
 * tree and available online at
 *
 * http://www.dspace.org/license/
 */
package org.dspace.authenticate;

import java.io.IOException;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.log4j.Logger;
import org.apache.commons.collections.ListUtils;
import org.dspace.authenticate.factory.AuthenticateServiceFactory;
import org.dspace.authenticate.service.AuthenticationService;
import org.dspace.core.ConfigurationManager;
import org.dspace.core.Context;
import org.dspace.core.LogManager;
import org.dspace.eperson.EPerson;
import org.dspace.eperson.Group;
import org.dspace.eperson.factory.EPersonServiceFactory;
import org.dspace.eperson.service.EPersonService;

// we use the Java CAS client
import org.jasig.cas.client.authentication.AttributePrincipal;
import org.jasig.cas.client.validation.Assertion;
import org.jasig.cas.client.validation.Cas30ServiceTicketValidator;
import org.jasig.cas.client.validation.TicketValidationException;

/**
 * Authenticator for Central Authentication Service (CAS).
 *
 * @author Naveed Hashmi, University of Bristol
 * based on code developed by Nordija A/S (www.nordija.com) for Center of Knowledge Technology (www.cvt.dk)
 * @version $Revision: 1.0 $
 * @author Nicolás Kovac Neumann, Universidad de La Laguna
 * CAS authentication has been adapted to DSpace 3.1 (latest stable) and proved functionality with CAS 3.5.0
 * @version $Revision: 1.1 $
 * @author Tomasz Baria Boiński, Gdańsk University of Technology
 * CAS authentication has been adapted to DSpace 4.2 and integrated with SAML user query
 * @version $Revision 1.2 $
 */

public class CASAuthentication
    implements AuthenticationMethod {

    /** log4j category */
    private static Logger log = Logger.getLogger(CASAuthentication.class);

    private static final AuthenticationService authenticationService = AuthenticateServiceFactory.getInstance().getAuthenticationService();
    private static final EPersonService ePersonService = EPersonServiceFactory.getInstance().getEPersonService();

    // user details for self registration
    private String firstName = null;
    private String lastName = null;
    private String email = null;

    /**
     * Predicate, can new user automatically create EPerson.
     * Checks configuration value.  You'll probably want this to
     * be true to take advantage of a Web certificate infrastructure
     * with many more users than are already known by DSpace.
     */
    @Override
    public boolean canSelfRegister(Context context,
                                   HttpServletRequest request,
                                   String username)
        throws SQLException
    {
        return ConfigurationManager.getBooleanProperty("webui.cas.autoregister");
    }

    /**
     *  Nothing extra to initialize.
     */
    @Override
    public void initEPerson(Context context, HttpServletRequest request,
            EPerson eperson)
        throws SQLException
    {
    }

    /**
     * We don't use EPerson password so there is no reason to change it.
     */
    @Override
    public boolean allowSetPassword(Context context,
                                    HttpServletRequest request,
                                    String username)
        throws SQLException
    {
        return false;
    }

    /**
     * 
     * Predicate, is this an implicit authentication method.
     * An implicit method gets credentials from the environment (such as
     * an HTTP request or even Java system properties) rather than the
     * explicit username and password.  For example, a method that reads
     * the X.509 certificates in an HTTPS request is implicit.
     * @return true if this method uses implicit authentication.
     * 
     * Returns true, CAS is an implicit method
     */
    @Override
    public boolean isImplicit()
    {
        return true;
    }

    /**
     * No special groups.
     */
    @Override
    public List<Group> getSpecialGroups(Context context, HttpServletRequest request)
    {
        return ListUtils.EMPTY_LIST;
    }


    /**
     * CAS authentication.
     *
     * @return One of: SUCCESS, BAD_CREDENTIALS, NO_SUCH_USER, BAD_ARGS
     */
    @Override
    public int authenticate(Context context,
                            String netid,
                            String password,
                            String realm,
                            HttpServletRequest request)
        throws SQLException
    {
        final String ticket = request.getParameter("ticket").toString();
        final String service = request.getRequestURL().toString();

        if (ticket != null && service != null)
        {
            try
            {
                // Validate ticket (it is assumed that CAS validator returns the user network ID)
                final String casUrlPrefix = ConfigurationManager.getProperty("cas.url.prefix");
                Cas30ServiceTicketValidator stv = new Cas30ServiceTicketValidator(casUrlPrefix);
                Assertion assertion = stv.validate(ticket, service);
                AttributePrincipal principal = assertion.getPrincipal();
                netid = principal.getName();

                // Locate the eperson in DSpace
                EPerson eperson = null;
                try
                {
                    eperson = ePersonService.findByNetid(context, netid.toLowerCase());
                }
                catch (SQLException e)
                {
                  log.error("cas findbynetid failed");
                  StackTraceElement[] stackTrace = e.getStackTrace();
                  StringBuilder stack = new StringBuilder();
                  int numLines = Math.min(stackTrace.length, 12);
                  for (int j = 0; j < numLines; j++) {
                      stack.append("\t" + stackTrace[j].toString() + "\n");
                  }
                  if (stackTrace.length > numLines) {
                      stack.append("\t. . .\n");
                  }

                  log.error(e.toString() + " -> \n" + stack.toString());
                }

                // if they entered a netd that matches an eperson and they are allowed to login
                if (eperson != null)
                {
                  // e-mail address corresponds to active account
                    if (eperson.getRequireCertificate())
                    {
                        // they must use a certificate
                        return CERT_REQUIRED;
                    }
                    else if (!eperson.canLogIn()) {
                        return BAD_ARGS;
                    }

                    // Logged in OK.
                    HttpSession session = request.getSession(false);
                    if (session!=null) {
                      session.setAttribute("loginType", "CAS");
                    }

                    context.setCurrentUser(eperson);
                    log.info(LogManager.getHeader(context, "authenticate", "type=CAS"));

                    return SUCCESS;
                }
                // the user does not exist in DSpace so create an eperson
                else
                {
                  if (canSelfRegister(context, request, netid) )
                    {
                        // TEMPORARILY turn off authorisation
                        context.turnOffAuthorisationSystem();

                        eperson = ePersonService.create(context);

                        // use netid only but this implies that user has to manually update their profile
                        eperson.setNetid(netid);

                        // if you wish to automatically extract further user details: email, first_name and last_name
                        eperson.setFirstName(context, firstName);
                        eperson.setLastName(context, lastName);

                        if (email == null) {
                            email = netid;
                        }

                        String lang = ConfigurationManager.getProperty("default.locale");
                        eperson.setLanguage(context, lang);
                        eperson.setEmail(email);
                        eperson.setRequireCertificate(false);
                        eperson.setSelfRegistered(false);

                        eperson.setCanLogIn(true);
                        authenticationService.initEPerson(context, request, eperson);
                        ePersonService.update(context, eperson);
                        context.commit();
                        context.dispatchEvents();
                        context.restoreAuthSystemState();
                        context.setCurrentUser(eperson);
                        log.warn(LogManager.getHeader(context, "authenticate",
                            netid + "  type=CAS auto-register"));
                        return SUCCESS;
                    }
                    else
                    {
                        // No auto-registration for valid netid
                        log.warn(LogManager.getHeader(context, "authenticate",
                            netid + "  type=netid_but_no_record, cannot auto-register"));
                        return NO_SUCH_USER;
                    }
                }
            }
            catch (Exception e)
            {
                StackTraceElement[] stackTrace = e.getStackTrace();
                StringBuilder stack = new StringBuilder();
                int numLines = Math.min(stackTrace.length, 12);
                for (int j = 0; j < numLines; j++) {
                    stack.append("\t" + stackTrace[j].toString() + "\n");
                }
                if (stackTrace.length > numLines) {
                    stack.append("\t. . .\n");
                }

                log.error(e.toString() + " -> \n" + stack.toString());
            }
        }
        return BAD_ARGS;
    }

    /*
     * Returns URL to which to redirect to obtain credentials (either password
     * prompt or e.g. HTTPS port for client cert.); null means no redirect.
     *
     * @param context
     *  DSpace context, will be modified (ePerson set) upon success.
     *
     * @param request
     *  The HTTP request that started this operation, or null if not applicable.
     *
     * @param response
     *  The HTTP response from the servlet method.
     *
     * @return fully-qualified URL
     */
    public String loginPageURL(Context context,
                            HttpServletRequest request,
                            HttpServletResponse response)
    {
       // Determine CAS server URL
       final String casUrlPrefix = ConfigurationManager.getProperty("cas.url.prefix");
       StringBuffer url=new StringBuffer(casUrlPrefix);
       // Add the login path
       url.append("/login");
       // Add the URL callback
       url.append("?service=").append(request.getScheme()).
       append("://").append(request.getServerName());
       if (request.getServerPort()!=80 || request.getServerPort()!=443)
         url.append(":").append(request.getServerPort());
       url.append(request.getContextPath()).append("/cas-login");
       log.info("CAS server and service:  " + casUrlPrefix);

       // Redirect to CAS server
       return response.encodeRedirectURL(url.toString());
    }

    /*
     * Returns message key for title of the "login" page, to use
     * in a menu showing the choice of multiple login methods.
     *
     * @param context
     *  DSpace context, will be modified (ePerson set) upon success.
     *
     * @return Message key to look up in i18n message catalog.
     */
    public String loginPageTitle(Context context)
    {
        //return null;
        return "org.dspace.eperson.CASAuthentication.title";
    }

}

