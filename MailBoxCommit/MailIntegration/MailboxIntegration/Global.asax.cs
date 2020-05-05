using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using System.Web.Optimization;
using System.Web.Routing;

namespace MailboxIntegration
{
    public class MvcApplication : System.Web.HttpApplication
    {
        protected void Application_Start()
        {
            AreaRegistration.RegisterAllAreas();
            FilterConfig.RegisterGlobalFilters(GlobalFilters.Filters);
            RouteConfig.RegisterRoutes(RouteTable.Routes);
            BundleConfig.RegisterBundles(BundleTable.Bundles);
        }
        //void Application_BeginRequest()
        //{
        //    if (Request.Cookies.Count > 0)
        //    {
        //        foreach (string s in Request.Cookies.AllKeys)
        //        {
        //            //if (s.ToLower().Contains("__requestverificationtoken"))

        //            Request.Cookies[s].Domain = ".MailBoxIntegration.com;";
        //            Request.Cookies[s].Path += ";SameSite=Strict";
        //            Request.Cookies[s].Secure = true;
        //        }
        //    }
        //}
    }
}
