using MailboxIntegration.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using System.Security.Claims;
using Microsoft.Owin.Security.Cookies;
using MailboxIntegration.TokenStorage;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.OpenIdConnect;
using Microsoft.Identity.Client;
using System.Configuration;
using Microsoft.Graph.Auth;
using Microsoft.Graph;
using System.Net.Http.Headers;
using Newtonsoft.Json;
using MailboxIntegration.Helpers;

namespace MailboxIntegration.Controllers
{
    
    public class BaseController : Controller
    {
        protected void Flash(string message, string debug = null)
        {
            var alerts = TempData.ContainsKey(ErrorLog.ErrorKey) ?
                (List<ErrorLog>)TempData[ErrorLog.ErrorKey] :
                new List<ErrorLog>();

            alerts.Add(new ErrorLog
            {
                Message = message,
                Debug = debug
            });

            TempData[ErrorLog.ErrorKey] = alerts;
        }


        protected async  override void OnActionExecuting(ActionExecutingContext filterContext)
        {
            //HttpCookie myCookie = Request.Cookies["myCookie"];
            //var graphClient = new GraphServiceClient(
            //   new DelegateAuthenticationProvider(
            //       async (requestMessage) =>
            //       {
            //           requestMessage.Headers.Authorization =
            //               new AuthenticationHeaderValue("Bearer", myCookie.Value);
            //       }));
            //var events = await graphClient.Me.MailFolders.Inbox.Messages.Request().Expand("attachments").GetAsync(); //Select("webLink,subject,hasAttachments,BodyPreview")
            //var userDetails = await graphClient.Me.Request().GetAsync();
            //var cachedUser = new CachedUser()
            //{
            //    DisplayName = userDetails.DisplayName,
            //    Email = (string.IsNullOrEmpty(userDetails.Mail) ? userDetails.UserPrincipalName : userDetails.Mail),
            //    Avatar = string.Empty
            //};
            //var tokenStore1 = new SessionStore(null,
            //       System.Web.HttpContext.Current, ClaimsPrincipal.Current);
            // tokenStore1.SaveUserDetails(cachedUser);
            // var graphClient = GraphHelper.GetAuthenticatedClient(myCookie.Value);
            //  var user1 = JsonConvert.SerializeObject(cachedUser);

            if (Request.Cookies["myCookie"] != null)
            {
                // Get the user's token cache
                //var tokenStore = new SessionStore(null,
                //    System.Web.HttpContext.Current, ClaimsPrincipal.Current);
                    // Add the user to the view bag
                   // ViewBag.User = tokenStore.GetUserDetails();
                    RedirectToAction("MailInboxSearch", "Mail", new { sharedMailId = "" });
               
                    // The session has lost data. This happens often
                    // when debugging. Log out so the user can log back in
                    //Request.GetOwinContext().Authentication.SignOut(CookieAuthenticationDefaults.AuthenticationType);
                    //Response.Redirect("https://www.mailboxintegration.com:443/Mail");
                    //filterContext.Result = RedirectToAction("MailInboxSearch", "Mail", new { sharedMailId = "" });
              //  }
            }
            else
            {
                //ViewBag.User = JsonConvert.DeserializeObject<CachedUser>((string)user1);
                Response.Redirect("https://www.mailboxintegration.com:1081/Default");
                // Signal OWIN to send an authorization request to Azure
                //Request.GetOwinContext().Authentication.Challenge(
                //    new AuthenticationProperties { RedirectUri = "/" },
                //    OpenIdConnectAuthenticationDefaults.AuthenticationType);
            }
            base.OnActionExecuting(filterContext);
        }


    }

}