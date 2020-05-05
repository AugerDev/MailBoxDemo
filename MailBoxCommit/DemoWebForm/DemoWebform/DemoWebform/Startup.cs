using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.Notifications;
using Microsoft.Owin.Security.OpenIdConnect;
using Owin;
using Microsoft.Identity.Client;
using System.Configuration;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web;
using DemoWebform.TokenStorage;
using Microsoft.Owin;
using Microsoft.Graph;
using System.Net.Http.Headers;
using Microsoft.AspNetCore.DataProtection;
using System.IO;
using Microsoft.Owin.Security.Interop;
using System;
using System.Web.Helpers;
using IdentityModel.Client;

[assembly: OwinStartup(typeof(DemoWebform.Startup))]

namespace DemoWebform
{
    public partial class Startup
    {
        private static string appId = ConfigurationManager.AppSettings["ida:AppId"];
        private static string appSecret = ConfigurationManager.AppSettings["ida:AppSecret"];
        private static string redirectUri = ConfigurationManager.AppSettings["ida:RedirectUri"];
        private static string graphScopes = ConfigurationManager.AppSettings["ida:AppScopes"];

        public void Configuration(IAppBuilder app)
        {
            ConfigureAuth(app);
        }
        public void ConfigureAuth(IAppBuilder app)
        {
            app.SetDefaultSignInAsAuthenticationType(CookieAuthenticationDefaults.AuthenticationType);
            //string keyRingPath = @"F:\ShareCookiePath\";
            //string baseDirectory = AppDomain.CurrentDomain.BaseDirectory;
            //string keyRingPath = Path.GetFullPath(Path.Combine(baseDirectory, "..", "ShareCookiePath"));
            //DirectoryInfo path = new DirectoryInfo(keyRingPath);
            //var protectionProvider = DataProtectionProvider.Create(path);
            //var dataProtector = protectionProvider.CreateProtector(
            //        "CookieAuthenticationMiddleware",
            //        "Cookie",
            //        "v2");
            //var ticketFormat = new AspNetTicketDataFormat(new DataProtectorShim(dataProtector));
            app.UseCookieAuthentication(new CookieAuthenticationOptions());
            //AuthenticationType = "AppCookieName",
            //SlidingExpiration = true,
            //ExpireTimeSpan = TimeSpan.FromHours(1)

            /* Account Controller SignIn() */

            //app.UseCookieAuthentication(new CookieAuthenticationOptions
            //{
            //    CookieDomain = "MailBoxIntegration.com"
            //});
            //  AntiForgeryConfig.UniqueClaimTypeIdentifier = ClaimTypes.NameIdentifier;

            app.UseOpenIdConnectAuthentication(
                new OpenIdConnectAuthenticationOptions
                {
                    ClientId = appId,
                    Authority = "https://login.microsoftonline.com/common/v2.0",
                    Scope = $"openid email profile offline_access {graphScopes}",
                    RedirectUri = redirectUri,
                    PostLogoutRedirectUri = redirectUri,
                    TokenValidationParameters = new TokenValidationParameters
                    {
                        // For demo purposes only, see below
                        ValidateIssuer = false
                    },
                    SignInAsAuthenticationType = "Cookies",
                    SaveTokens = true,
                    Notifications = new OpenIdConnectAuthenticationNotifications
                    {
                        AuthenticationFailed = OnAuthenticationFailedAsync,
                        AuthorizationCodeReceived = OnAuthorizationCodeReceivedAsync
                    }
                }
            );
        }

        private static Task OnAuthenticationFailedAsync(AuthenticationFailedNotification<OpenIdConnectMessage,
          OpenIdConnectAuthenticationOptions> notification)
        {
            notification.HandleResponse();
            string redirect = $"/Home/Error?message={notification.Exception.Message}";
            if (notification.ProtocolMessage != null && !string.IsNullOrEmpty(notification.ProtocolMessage.ErrorDescription))
            {
                redirect += $"&debug={notification.ProtocolMessage.ErrorDescription}";
            }
            notification.Response.Redirect(redirect);
            return Task.FromResult(0);
        }

        private async Task OnAuthorizationCodeReceivedAsync(AuthorizationCodeReceivedNotification notification)
        {
            var idClient = ConfidentialClientApplicationBuilder.Create(appId)
                .WithRedirectUri(redirectUri)
                .WithClientSecret(appSecret)
                .Build();

            string message;
            var signedInUser = new ClaimsPrincipal(notification.AuthenticationTicket.Identity);
            var tokenStore = new SessionStore(idClient.UserTokenCache, HttpContext.Current, signedInUser);
            try
            {
                string[] scopes = graphScopes.Split(' ');

                var result = await idClient.AcquireTokenByAuthorizationCode(
                    scopes, notification.Code).ExecuteAsync();

                var graphClient = new GraphServiceClient(
               new DelegateAuthenticationProvider(
                   async (requestMessage) =>
                   {
                       requestMessage.Headers.Authorization =
                           new AuthenticationHeaderValue("Bearer", result.AccessToken);
                   }));
                HttpCookie myCookie = new HttpCookie("myCookie");
                myCookie.Domain = ".MailBoxIntegration.com";
                //Add key-values in the cookie
                //myCookie.Values.Add("userid", result.AccessToken);
                myCookie.Value = result.AccessToken;
                //set cookie expiry date-time. Made it to last for next 12 hours.
                myCookie.Expires = DateTime.Now.AddHours(12);

                //Most important, write the cookie to client.
                HttpContext.Current.Response.Cookies.Add(myCookie);

                //HttpCookie chk = new HttpCookie("chk");
                //chk.Domain = ".MailBoxIntegration.com";
                //chk.Name = "Token";
                //chk.Value = result.AccessToken;
                var userDetails = await graphClient.Me.Request().GetAsync();

                //var userDetails = await GraphHelper.GetUserDetailsAsync(result.AccessToken);

                var cachedUser = new CachedUser()
                {
                    DisplayName = userDetails.DisplayName,
                    Email = (string.IsNullOrEmpty(userDetails.Mail) ? userDetails.UserPrincipalName : userDetails.Mail),
                    Avatar = string.Empty
                };

                tokenStore.SaveUserDetails(cachedUser);
            }
            catch (MsalException ex)
            {
                message = "AcquireTokenByAuthorizationCodeAsync threw an exception";
                notification.HandleResponse();
                notification.Response.Redirect($"/Home/Error?message={message}&debug={ex.Message}");
            }
            catch (Microsoft.Graph.ServiceException ex)
            {
                message = "GetUserDetailsAsync threw an exception";
                notification.HandleResponse();
                notification.Response.Redirect($"/Home/Error?message={message}&debug={ex.Message}");
            }
        }
    }
}