using Microsoft.Owin.Security;
using Microsoft.Owin.Security.OpenIdConnect;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.UI;
using System.Web.UI.WebControls;

namespace DemoWebform
{
    public partial class _Default : Page
    {
        protected void Page_Load(object sender, EventArgs e)
        {

        }
        protected void btnLaunch_Click(object sender, EventArgs e)
        {
            if (Request.IsAuthenticated)
            {
                Response.Redirect("https://www.mailboxintegration.com:443/Mail"); 
            }
        }
    }
}