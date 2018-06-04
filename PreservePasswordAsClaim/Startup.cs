using Microsoft.Owin;
using Owin;

[assembly: OwinStartupAttribute(typeof(PreservePasswordAsClaim.Startup))]
namespace PreservePasswordAsClaim
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            ConfigureAuth(app);
        }
    }
}
