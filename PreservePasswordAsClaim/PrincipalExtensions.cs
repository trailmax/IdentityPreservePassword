using System;
using System.Security.Claims;
using System.Security.Principal;

namespace PreservePasswordAsClaim
{
    public static class PrincipalExtensions
    {
        public static String GetStoredPassword(this IPrincipal principal)
        {
            var claimsPrincipal = principal as ClaimsPrincipal;
            if (claimsPrincipal == null)
            {
                throw new Exception("Expecting ClaimsPrincipal");
            }

            var passwordClaim = claimsPrincipal.FindFirst("MyApplication:Password");

            if (passwordClaim == null)
            {
                throw new Exception("Password is not stored");
            }

            var password = passwordClaim.Value;

            return password;
        }
    }
}