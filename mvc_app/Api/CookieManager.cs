using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.Net;

namespace mvc_app.Api
{
    public class CookieManager
    {
        private readonly IHttpContextAccessor httpContextAccessor;
        public CookieManager(IHttpContextAccessor httpContextAccessor) 
        {
            this.httpContextAccessor = httpContextAccessor;
        }
        public ActionResult<string> GetCookie(string name)
        {
            string data = httpContextAccessor.HttpContext.Request.Cookies[name];
            if (data.IsNullOrEmpty())
            {
                return "";
            }
            return data;
        }
        public ActionResult<string> AddCookie(string name, string data)
        {
            httpContextAccessor.HttpContext.Response.Cookies.Append(name, data, new CookieOptions
            {
                HttpOnly = true,
                SameSite = SameSiteMode.Strict
            });
            return new ObjectResult(name) { StatusCode = StatusCodes.Status201Created };
        }

        public ActionResult<string> RemoveCookie(string name)
        {
            httpContextAccessor.HttpContext.Response.Cookies.Delete(name);
            return new ObjectResult(name) { StatusCode = StatusCodes.Status200OK }; ;
        }
    }
}
