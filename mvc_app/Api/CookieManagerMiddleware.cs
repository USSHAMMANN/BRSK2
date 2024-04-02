namespace mvc_app.Api
{
    public class CookieManagerMiddleware
    {
        private readonly RequestDelegate _next;

        public CookieManagerMiddleware(RequestDelegate next)
        {
            _next = next;
        }

        public async Task InvokeAsync(HttpContext context, IHttpContextAccessor httpContextAccessor)
        {
            Api.cookieManager = new CookieManager(httpContextAccessor);
            await _next(context);
        }
    }
}
