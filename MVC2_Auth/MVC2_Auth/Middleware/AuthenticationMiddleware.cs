namespace MVC2_Auth.Middleware
{
    public class AuthenticationMiddleware
    {
        private readonly RequestDelegate _next;

        public AuthenticationMiddleware(RequestDelegate next)
        {
            _next = next;
        }

        public async Task Invoke(HttpContext httpContext)
        {
            if (httpContext.Request.Path.StartsWithSegments("/Authentication/Register") ||
                httpContext.Request.Path.StartsWithSegments("/Authentication/RegisterAdmin")||
                httpContext.Request.Path.StartsWithSegments("/Authentication/User/Login") ||
                httpContext.Request.Path.StartsWithSegments("/Authentication/Admin/Login"))
            {
                // Skip token validation for the Register API
                await _next(httpContext);
                return;
            }

            // Check if the user is authenticated
            if (!httpContext.User.Identity.IsAuthenticated)
            {
                // The user is not authenticated, redirect to the login page
                httpContext.Response.Redirect("/Authentication/Login");
                return;
            }

            // The user is authenticated, continue with the request
            await _next(httpContext);
        }
    }

    public static class AuthenticationMiddlewareExtensions
    {
        public static IApplicationBuilder UseAuthenticationMiddleware(this IApplicationBuilder builder)
        {
            return builder.UseMiddleware<AuthenticationMiddleware>();
        }
    }
}
