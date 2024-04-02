using Microsoft.AspNetCore.Http;
using Microsoft.IdentityModel.Tokens;
using System.Net;

namespace mvc_app.Api
{
    public class TokenRefreshHandler : DelegatingHandler
    {
        static Api api;
        public TokenRefreshHandler(HttpMessageHandler innerHandler)
        : base(innerHandler)
        {

        }
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var response = await base.SendAsync(request, cancellationToken);

            if (response.StatusCode == HttpStatusCode.Unauthorized)
            {
                var refreshToken = "";
                try
                {
                    if (Api.cookieManager != null)
                    {
                        refreshToken = Api.cookieManager.GetCookie("refreshToken").Value;
                    }
                }
                catch (Exception)
                {

                    
                }
             
                // Обновить токен
                TokenResponse tokens = await Api.RefreshAccessToken(refreshToken);

                if (!string.IsNullOrEmpty(tokens.AccessToken))
                {
                    Api.SetTokenForClientAsync(tokens.AccessToken);

                    // Отправка запроса с новым токеном
                    response = await base.SendAsync(request, cancellationToken);
                    Console.WriteLine("Токен обновлен");
                }
            }

            return response;
        }
    }
}
