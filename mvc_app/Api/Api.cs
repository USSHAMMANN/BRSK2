using mvc_app.Models;
using Newtonsoft.Json;
using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Xml.Linq;

namespace mvc_app.Api
{
    public class Api
    {
        internal static CookieManager cookieManager;
        public HttpStatusCode current_status;
        internal static HttpClient client = new HttpClient(new TokenRefreshHandler(new HttpClientHandler()))
        {
            BaseAddress = new Uri("https://localhost:8080/api/")
        };

        public Api(IHttpContextAccessor httpContextAccessor)
        {
            current_status = new HttpStatusCode();
            cookieManager = new CookieManager(httpContextAccessor);
        }
        public async Task<bool> UserRegistrationAsync(string login, string password, string email, string username)
        {
            UserRegistration registrationModel = new UserRegistration()
            {
                UserEmail = email,
                UserLogin = login,
                UserPassword = password,
                UserName = username,
            };

            var json = JsonConvert.SerializeObject(registrationModel);
            var data = new StringContent(json, Encoding.UTF8, "application/json");

            var response = await client.PostAsync("Registration", data);
            current_status = response.StatusCode;



            if (response.StatusCode == System.Net.HttpStatusCode.Created)
            {
                return true;
            }
            else
            {
                return false;
            }
        }

        public async Task<TokenResponse> UserLoginAsync(string login, string password)
        {
            TokenResponse tokenResponse = new TokenResponse();
            UserLogin loginModel = new UserLogin()
            {
                Login = login,
                Password = password,
            };

            var json = JsonConvert.SerializeObject(loginModel);
            var data = new StringContent(json, Encoding.UTF8, "application/json");

            var response = await client.PostAsync("Login", data);
            current_status = response.StatusCode;

            if (response.StatusCode != HttpStatusCode.OK)
            {
                return tokenResponse;
            }
            else
            {

                tokenResponse = JsonConvert.DeserializeObject<TokenResponse>(response.Content.ReadAsStringAsync().Result);
                cookieManager.AddCookie("refreshToken", tokenResponse.RefreshToken);

                return tokenResponse;
            }
        }
        public static async Task SetTokenForClientAsync(string token)
        {
            if (token == null || token == "")
            {
                return;
            }
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
            var response = await client.GetAsync("Users/GetCurrentUserInfo");

            if (response.StatusCode == System.Net.HttpStatusCode.OK)
            {
                User user = JsonConvert.DeserializeObject<User>(response.Content.ReadAsStringAsync().Result);

                if (user != null) 
                {
                    cookieManager.AddCookie("user", JsonConvert.SerializeObject(user));
                }
            }
            else
            {

            }
        }

        public static async Task<TokenResponse> RefreshAccessToken(string refreshToken)
        {
            var json = JsonConvert.SerializeObject(new TokenResponse() { AccessToken = "", RefreshToken = refreshToken});
            var data = new StringContent(json, Encoding.UTF8, "application/json");

            var response = await client.PostAsync("Login/RefreshToken", data);

            TokenResponse tokens = JsonConvert.DeserializeObject<TokenResponse>(response.Content.ReadAsStringAsync().Result);
            cookieManager.AddCookie("refreshToken", tokens.RefreshToken);
            return tokens;
        }
        public async Task<HttpStatusCode> GetLastCodeStatusAsync()
        {
            return current_status;
        }
    }
}
