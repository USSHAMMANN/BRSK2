using api_market.Models;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using mvc_app.Models;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using static api_market.Controllers.LoginController;

namespace api_market.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class LoginController : ControllerBase
    {
        db_marketContext db_context = new db_marketContext();
        [HttpPost]
        public async Task<ActionResult<TokenResponse>> GetTokens([FromBody] UserLogin userLogin) 
        {
            var user = Authentecate(userLogin);
            if (user == null)
            {
                return new ObjectResult("Неверный логин или пароль") { StatusCode = StatusCodes.Status401Unauthorized };
            }
            else
            {
                var newAccessToken = GenerateAccessToken(user);
                var newRefreshToken = GenerateRefreshToken(user);
/*              var token = Generate(user);
*/              Console.WriteLine("Вход(отправка 2-х токенов)");
                return Ok(new TokenResponse { AccessToken = newAccessToken, RefreshToken = newRefreshToken });
            }
        }
        public class TokenResponse
        {
            public string AccessToken { get; set; }
            public string RefreshToken { get; set; }
        }

        [HttpPost]
        [Route("RefreshToken")]
        public async Task<ActionResult<TokenResponse>> RefreshTokens(TokenResponse tokenResponse)
        {
            TokenResponse newTokenResponse = new TokenResponse();

            string access_token = RefreshAccessToken(tokenResponse.RefreshToken);
            if (access_token.IsNullOrEmpty())
            {
                return BadRequest("Неправильный токен");
            }
            newTokenResponse.AccessToken = access_token;
            User user = GetUserByToken(newTokenResponse.AccessToken);
            newTokenResponse.RefreshToken = GenerateRefreshToken(user);

            Console.WriteLine("Вход(Обновление токенов для доступа)");
            return Ok(newTokenResponse);
        }

        [NonAction]
        public User GetUserByToken(string access_token)
        {
            var principal = GetPrincipalFromToken(access_token);
            var userIdClaim = principal.Claims.FirstOrDefault(c => c.Type == ClaimTypes.NameIdentifier);

            if (userIdClaim == null)
            {
                throw new SecurityTokenException("Неправильный токен");
            }

            var userId = int.Parse(userIdClaim.Value);
            User user = db_context.Users.Find(userId);

            return user;
        }
        [NonAction]
        private User Authentecate(UserLogin userLogin) 
        {
            User user = db_context.Users.FirstOrDefault(x => x.UserName == userLogin.Login);
            if (user == null)
            {
                return null;
            }
            else
            {
                bool isPasswordCorrect = BCrypt.Net.BCrypt.Verify(userLogin.Password, user.UserPassword);

                User current_user = db_context.Users.Include(x => x.UserRoleNavigation).FirstOrDefault(x => x.UserLogin == userLogin.Login && isPasswordCorrect);
                return current_user;
            }
        }
        [NonAction]
        private string RefreshAccessToken(string refresh_token) 
        {
            var principal = GetPrincipalFromToken(refresh_token);

            var userId = principal.Claims.First(c => c.Type == ClaimTypes.NameIdentifier);
            var usernameClaim = principal.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Name);
            var roleClaim = principal.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Role);

            if (usernameClaim == null || roleClaim == null)
            {
                throw new SecurityTokenException("Invalid token");
            }

            var user = db_context.Users.Include(u => u.UserRoleNavigation).FirstOrDefault(u => u.UserId == Convert.ToInt32(userId.Value));
            if (user == null)
            {
                throw new Exception("User not found");
            }

            return GenerateAccessToken(user);

        }
        [NonAction]
        private string GenerateAccessToken(User user)
        {
            var config = new ConfigurationBuilder()
           .SetBasePath(Directory.GetCurrentDirectory())
           .AddJsonFile("appsettings.json")
           .Build();

            var authOptions = config.GetSection("AuthOptions");
            string key = authOptions["KEY"];

            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(key));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            var claims = new[]
            {
                new Claim(ClaimTypes.NameIdentifier, user.UserId.ToString()),
                new Claim(ClaimTypes.Name, user.UserName),
                new Claim(ClaimTypes.Role, user.UserRoleNavigation.RoleName)
            };

            var token = new JwtSecurityToken("http://localhost/", "http://localhost/",
                claims,
                expires: DateTime.Now.AddMinutes(15),
                signingCredentials: credentials);


            return new JwtSecurityTokenHandler().WriteToken(token);
        }
        [NonAction]
        private string GenerateRefreshToken(User user) 
        {
            var config = new ConfigurationBuilder()
           .SetBasePath(Directory.GetCurrentDirectory())
           .AddJsonFile("appsettings.json")
           .Build();

            var authOptions = config.GetSection("AuthOptions");
            string key = authOptions["KEY"];

            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(key));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            var claims = new[]
            {
                new Claim(ClaimTypes.NameIdentifier, user.UserId.ToString()),
                new Claim(ClaimTypes.Name, user.UserName),
                new Claim(ClaimTypes.Role, user.UserRoleNavigation.RoleName),
                new Claim("token_type", "refresh") 
            };

            var token = new JwtSecurityToken("http://localhost/", "http://localhost/",
                claims,
                expires: DateTime.Now.AddMonths(1), 
                signingCredentials: credentials);

            return new JwtSecurityTokenHandler().WriteToken(token);
        }
        [NonAction]
        private ClaimsPrincipal GetPrincipalFromToken(string token)
        {
            var config = new ConfigurationBuilder()
           .SetBasePath(Directory.GetCurrentDirectory())
           .AddJsonFile("appsettings.json")
           .Build();

            var authOptions = config.GetSection("AuthOptions");
            string key = authOptions["KEY"];

            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateAudience = false, 
                ValidateIssuer = false,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(key)),
                ValidateLifetime = true,
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            SecurityToken securityToken;    
            var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out securityToken);
            var jwtSecurityToken = securityToken as JwtSecurityToken;

            if (jwtSecurityToken == null || !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
            {
                throw new SecurityTokenException("Invalid token");
            }

            return principal;
        }

    }
}
